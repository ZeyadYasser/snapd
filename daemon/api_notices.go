// Copyright (c) 2023-2024 Canonical Ltd
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 3 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"path/filepath"
	"strconv"

	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/overlord/auth"
	"github.com/snapcore/snapd/overlord/snapstate"
	"github.com/snapcore/snapd/overlord/state"
	"github.com/snapcore/snapd/strutil"
)

var noticeReadInterfaces = map[state.NoticeType][]string{
	state.ChangeUpdateNotice:   {"snap-refresh-observe"},
	state.RefreshInhibitNotice: {"snap-refresh-observe"},
	state.SnapRunInhibitNotice: {"snap-refresh-observe"},
}

var (
	noticesCmd = &Command{
		Path:        "/v2/notices",
		GET:         getNotices,
		POST:        postNotices,
		ReadAccess:  interfaceOpenAccess{Interfaces: []string{"snap-refresh-observe"}},
		WriteAccess: openAccess{},
	}

	noticeCmd = &Command{
		Path:       "/v2/notices/{id}",
		GET:        getNotice,
		ReadAccess: interfaceOpenAccess{Interfaces: []string{"snap-refresh-observe"}},
	}
)

const (
	maxNoticeKeyLength = 256
)

type addedNotice struct {
	ID string `json:"id"`
}

func getNotices(c *Command, r *http.Request, user *auth.UserState) Response {
	query := r.URL.Query()

	requestUID, err := uidFromRequest(r)
	if err != nil {
		return Forbidden("cannot determine UID of request, so cannot retrieve notices")
	}

	// By default, return notices with the request UID and public notices.
	userID := &requestUID

	if len(query["user-id"]) > 0 {
		if requestUID != 0 {
			return Forbidden(`only admins may use the "user-id" filter`)
		}
		userID, err = sanitizeNoticeUserIDFilter(query["user-id"])
		if err != nil {
			return BadRequest(`invalid "user-id" filter: %v`, err)
		}
	}

	if len(query["users"]) > 0 {
		if requestUID != 0 {
			return Forbidden(`only admins may use the "users" filter`)
		}
		if len(query["user-id"]) > 0 {
			return BadRequest(`cannot use both "users" and "user-id" parameters`)
		}
		if query.Get("users") != "all" {
			return BadRequest(`invalid "users" filter: must be "all"`)
		}
		// Clear the userID filter so all notices will be returned.
		userID = nil
	}

	types, err := sanitizeNoticeTypesFilter(query["types"], r)
	if err != nil {
		// Caller did provide a types filter, but they're all invalid notice types.
		// Return no notices, rather than the default of all notices.
		return SyncResponse([]*state.Notice{})
	}
	if !noticeTypesViewableBySnap(types, r) {
		return Forbidden("snap cannot access specified notice types")
	}

	keys := strutil.MultiCommaSeparatedList(query["keys"])

	after, err := parseOptionalTime(query.Get("after"))
	if err != nil {
		return BadRequest(`invalid "after" timestamp: %v`, err)
	}

	filter := &state.NoticeFilter{
		UserID: userID,
		Types:  types,
		Keys:   keys,
		After:  after,
	}

	timeout, err := parseOptionalDuration(query.Get("timeout"))
	if err != nil {
		return BadRequest("invalid timeout: %v", err)
	}

	st := c.d.overlord.State()
	st.Lock()
	defer st.Unlock()

	var notices []*state.Notice

	if timeout != 0 {
		// Wait up to timeout for notices matching given filter to occur
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		notices, err = st.WaitNotices(ctx, filter)
		if errors.Is(err, context.Canceled) {
			return BadRequest("request canceled")
		}
		// DeadlineExceeded will occur if timeout elapses; in that case return
		// an empty list of notices, not an error.
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			return InternalError("cannot wait for notices: %s", err)
		}
	} else {
		// No timeout given, fetch currently-available notices
		notices = st.Notices(filter)
	}

	if notices == nil {
		notices = []*state.Notice{} // avoid null result
	}
	return SyncResponse(notices)
}

// Get the UID of the request. If the UID is not known, return an error.
func uidFromRequest(r *http.Request) (uint32, error) {
	cred, err := ucrednetGet(r.RemoteAddr)
	if err != nil {
		return 0, fmt.Errorf("could not parse request UID")
	}
	return cred.Uid, nil
}

// Construct the user IDs filter which will be passed to state.Notices.
// Must only be called if the query user ID argument is set.
func sanitizeNoticeUserIDFilter(queryUserID []string) (*uint32, error) {
	userIDStrs := strutil.MultiCommaSeparatedList(queryUserID)
	if len(userIDStrs) != 1 {
		return nil, fmt.Errorf(`must only include one "user-id"`)
	}
	userIDInt, err := strconv.ParseInt(userIDStrs[0], 10, 64)
	if err != nil {
		return nil, err
	}
	if userIDInt < 0 || userIDInt > math.MaxUint32 {
		return nil, fmt.Errorf("user ID is not a valid uint32: %d", userIDInt)
	}
	userID := uint32(userIDInt)
	return &userID, nil
}

// Construct the types filter which will be passed to state.Notices.
func sanitizeNoticeTypesFilter(queryTypes []string, r *http.Request) ([]state.NoticeType, error) {
	typeStrs := strutil.MultiCommaSeparatedList(queryTypes)
	alreadySeen := make(map[state.NoticeType]bool, len(typeStrs))
	types := make([]state.NoticeType, 0, len(typeStrs))
	for _, typeStr := range typeStrs {
		noticeType := state.NoticeType(typeStr)
		if !noticeType.Valid() {
			// Ignore invalid notice types (so requests from newer clients
			// with unknown types succeed).
			continue
		}
		if alreadySeen[noticeType] {
			continue
		}
		alreadySeen[noticeType] = true
		types = append(types, noticeType)
	}
	if len(types) == 0 {
		if len(typeStrs) > 0 {
			return nil, errors.New("all requested notice types invalid")
		}
		// No types were specified, populate with notice types snap can view
		// with its connected interface.
		ucred, ifaces, err := ucrednetGetWithInterfaces(r.RemoteAddr)
		if err != nil {
			return nil, err
		}
		if ucred.Socket == dirs.SnapdSocket {
			// Not connecting through snapd-snap.socket, should have read-access to all types.
			return nil, nil
		}
		for _, iface := range ifaces {
			ifaceNoticeTypes := allowedNoticeTypesForInterface(iface)
			for _, t := range ifaceNoticeTypes {
				if alreadySeen[t] {
					continue
				}
				alreadySeen[t] = true
				types = append(types, t)
			}
		}
		if len(types) == 0 {
			return nil, errors.New("snap cannot access any notice type")
		}
	}
	return types, nil
}

// allowedNoticeTypesForInterface returns a list of notice types that a snap
// can read with connected interface.
func allowedNoticeTypesForInterface(iface string) []state.NoticeType {
	// Populate with notice types the snap can access through its plugged interfaces
	var types []state.NoticeType
	for noticeType, allowedInterfaces := range noticeReadInterfaces {
		if strutil.ListContains(allowedInterfaces, iface) {
			types = append(types, noticeType)
		}
	}

	return types
}

func postNotices(c *Command, r *http.Request, user *auth.UserState) Response {
	requestUID, err := uidFromRequest(r)
	if err != nil {
		return Forbidden("cannot determine UID of request, so cannot create notice")
	}

	var payload struct {
		Action string `json:"action"`
		Type   string `json:"type"`
		Key    string `json:"key"`
		// NOTE: Data and RepeatAfter fields are not needed for snap-run-inhibit notices.
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&payload); err != nil {
		return BadRequest("cannot decode request body: %v", err)
	}

	if payload.Action != "add" {
		return BadRequest("invalid action %q", payload.Action)
	}
	if payload.Type != "snap-run-inhibit" {
		return BadRequest(`invalid type %q (can only add "snap-run-inhibit" notices)`, payload.Type)
	}
	if len(payload.Key) > maxNoticeKeyLength {
		return BadRequest("key must be %d bytes or less", maxNoticeKeyLength)
	}

	st := c.d.overlord.State()
	st.Lock()
	defer st.Unlock()

	fromSnapCmd, err := requestFromSnapCmd(st, r)
	if err != nil {
		return InternalError("cannot check request source")
	}
	if !fromSnapCmd {
		return Forbidden("only snap command can record notices")
	}

	exists, err := snapInstanceExists(st, payload.Key)
	if err != nil {
		return InternalError("cannot check snap in state: %v", err)
	}
	if !exists {
		return BadRequest("snap %q does not exist", payload.Key)
	}

	noticeId, err := st.AddNotice(&requestUID, state.SnapRunInhibitNotice, payload.Key, nil)
	if err != nil {
		return InternalError("%v", err)
	}

	return SyncResponse(addedNotice{ID: noticeId})
}

func requestFromSnapCmd(st *state.State, r *http.Request) (bool, error) {
	ucred, err := ucrednetGet(r.RemoteAddr)
	if err != nil {
		return false, err
	}
	exe, err := osReadlink(fmt.Sprintf("/proc/%d/exe", ucred.Pid))
	if err != nil {
		return false, err
	}

	// SNAP_REEXEC=0
	if exe == filepath.Join(dirs.GlobalRootDir, "/usr/bin/snap") {
		return true, nil
	}

	// Check if re-exec in snapd
	var snapst snapstate.SnapState
	err = snapstate.Get(st, "snapd", &snapst)
	if err != nil && !errors.Is(err, state.ErrNoState) {
		return false, err
	}
	if err == nil {
		snapdPath := fmt.Sprintf("snapd/%s/usr/bin/snap", snapst.CurrentSideInfo().Revision)
		if exe == filepath.Join(dirs.SnapMountDir, snapdPath) {
			return true, nil
		}
	}

	// Check if re-exec in core
	err = snapstate.Get(st, "core", &snapst)
	if err != nil && !errors.Is(err, state.ErrNoState) {
		return false, err
	}
	if err == nil {
		corePath := fmt.Sprintf("core/%s/usr/bin/snap", snapst.CurrentSideInfo().Revision)
		if exe == filepath.Join(dirs.SnapMountDir, corePath) {
			return true, nil
		}
	}

	return false, nil
}

func getNotice(c *Command, r *http.Request, user *auth.UserState) Response {
	requestUID, err := uidFromRequest(r)
	if err != nil {
		return Forbidden("cannot determine UID of request, so cannot retrieve notice")
	}
	noticeID := muxVars(r)["id"]
	st := c.d.overlord.State()
	st.Lock()
	defer st.Unlock()
	notice := st.Notice(noticeID)
	if notice == nil {
		return NotFound("cannot find notice with id %q", noticeID)
	}
	if !noticeViewableByUser(notice, requestUID) {
		return Forbidden("not allowed to access notice with id %q", noticeID)
	}
	if !noticeTypesViewableBySnap([]state.NoticeType{notice.Type()}, r) {
		return Forbidden("not allowed to access notice with id %q", noticeID)
	}
	return SyncResponse(notice)
}

// Only the user associated with the given notice, as well as the root user,
// may view the notice. Snapd does also have authenticated admins which are not
// root, but at the moment we do not have a level of notice visibility which
// grants access to those admins, as well as root and the notice's user.
func noticeViewableByUser(notice *state.Notice, requestUID uint32) bool {
	userID, isSet := notice.UserID()
	if !isSet {
		return true
	}
	// Root is allowed to view any notice.
	if requestUID == 0 {
		return true
	}
	return requestUID == userID
}

// noticeTypesViewableBySnap checks if passed interface allows the snap
// to have read-access for the passed notice types.
func noticeTypesViewableBySnap(types []state.NoticeType, r *http.Request) bool {
	ucred, ifaces, err := ucrednetGetWithInterfaces(r.RemoteAddr)
	if err != nil {
		return false
	}
	if ucred.Socket == dirs.SnapdSocket {
		// Not connecting through snapd-snap.socket, should have read-access to all types.
		return true
	}

	if len(types) == 0 {
		// At least one type must be specified for snaps
		return false
	}

InterfaceTypeLoop:
	for _, noticeType := range types {
		allowedInterfaces := noticeReadInterfaces[noticeType]
		for _, iface := range ifaces {
			if strutil.ListContains(allowedInterfaces, iface) {
				continue InterfaceTypeLoop
			}
		}
		return false
	}
	return true
}
