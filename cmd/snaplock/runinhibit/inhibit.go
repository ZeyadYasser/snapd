// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2020 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

// Package runinhibit contains operations for establishing, removing and
// querying snap run inhibition lock.
package runinhibit

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/snap"
)

// defaultInhibitDir is the directory where inhibition files are stored.
const defaultInhibitDir = "/var/lib/snapd/inhibit"

// InhibitDir is the directory where inhibition files are stored.
// This value can be changed by calling dirs.SetRootDir.
var InhibitDir = defaultInhibitDir

func init() {
	dirs.AddRootDirCallback(func(root string) {
		InhibitDir = filepath.Join(root, defaultInhibitDir)
	})
}

type inhibitLockInfo struct {
	Hint     Hint          `json:"hint"`
	Revision snap.Revision `json:"revision"`
}

// Hint is a string representing reason for the inhibition of "snap run".
type Hint string

const (
	// HintNotInhibited is used when "snap run" is not inhibited.
	HintNotInhibited Hint = ""
	// HintInhibitedGateRefresh represents inhibition of a "snap run" while gate-auto-refresh hook is run.
	HintInhibitedGateRefresh Hint = "gate-refresh"
	// HintInhibitedForRefresh represents inhibition of a "snap run" while a refresh change is being performed.
	HintInhibitedForRefresh Hint = "refresh"
	// HintInhibitedForPreDownload represents inhibition of a "snap run" while a
	// pre-download is triggering a refresh.
	HintInhibitedForPreDownload Hint = "pre-download"
)

// LockFile returns the full path of the run inhibition lock file for the given snap.
func LockFile(snapName string) string {
	return filepath.Join(InhibitDir, snapName+".lock")
}

func openLockFile(snapName string) (*osutil.FileLock, error) {
	return osutil.NewFileLockWithMode(LockFile(snapName), 0644)
}

// TODO: UPDATE DOC
// Lock sets a persistent "snap run" inhibition lock, for the given snap, with a given hint.
//
// The hint cannot be empty. It should be one of the Hint constants defined in
// this package. With the hint in place "snap run" will not allow the snap to
// start and will block, presenting a user interface if possible.
func Lock(snapName string, revision snap.Revision, hint Hint) error {
	if len(hint) == 0 {
		return fmt.Errorf("lock hint cannot be empty")
	}
	// XXX: Should we be that strict?
	if revision.Unset() {
		return fmt.Errorf("snap revision cannot be unset")
	}
	if err := os.MkdirAll(InhibitDir, 0755); err != nil {
		return err
	}
	flock, err := openLockFile(snapName)
	if err != nil {
		return err
	}
	defer flock.Close()

	if err := flock.Lock(); err != nil {
		return err
	}
	f := flock.File()
	if err := f.Truncate(0); err != nil {
		return err
	}
	lockInfo := inhibitLockInfo{
		Hint:     hint,
		Revision: revision,
	}
	lockInfoJson, err := json.Marshal(lockInfo)
	if err != nil {
		return err
	}
	_, err = f.WriteString(string(lockInfoJson))
	return err
}

// Unlock clears the run inhibition lock, for the given snap.
//
// An empty inhibition lock means uninhibited "snap run".
func Unlock(snapName string) error {
	flock, err := openLockFile(snapName)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer flock.Close()

	if err := flock.Lock(); err != nil {
		return err
	}
	f := flock.File()
	err = f.Truncate(0)
	if err != nil {
		return err
	}
	_, err = f.WriteString("{}")
	return err
}

func getInhibitLockInfo(snapName string) (inhibitLockInfo, error) {
	flock, err := osutil.OpenExistingLockForReading(LockFile(snapName))
	if os.IsNotExist(err) {
		return inhibitLockInfo{}, nil
	}
	if err != nil {
		return inhibitLockInfo{}, err
	}
	defer flock.Close()

	if err := flock.ReadLock(); err != nil {
		return inhibitLockInfo{}, err
	}

	buf, err := ioutil.ReadAll(flock.File())
	if err != nil {
		return inhibitLockInfo{}, err
	}
	var lockInfo inhibitLockInfo
	err = json.Unmarshal(buf, &lockInfo)
	if err != nil {
		return inhibitLockInfo{}, err
	}
	return lockInfo, nil
}

// IsLocked returns the state of the run inhibition lock for the given snap.
//
// It returns the current, non-empty hint if inhibition is in place. Otherwise
// it returns an empty hint.
func IsLocked(snapName string) (Hint, error) {
	lockInfo, err := getInhibitLockInfo(snapName)
	return lockInfo.Hint, err
}

// RemoveLockFile removes the run inhibition lock for the given snap.
//
// This function should not be used as a substitute of Unlock, as race-free
// ability to inspect the inhibition state relies on flock(2) which requires the
// file to exist in the first place and non-privileged processes cannot create
// it.
//
// The function does not fail if the inhibition lock does not exist.
func RemoveLockFile(snapName string) error {
	err := os.Remove(LockFile(snapName))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// GetRevision returns the revision for the given snap.
//
// The snap revision is retrieved from the inhibit lock file if it exists.
// Otherwise, it returns snap.R(0).
// This is handy to use when the `current` symlink is not available (i.e.
// during a refresh after the snap is unlinked).
func GetRevision(snapName string) (snap.Revision, error) {
	lockInfo, err := getInhibitLockInfo(snapName)
	return lockInfo.Revision, err
}
