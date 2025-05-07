// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
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

package daemon

import (
	"encoding/json"
	"fmt"
	"net/http"

	sb "github.com/snapcore/secboot"
	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/overlord/auth"
	"github.com/snapcore/snapd/secboot"
)

var systemVolumesCmd = &Command{
	Path:        "/v2/system-volumes",
	POST:        postSystemVolumesAction,
	WriteAccess: rootAccess{},
}

func postSystemVolumesAction(c *Command, r *http.Request, user *auth.UserState) Response {
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/json"
	}

	switch contentType {
	case "application/json":
		return postSystemVolumesActionJSON(c, r)
	default:
		return BadRequest("unexpected content type: %q", contentType)
	}
}

type systemVolumesRequest struct {
	Action string `json:"action,omitempty"`

	CurrentPassphrase string `json:"current-passphrase,omitempty"`
	NewPassphrase     string `json:"new-passphrase,omitempty"`
}

func (r *systemVolumesRequest) Validate() error {
	switch r.Action {
	case "change-passphrase":
		if r.CurrentPassphrase == "" {
			return fmt.Errorf("current-passphrase cannot be empty for action %q", r.Action)
		}
		if r.NewPassphrase == "" {
			return fmt.Errorf("new-passphrase cannot be empty for action %q", r.Action)
		}
		// TODO: Validate passphrase quality??
	default:
		return fmt.Errorf("unsupported volumes action %q", r.Action)
	}
	return nil
}

func postSystemVolumesActionJSON(c *Command, r *http.Request) Response {
	var req systemVolumesRequest

	decoder := json.NewDecoder(r.Body)

	if err := decoder.Decode(&req); err != nil {
		return BadRequest("cannot decode request body: %v", err)
	}

	if decoder.More() {
		return BadRequest("extra content found in request body")
	}

	if err := req.Validate(); err != nil {
		return BadRequest(err.Error())
	}

	switch req.Action {
	case "change-passphrase":
		return postSystemVolumesActionChangePassphrase(c, &req)
	default:
		return InternalError("support for system volumes action %q is not implemented", req.Action)
	}
}

func postSystemVolumesActionChangePassphrase(c *Command, req *systemVolumesRequest) Response {
	st := c.d.overlord.State()
	st.Lock()
	defer st.Unlock()

	fdeMgr := c.d.overlord.FDEManager()
	containers, err := fdeMgr.GetEncryptedContainers()
	if err != nil {
		return BadRequest("cannot get encrypted containers: %v", err)
	}

	containersJson := make([]map[string]any, 0, len(containers))
	for _, container := range containers {
		if len(container.LegacyKeys()) > 0 {
			return BadRequest("cannot change passphrase: legacy keyfile detected")
		}
		containersJson = append(containersJson, map[string]any{
			"container-role": container.ContainerRole(),
			"dev-path":       container.DevPath(),
			"legacy-keys":    container.LegacyKeys(),
		})

		var keys []secboot.KeyDataLocation
		switch container.ContainerRole() {
		case "system-data":
			runKey := secboot.KeyDataLocation{
				DevicePath: container.DevPath(),
				SlotName:   "default",
			}

			keys = append(keys, runKey)
		}

		switch container.ContainerRole() {
		case "system-save", "system-data":
			fallbackKey := secboot.KeyDataLocation{
				DevicePath: container.DevPath(),
				SlotName:   "default-fallback",
			}

			keys = append(keys, fallbackKey)
		}

		logger.Noticef("container role: %q", container.ContainerRole())
		keyDatas := make([]*sb.KeyData, 0, len(keys))
		writers := make([]sb.KeyDataWriter, 0, len(keys))
		for _, key := range keys {
			keyData, writer, err := secboot.ReadTokenAndGetWriter(key)
			if err != nil {
				return BadRequest("cannot read token: %v", err)
			}
			if keyData.AuthMode() != sb.AuthModePassphrase {
				return BadRequest("non-passphrase auth mode detected")
			}
			logger.Noticef("\tkeyData.ReadableName: %q", keyData.ReadableName())
			keyDatas = append(keyDatas, keyData)
			writers = append(writers, writer)
		}
		for i := 0; i < len(keyDatas); i++ {
			if err := keyDatas[i].ChangePassphrase(req.CurrentPassphrase, req.NewPassphrase); err != nil {
				return BadRequest("cannot change passphrase: %v", err)
			}
		}
		for i := 0; i < len(keyDatas); i++ {
			if err := keyDatas[i].WriteAtomic(writers[i]); err != nil {
				return BadRequest("cannot write keydata: %v", err)
			}
		}
	}
	return SyncResponse(containersJson)
}
