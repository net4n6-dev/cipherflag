// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handler

import (
	"context"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// sshKeyStore is the minimal store interface required by SSHKeyHandler.
type sshKeyStore interface {
	GetSSHKey(ctx context.Context, id string) (*model.SSHKey, error)
	ListSSHKeys(ctx context.Context, query store.SSHKeySearchQuery) (*store.SSHKeySearchResult, error)
}

// SSHKeyHandler handles SSH key asset endpoints.
type SSHKeyHandler struct {
	store sshKeyStore
}

// NewSSHKeyHandler constructs an SSHKeyHandler.
func NewSSHKeyHandler(s sshKeyStore) *SSHKeyHandler {
	return &SSHKeyHandler{store: s}
}

// List handles GET /ssh-keys
func (h *SSHKeyHandler) List(w http.ResponseWriter, r *http.Request) {
	q := store.SSHKeySearchQuery{
		HostID:  r.URL.Query().Get("host_id"),
		KeyType: r.URL.Query().Get("key_type"),
		Status:  r.URL.Query().Get("status"),
		Search:  r.URL.Query().Get("search"),
		Limit:   50,
	}

	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			if n > 500 {
				n = 500
			}
			q.Limit = n
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		q.Offset, _ = strconv.Atoi(o)
	}

	result, err := h.store.ListSSHKeys(r.Context(), q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// Get handles GET /ssh-keys/{id}
func (h *SSHKeyHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	key, err := h.store.GetSSHKey(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if key == nil {
		writeError(w, http.StatusNotFound, "ssh key not found")
		return
	}
	writeJSON(w, http.StatusOK, key)
}
