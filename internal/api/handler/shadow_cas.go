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

// Package handler — shadow_cas.go
//
// Endpoints for AQ-IC-04 (shadow CA discovery):
//
//   GET    /api/v1/inventory/shadow-cas        — observed CAs not declared as managed
//   GET    /api/v1/inventory/declared-cas      — operator-declared managed CAs
//   POST   /api/v1/inventory/declared-cas      — declare a CA as managed (admin-only)
//   DELETE /api/v1/inventory/declared-cas/{fp} — revoke a declaration (admin-only)
//
// Spec: research/shadow-ca-plan-v1.6.0.md §3 P2.
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/net4n6-dev/cipherflag/internal/api/middleware"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// shadowCAStore is the narrow interface this handler needs. Accepting
// a store.CryptoStore in server wiring is fine; the narrower interface
// here lets handler tests supply a focused fake.
type shadowCAStore interface {
	ListShadowCAs(ctx context.Context) ([]store.ShadowCA, error)
	ListDeclaredCAs(ctx context.Context) ([]store.DeclaredCA, error)
	DeclareCA(ctx context.Context, req *store.DeclareCARequest) error
	RevokeDeclaredCA(ctx context.Context, fingerprint string) error
}

// ShadowCAHandler serves the inventory shadow-CA endpoints.
type ShadowCAHandler struct{ store shadowCAStore }

// NewShadowCAHandler constructs a ShadowCAHandler.
func NewShadowCAHandler(s shadowCAStore) *ShadowCAHandler {
	return &ShadowCAHandler{store: s}
}

// noteMaxBytes is the operator-note cap. Notes are free-form operator
// memory aids ("why is this CA managed, what's the rotation schedule")
// not audit evidence, so 2KB is generous; anything longer is almost
// certainly pasted garbage.
const noteMaxBytes = 2048

// ListShadow handles GET /api/v1/inventory/shadow-cas.
func (h *ShadowCAHandler) ListShadow(w http.ResponseWriter, r *http.Request) {
	rows, err := h.store.ListShadowCAs(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rows == nil {
		rows = []store.ShadowCA{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"shadow_cas": rows,
		"total":      len(rows),
	})
}

// ListDeclared handles GET /api/v1/inventory/declared-cas.
func (h *ShadowCAHandler) ListDeclared(w http.ResponseWriter, r *http.Request) {
	rows, err := h.store.ListDeclaredCAs(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rows == nil {
		rows = []store.DeclaredCA{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"declared_cas": rows,
		"total":        len(rows),
	})
}

// declareRequest is the POST /inventory/declared-cas body.
type declareRequest struct {
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	OwnerTeam         string `json:"owner_team"`
	Note              string `json:"note"`
}

// Declare handles POST /api/v1/inventory/declared-cas (admin-only via
// middleware.RequireAdmin in server.go wiring).
func (h *ShadowCAHandler) Declare(w http.ResponseWriter, r *http.Request) {
	var body declareRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	body.FingerprintSHA256 = strings.TrimSpace(body.FingerprintSHA256)
	body.OwnerTeam = strings.TrimSpace(body.OwnerTeam)
	// Note is NOT trimmed — internal whitespace / newlines may be
	// meaningful to the operator (e.g. pasted rotation schedule with
	// indentation). Only the 2KB cap applies.
	if body.FingerprintSHA256 == "" {
		writeError(w, http.StatusBadRequest, "fingerprint_sha256 is required")
		return
	}
	if len(body.Note) > noteMaxBytes {
		writeError(w, http.StatusBadRequest, "note exceeds 2048 bytes")
		return
	}

	// Extract the caller's user ID from the JWT context so added_by
	// is recorded. The Auth middleware populates this via GetUser;
	// absence (nil) means the route was misconfigured (not gated by
	// Auth + RequireAdmin) — we record an empty added_by rather than
	// panic, and let the route-wiring invariant in server.go keep the
	// real protection.
	var addedBy string
	if u := middleware.GetUser(r.Context()); u != nil {
		addedBy = u.ID
	}

	err := h.store.DeclareCA(r.Context(), &store.DeclareCARequest{
		FingerprintSHA256: body.FingerprintSHA256,
		AddedBy:           addedBy,
		OwnerTeam:         body.OwnerTeam,
		Note:              body.Note,
	})
	if err != nil {
		// Store-level validation (unknown fingerprint, is_leaf) → 400.
		// Unexpected DB errors → 500. The strings are the store's own
		// descriptive messages so the caller can fix their request.
		msg := err.Error()
		if strings.Contains(msg, "not in certificates") ||
			strings.Contains(msg, "is a leaf") {
			writeError(w, http.StatusBadRequest, msg)
			return
		}
		writeError(w, http.StatusInternalServerError, msg)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"fingerprint_sha256": body.FingerprintSHA256,
		"status":             "declared",
	})
}

// Revoke handles DELETE /api/v1/inventory/declared-cas/{fingerprint}
// (admin-only). Idempotent: revoking a fingerprint that wasn't
// declared returns 200 with status=not_declared rather than 404 so
// repeat calls from the UI don't surface confusing errors.
func (h *ShadowCAHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	fp := strings.TrimSpace(chi.URLParam(r, "fingerprint"))
	if fp == "" {
		writeError(w, http.StatusBadRequest, "fingerprint is required")
		return
	}
	if err := h.store.RevokeDeclaredCA(r.Context(), fp); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"fingerprint_sha256": fp,
		"status":             "revoked",
	})
}
