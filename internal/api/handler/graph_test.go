// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// fakeGraphStore embeds store.CertStore (nil) so it satisfies NewGraphHandler's
// parameter type without implementing every method. We override only the six
// methods the five graph routes invoke; GetCertificate returns a non-nil cert
// so ChainGraph exercises its success path (not the 404 branch).
type fakeGraphStore struct {
	store.CertStore
}

func (f *fakeGraphStore) GetAllCertificatesForGraph(ctx context.Context) ([]model.Certificate, error) {
	return []model.Certificate{}, nil
}
func (f *fakeGraphStore) GetCertificate(ctx context.Context, fingerprint string) (*model.Certificate, error) {
	// Return a realistic cert: a full-length (64-hex) SHA-256 fingerprint and a
	// non-empty CN. BuildChainGraphData slices FingerprintSHA256[:12] as a label
	// fallback when CN is empty, so a short echoed URL param (e.g. "abc123")
	// would panic — real certs never have a 6-char fingerprint.
	return &model.Certificate{
		FingerprintSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Subject:           model.DistinguishedName{CommonName: "example.test"},
	}, nil
}
func (f *fakeGraphStore) GetAllHealthReports(ctx context.Context) ([]model.HealthReport, error) {
	return []model.HealthReport{}, nil
}
func (f *fakeGraphStore) GetAggregatedLandscape(ctx context.Context) (*model.AggregatedLandscapeResponse, error) {
	return &model.AggregatedLandscapeResponse{}, nil
}
func (f *fakeGraphStore) GetCAChildren(ctx context.Context, fingerprint string, limit, offset int) (*model.CAChildrenResponse, error) {
	return &model.CAChildrenResponse{}, nil
}
func (f *fakeGraphStore) GetBlastRadius(ctx context.Context, fingerprint string, limit int) (*model.BlastRadiusResponse, error) {
	return &model.BlastRadiusResponse{}, nil
}

func newGraphRouter(t *testing.T, s store.CertStore) http.Handler {
	t.Helper()
	r := chi.NewRouter()
	h := NewGraphHandler(s)
	r.Get("/graph/landscape", h.Landscape)
	r.Get("/graph/chain/{fingerprint}", h.ChainGraph)
	r.Get("/graph/landscape/aggregated", h.AggregatedLandscape)
	r.Get("/graph/ca/{fingerprint}/children", h.CAChildren)
	r.Get("/graph/ca/{fingerprint}/blast-radius", h.BlastRadius)
	return r
}

func TestGraphHandler_RoutesRegistered(t *testing.T) {
	r := newGraphRouter(t, &fakeGraphStore{})

	for _, path := range []string{
		"/graph/landscape",
		"/graph/chain/abc123",
		"/graph/landscape/aggregated",
		"/graph/ca/abc123/children",
		"/graph/ca/abc123/blast-radius",
	} {
		req := httptest.NewRequest("GET", path, nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("%s: want 200, got %d: %s", path, rr.Code, rr.Body.String())
		}
	}
}
