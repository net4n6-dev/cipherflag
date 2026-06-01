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

// fakeStatsStore embeds the full CryptoStore interface (nil) so it satisfies
// NewStatsHandler's parameter type without implementing every method. We only
// override the four de-mooted analytics methods exercised by these tests;
// any other method call would panic (and none of the tested routes make one).
type fakeStatsStore struct {
	store.CryptoStore
	chainFlow     *model.ChainFlowResponse
	ownership     *model.OwnershipResponse
	deployment    *model.DeploymentResponse
	sourceLineage *model.SourceLineageResponse
}

func (f *fakeStatsStore) GetChainFlow(ctx context.Context) (*model.ChainFlowResponse, error) {
	return f.chainFlow, nil
}
func (f *fakeStatsStore) GetOwnershipStats(ctx context.Context) (*model.OwnershipResponse, error) {
	return f.ownership, nil
}
func (f *fakeStatsStore) GetDeploymentStats(ctx context.Context) (*model.DeploymentResponse, error) {
	return f.deployment, nil
}
func (f *fakeStatsStore) GetSourceLineage(ctx context.Context) (*model.SourceLineageResponse, error) {
	return f.sourceLineage, nil
}

func newStatsRouter(t *testing.T, s store.CryptoStore) http.Handler {
	t.Helper()
	r := chi.NewRouter()
	h := NewStatsHandler(s)
	r.Get("/stats/chain-flow", h.ChainFlow)
	r.Get("/stats/ownership", h.Ownership)
	r.Get("/stats/deployment", h.Deployment)
	r.Get("/stats/source-lineage", h.SourceLineage)
	return r
}

func TestStatsHandler_DeMootedRoutesReturn200(t *testing.T) {
	s := &fakeStatsStore{
		chainFlow:     &model.ChainFlowResponse{},
		ownership:     &model.OwnershipResponse{},
		deployment:    &model.DeploymentResponse{},
		sourceLineage: &model.SourceLineageResponse{},
	}
	r := newStatsRouter(t, s)

	for _, path := range []string{
		"/stats/chain-flow",
		"/stats/ownership",
		"/stats/deployment",
		"/stats/source-lineage",
	} {
		req := httptest.NewRequest("GET", path, nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("%s: want 200, got %d: %s", path, rr.Code, rr.Body.String())
		}
	}
}
