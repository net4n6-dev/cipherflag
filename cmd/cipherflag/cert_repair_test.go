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

package main

import (
	"context"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// blockingBlankStore holds the repair's first page read until released, as a
// large backlog of blank rows would.
type blockingBlankStore struct {
	release chan struct{}
}

func (s *blockingBlankStore) ListBlankCertificatesWithPEM(ctx context.Context, _ string, _ int) ([]store.BlankCertificate, error) {
	select {
	case <-s.release:
		return nil, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *blockingBlankStore) UpsertCertificate(context.Context, *model.Certificate) error { return nil }

func noScore(context.Context, string) error { return nil }

// serve ran the startup repair inline, before the CBOM runtime and the HTTP
// server started: a large backlog held the API down until it finished, and
// the scored events it produced were dropped because nothing was draining
// the CBOM notify channel yet. The repair now runs in the background.
func TestStartCertificateRepair_DoesNotBlockStartup(t *testing.T) {
	st := &blockingBlankStore{release: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := make(chan (<-chan struct{}), 1)
	go func() { started <- startCertificateRepair(ctx, st, noScore) }()

	var done <-chan struct{}
	select {
	case done = <-started:
	case <-time.After(2 * time.Second):
		close(st.release)
		t.Fatal("startCertificateRepair blocked until the repair finished")
	}
	select {
	case <-done:
		t.Fatal("done closed before the repair finished")
	default:
	}

	close(st.release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("done not closed after the repair finished")
	}
}

// Shutdown stops a repair in progress.
func TestStartCertificateRepair_StopsWithTheServer(t *testing.T) {
	st := &blockingBlankStore{release: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())

	started := make(chan (<-chan struct{}), 1)
	go func() { started <- startCertificateRepair(ctx, st, noScore) }()
	cancel()

	select {
	case done := <-started:
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("repair did not stop when the server context was cancelled")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("startCertificateRepair did not return")
	}
}
