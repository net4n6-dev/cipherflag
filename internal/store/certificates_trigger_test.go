//go:build integration

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

package store

import (
	"context"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// TestUpsertCertificate_TriggerFires regresses against the 2026-04-16
// migration-019 trigger bug. That migration's notify_cert_discovered
// trigger body references NEW.source, but the certificates column has
// always been named source_discovery (migration 001 line 32). The
// PG NOTIFY trigger fires AFTER INSERT, so every fresh cert upsert
// errors with SQLSTATE 42703 ("record 'new' has no field 'source'").
// This has blocked Zeek passive ingest, PCAP upload, and any fresh-DB
// seed run since commit 1e3c246 landed.
//
// Migration 023 (shipped in v1.3.2) replaces the trigger body with a
// reference to NEW.source_discovery. This test asserts that
// UpsertCertificate — the single path for cert ingestion — completes
// without SQLSTATE 42703.
func TestUpsertCertificate_TriggerFires(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// Minimal cert — just enough fields to satisfy the UpsertCertificate
	// column list. The test isn't about cert data shape; it's about the
	// INSERT completing past the AFTER-INSERT trigger.
	cert := &model.Certificate{
		FingerprintSHA256:  "sha256:triggerregress0001",
		Subject:            model.DistinguishedName{CommonName: "trigger-test.example"},
		Issuer:             model.DistinguishedName{CommonName: "TestCA"},
		SerialNumber:       "serial-trigger-001",
		NotBefore:          time.Now().Add(-365 * 24 * time.Hour),
		NotAfter:           time.Now().Add(30 * 24 * time.Hour),
		KeyAlgorithm:       model.KeyRSA,
		KeySizeBits:        2048,
		SignatureAlgorithm: model.SigSHA256WithRSA,
		SourceDiscovery:    model.SourceZeekPassive,
		FirstSeen:          time.Now(),
		LastSeen:           time.Now(),
	}

	if err := st.UpsertCertificate(ctx, cert); err != nil {
		t.Fatalf("UpsertCertificate failed — migration 019 trigger bug regressed? %v", err)
	}

	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM certificates WHERE fingerprint_sha256 = $1`, cert.FingerprintSHA256)
	})
}

// TestUpsertCertificate_NotifyPayloadHasSource asserts that the PG
// NOTIFY payload still carries the "source" key in its JSON, even
// after migration 023 remapped the column reference. The SSE wire
// contract is "source" (established in migration 019); changing the
// column name shouldn't leak into the payload key.
//
// Uses the same LISTEN loop pattern as internal/sse/listener.go but
// with a short deadline — if no NOTIFY arrives within 500ms after the
// INSERT, assumes the trigger silently skipped (or regressed).
func TestUpsertCertificate_NotifyPayloadHasSource(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	conn, err := st.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire conn: %v", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "LISTEN cipherflag_events"); err != nil {
		t.Fatalf("LISTEN: %v", err)
	}

	cert := &model.Certificate{
		FingerprintSHA256:  "sha256:triggerpayload0001",
		Subject:            model.DistinguishedName{CommonName: "payload-test.example"},
		Issuer:             model.DistinguishedName{CommonName: "TestCA"},
		SerialNumber:       "serial-payload-001",
		NotBefore:          time.Now().Add(-365 * 24 * time.Hour),
		NotAfter:           time.Now().Add(30 * 24 * time.Hour),
		KeyAlgorithm:       model.KeyRSA,
		KeySizeBits:        2048,
		SignatureAlgorithm: model.SigSHA256WithRSA,
		SourceDiscovery:    model.SourceActiveScan,
		FirstSeen:          time.Now(),
		LastSeen:           time.Now(),
	}
	if err := st.UpsertCertificate(ctx, cert); err != nil {
		t.Fatalf("UpsertCertificate: %v", err)
	}
	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM certificates WHERE fingerprint_sha256 = $1`, cert.FingerprintSHA256)
	})

	waitCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	n, err := conn.Conn().WaitForNotification(waitCtx)
	if err != nil {
		t.Fatalf("wait notify: %v (did the trigger fire?)", err)
	}
	if !containsJSON(n.Payload, `"source"`) {
		t.Errorf("NOTIFY payload missing `source` key: %s", n.Payload)
	}
	if !containsJSON(n.Payload, `"active_scan"`) {
		t.Errorf("NOTIFY payload missing source value: %s", n.Payload)
	}
	if !containsJSON(n.Payload, `"asset.discovered"`) {
		t.Errorf("NOTIFY payload not asset.discovered: %s", n.Payload)
	}
}

func containsJSON(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
