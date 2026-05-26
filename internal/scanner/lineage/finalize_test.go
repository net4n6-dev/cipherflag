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

package lineage

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

type stubStore struct{ links []*model.LineageLink }

func (s *stubStore) CreateLineageLink(ctx context.Context, l *model.LineageLink) error {
	s.links = append(s.links, l)
	return nil
}

type stubPool struct {
	hitCert bool
	hitSSH  bool
	calls   int
}

type stubRow struct{ exists bool }

func (r *stubRow) Scan(dest ...any) error {
	if len(dest) != 1 {
		return errors.New("bad dest")
	}
	b, ok := dest[0].(*bool)
	if !ok {
		return errors.New("not *bool")
	}
	*b = r.exists
	return nil
}

func (p *stubPool) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	p.calls++
	if p.calls == 1 {
		return &stubRow{exists: p.hitCert}
	}
	return &stubRow{exists: p.hitSSH}
}

func TestFinalize_CertMatchEmitsOneLink(t *testing.T) {
	st := &stubStore{}
	p := &stubPool{hitCert: true}
	f := &Finalizer{Store: st, Pool: p}
	_, err := f.Finalize(context.Background(), "repo-1", "scan-1",
		[]finding.FindingRecord{{Fingerprint: "sha256:aa", Path: "x.pem"}})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(st.links) != 1 {
		t.Errorf("want 1 link, got %d", len(st.links))
	}
	if st.links[0].ToAssetType != "certificate" {
		t.Errorf("to_asset_type: %q", st.links[0].ToAssetType)
	}
}

func TestFinalize_NoFingerprintSkipped(t *testing.T) {
	st := &stubStore{}
	p := &stubPool{}
	f := &Finalizer{Store: st, Pool: p}
	_, _ = f.Finalize(context.Background(), "r", "s",
		[]finding.FindingRecord{{Path: "x"}})
	if len(st.links) != 0 {
		t.Error("no fingerprint -> no link")
	}
}
