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

package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/analysis/scoring"
	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom"
	"github.com/net4n6-dev/cipherflag/internal/export/venafi"
	"github.com/net4n6-dev/cipherflag/internal/ingest/observcache"
	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/sse"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// slowPagedStore serves three full pages of certificates and then an empty
// one, taking a while per call like a large table does.
type slowPagedStore struct {
	exportGateStore
	delay time.Duration
}

func (s *slowPagedStore) SearchCertificates(_ context.Context, q store.CertSearchQuery) (*store.CertSearchResult, error) {
	time.Sleep(s.delay)
	res := &store.CertSearchResult{Page: q.Page, PageSize: q.PageSize}
	if q.Page <= 3 {
		for i := 0; i < q.PageSize; i++ {
			res.Certificates = append(res.Certificates, model.Certificate{
				FingerprintSHA256: fmt.Sprintf("p%d-%04d", q.Page, i),
			})
		}
	}
	return res, nil
}

// The server's WriteTimeout runs from the request headers. Through the real
// router and a real server, an export that takes several times longer than the
// timeout must still arrive whole, because Export pushes the deadline out
// before every page.
func TestRouter_CertificateExport_SurvivesTheServerWriteTimeout(t *testing.T) {
	secret := []byte("test-secret")
	sum := sha256.Sum256([]byte("agent-secret"))
	st := &slowPagedStore{
		exportGateStore: exportGateStore{authGateStore{agentHash: hex.EncodeToString(sum[:])}},
		delay:           150 * time.Millisecond,
	}
	router := NewRouter(st, &config.Config{}, "", "", secret, "",
		observcache.NewNoop(), scoring.NewNoopScorer(), sse.NewHub(),
		venafi.NewLiveConfig(config.VenafiExportConfig{}), cbom.NewGenerator())

	srv := httptest.NewUnstartedServer(router)
	srv.Config.WriteTimeout = 300 * time.Millisecond
	srv.Start()
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/export/certificates?format=csv", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer agent-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v (the export was cut off by the server write timeout)", err)
	}
	lines := strings.Count(string(body), "\n")
	if lines != 1501 {
		t.Errorf("lines = %d, want 1501 (header plus 1500 rows)", lines)
	}
}
