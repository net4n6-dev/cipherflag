//go:build livect

// Copyright 2026 net4n6-dev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Opt-in live validation against production Static CT logs. Not part of
// the normal (hermetic) suite; run with:
//
//	go test -tags livect -run Live -v ./internal/ingest/ct/static/
//
// Use it to re-validate the checkpoint verifier and the full tile walk
// against the current log list (new logs, key rotations, implementation
// changes), and to refresh testdata/real_checkpoints/.
package static

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const liveLogListURL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

func liveClient() *http.Client { return &http.Client{Timeout: 60 * time.Second} }

// Every tiled log in the CURRENT Google log list: fetch its checkpoint
// from monitoring_url and verify it with origin = submission_url minus
// scheme and trailing slash, key = the listed SPKI.
func TestLive_TiledLogCheckpointsVerify(t *testing.T) {
	hc := liveClient()
	resp, err := hc.Get(liveLogListURL)
	if err != nil {
		t.Fatalf("fetch log list: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read log list: %v", err)
	}
	var list struct {
		Operators []struct {
			Name      string `json:"name"`
			TiledLogs []struct {
				Key           string `json:"key"`
				MonitoringURL string `json:"monitoring_url"`
				SubmissionURL string `json:"submission_url"`
			} `json:"tiled_logs"`
		} `json:"operators"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatalf("parse log list: %v", err)
	}
	n := 0
	for _, op := range list.Operators {
		for _, l := range op.TiledLogs {
			n++
			origin := strings.TrimSuffix(strings.TrimPrefix(l.SubmissionURL, "https://"), "/")
			t.Run(origin, func(t *testing.T) {
				der, err := base64.StdEncoding.DecodeString(l.Key)
				if err != nil {
					t.Fatalf("key: %v", err)
				}
				pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
				if err := ValidateDomainConfig("example.com", l.MonitoringURL, origin, pemStr); err != nil {
					t.Fatalf("ValidateDomainConfig: %v", err)
				}
				key, _ := ParseLogPublicKeyPEM(pemStr)
				cp, err := fetchCheckpoint(context.Background(), hc, l.MonitoringURL)
				if err != nil {
					t.Skipf("fetch (not a verifier failure): %v", err)
				}
				sth, err := ParseAndVerifyCheckpoint(cp, origin, key)
				if err != nil {
					t.Fatalf("verify: %v\n%s", err, cp)
				}
				t.Logf("%s: tree_size=%d", op.Name, sth.TreeSize)
			})
		}
	}
	if n == 0 {
		t.Fatal("log list has no tiled_logs")
	}
}

// Full Provider.QueryDomain path against real logs from four different
// Static CT implementations: verified checkpoint → real data tiles
// (x509 + precert leaves) → SAN filter → inclusion proofs from real hash
// tiles against the checkpoint root. The window is the last ~300 leaves
// below the head; domain "com" matches most certificates, so dozens of
// real inclusion proofs are verified per log.
func TestLive_QueryDomain_RealLogs(t *testing.T) {
	const window = 300
	for _, origin := range []string{
		"log.sycamore.ct.letsencrypt.org/2026h2",              // Sunlight (Let's Encrypt)
		"parcelyard2026h2.prod.certificate.transparency.goog", // Tessera (Google)
		"gouda2026h2.log.ct.ipng.ch",                          // TesseraCT (IPng)
		"luoshu2027.trustasia.com/luoshu2027",                 // TrustAsia
	} {
		t.Run(origin, func(t *testing.T) {
			f := findFixture(t, origin)
			hc := liveClient()
			key := f.key(t)
			cp, err := fetchCheckpoint(context.Background(), hc, f.MonitoringURL)
			if err != nil {
				t.Skipf("fetch checkpoint: %v", err)
			}
			sth, err := ParseAndVerifyCheckpoint(cp, f.Origin, key)
			if err != nil {
				t.Fatalf("verify checkpoint: %v", err)
			}
			if sth.TreeSize <= window {
				t.Skipf("tree too small (%d)", sth.TreeSize)
			}
			start := sth.TreeSize - window
			prov := &Provider{
				Cfg:        Config{Domain: "com", LogURL: f.MonitoringURL, Origin: f.Origin, PublicKeyPEM: f.pem(t), Cache: &Cache{LastTreeSize: start}},
				HTTPClient: hc,
			}
			got, err := prov.QueryDomain(context.Background(), "com")
			if err != nil {
				t.Fatalf("QueryDomain: %v", err)
			}
			t.Logf("start=%d head=%d entries=%d verified=%d proof_fetch_failures=%d last_seen=%d",
				start, prov.LastSeenTreeSize, len(got), prov.LastVerifiedCount, prov.LastProofFetchFailures, prov.LastSeenTreeSize)
			if prov.LastVerifiedCount == 0 {
				t.Errorf("no inclusion proofs verified in a %d-leaf window", window)
			}
			if prov.LastProofFetchFailures == 0 && prov.LastSeenTreeSize < sth.TreeSize {
				t.Errorf("LastSeenTreeSize %d < earlier head %d with no fetch failures", prov.LastSeenTreeSize, sth.TreeSize)
			}
		})
	}
}
