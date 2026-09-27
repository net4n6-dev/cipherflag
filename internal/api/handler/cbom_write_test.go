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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom/cbomtest"
)

func TestCBOMHandler_Download_SignedBOMKeepsSignature(t *testing.T) {
	h := newTestCBOMHandler(&fakeCBOMGen{bom: cbomtest.SignedBOM(t)}, &config.CBOMConfig{})

	rr := httptest.NewRecorder()
	h.Download(rr, httptest.NewRequest(http.MethodGet, "/api/v1/export/cbom?asset_type=certificate", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rr.Code, rr.Body.String())
	}
	cbomtest.AssertValidSignature(t, rr.Body.Bytes())
}

func TestRepoCBOMHandler_SignedDownloadKeepsSignature(t *testing.T) {
	h := NewRepoCBOMHandler(&fakeRepoCBOMStore{}, cbomtest.SigningConfig(t))

	rr := httptest.NewRecorder()
	h.Download(rr, httptest.NewRequest(http.MethodGet,
		"/api/v1/repo/exports/cbom?repo_id=11111111-1111-1111-1111-111111111111", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rr.Code, rr.Body.String())
	}
	cbomtest.AssertValidSignature(t, rr.Body.Bytes())
	if !strings.Contains(rr.Body.String(), "\n  ") {
		t.Errorf("repo CBOM output should stay indented")
	}
	if !strings.HasSuffix(rr.Body.String(), "\n") {
		t.Errorf("repo CBOM output should end with a newline, as it did before")
	}
}

func TestExtendWriteDeadline_IgnoresRecorder(t *testing.T) {
	extendWriteDeadline(httptest.NewRecorder()) // must not panic or log an error
}

// The server-wide WriteTimeout would cut off a slow export. A real server with
// a short timeout shows the helper lets a slow handler finish, and that the
// control case (no extension) really is cut off.
func TestExtendWriteDeadline_LetsSlowHandlerFinish(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("extend") == "1" {
			extendWriteDeadline(w)
		}
		time.Sleep(400 * time.Millisecond)
		_, _ = w.Write([]byte("done"))
	}))
	srv.Config.WriteTimeout = 150 * time.Millisecond
	srv.Start()
	defer srv.Close()

	if resp, err := http.Get(srv.URL + "/?extend=0"); err == nil {
		resp.Body.Close()
		t.Fatalf("control request should have been cut off by WriteTimeout")
	}

	resp, err := http.Get(srv.URL + "/?extend=1")
	if err != nil {
		t.Fatalf("extended request failed: %v", err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 4)
	if n, _ := resp.Body.Read(buf); string(buf[:n]) != "done" {
		t.Errorf("body = %q, want done", buf[:n])
	}
}

func TestWriteBOM_SerialisationFailureIs500(t *testing.T) {
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_1 // the JSON encoder rejects spec versions below 1.2

	rr := httptest.NewRecorder()
	writeBOM(rr, bom, "x.cdx.json", false)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body = %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Content-Disposition") != "" {
		t.Errorf("no attachment header should be sent for a failed serialisation")
	}
}
