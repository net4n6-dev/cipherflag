package certspotter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// pageOne is a minimal valid CertSpotter response shape with one entry.
var pageOne = `[{
  "id": "1234567890",
  "tbs_sha256": "aaa",
  "cert_sha256": "BB11",
  "dns_names": ["example.com", "*.example.com"],
  "issuer": {"name": "CN=Test CA"},
  "not_before": "2026-01-01T00:00:00Z",
  "not_after":  "2026-04-01T00:00:00Z",
  "cert": {"data": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"}
}]`

func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := &Client{
		HTTP:    srv.Client(),
		BaseURL: srv.URL,
		Limiter: NewRateLimiter(100000), // effectively unlimited in tests
	}
	return c, srv
}

func TestClient_QueryDomain_HappyPath(t *testing.T) {
	var gotPath string
	var gotAuth string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.String()
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte(pageOne))
	})
	issuances, nextCursor, err := c.QueryDomain(context.Background(), "example.com", true, "")
	if err != nil {
		t.Fatalf("QueryDomain: %v", err)
	}
	if len(issuances) != 1 {
		t.Fatalf("issuances len = %d, want 1", len(issuances))
	}
	if issuances[0].ID != "1234567890" {
		t.Errorf("id = %q", issuances[0].ID)
	}
	if nextCursor != "1234567890" {
		t.Errorf("nextCursor = %q, want last id", nextCursor)
	}
	if !strings.Contains(gotPath, "domain=example.com") {
		t.Errorf("URL missing domain: %s", gotPath)
	}
	if !strings.Contains(gotPath, "include_subdomains=true") {
		t.Errorf("URL missing include_subdomains: %s", gotPath)
	}
	if !strings.Contains(gotPath, "expand=cert") {
		t.Errorf("URL missing expand=cert: %s", gotPath)
	}
	if gotAuth != "" {
		t.Errorf("Authorization unexpectedly set: %q", gotAuth)
	}
}

func TestClient_QueryDomain_SendsAuthHeaderWhenTokenSet(t *testing.T) {
	var gotAuth string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte(`[]`))
	})
	c.APIToken = "secret-token"
	_, _, err := c.QueryDomain(context.Background(), "x.com", false, "")
	if err != nil {
		t.Fatalf("QueryDomain: %v", err)
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("Authorization = %q", gotAuth)
	}
}

func TestClient_QueryDomain_EmptyPageReturnsEmptyCursor(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	})
	issuances, nextCursor, err := c.QueryDomain(context.Background(), "x.com", false, "abc")
	if err != nil {
		t.Fatalf("QueryDomain: %v", err)
	}
	if len(issuances) != 0 {
		t.Errorf("issuances len = %d, want 0", len(issuances))
	}
	if nextCursor != "" {
		t.Errorf("nextCursor = %q, want empty", nextCursor)
	}
}

func TestClient_QueryDomain_PropagatesAfterCursor(t *testing.T) {
	var gotPath string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.String()
		w.Write([]byte(`[]`))
	})
	if _, _, err := c.QueryDomain(context.Background(), "x.com", false, "cursor-xyz"); err != nil {
		t.Fatalf("QueryDomain: %v", err)
	}
	if !strings.Contains(gotPath, "after=cursor-xyz") {
		t.Errorf("URL missing after cursor: %s", gotPath)
	}
}

func TestClient_QueryDomain_4xxNoRetry(t *testing.T) {
	var calls int
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("bad domain"))
	})
	_, _, err := c.QueryDomain(context.Background(), "x.com", false, "")
	if err == nil {
		t.Fatal("expected error for 400")
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (no retry on 4xx)", calls)
	}
}

func TestClient_QueryDomain_DecodesAllFields(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(pageOne))
	})
	issuances, _, _ := c.QueryDomain(context.Background(), "x.com", false, "")
	got := issuances[0]
	if got.CertSHA256 != "BB11" {
		t.Errorf("CertSHA256 = %q", got.CertSHA256)
	}
	if got.Issuer.Name != "CN=Test CA" {
		t.Errorf("Issuer.Name = %q", got.Issuer.Name)
	}
	want, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	if !got.NotBefore.Equal(want) {
		t.Errorf("NotBefore = %v, want %v", got.NotBefore, want)
	}
	if len(got.DNSNames) != 2 || got.DNSNames[0] != "example.com" {
		t.Errorf("DNSNames = %v", got.DNSNames)
	}
	if got.Cert.Data == "" {
		t.Errorf("Cert.Data unexpectedly empty")
	}
}

// json.Marshal smoke-check the Issuance shape stays decodable both ways.
func TestIssuance_RoundTrip(t *testing.T) {
	var iss Issuance
	if err := json.Unmarshal([]byte(strings.TrimPrefix(strings.TrimSuffix(pageOne, "]"), "[")), &iss); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	out, _ := json.Marshal(iss)
	if !strings.Contains(string(out), `"id":"1234567890"`) {
		t.Errorf("round-trip lost id: %s", out)
	}
}

func TestClient_QueryDomainAll_Pagination(t *testing.T) {
	// 3 pages: ids 1..50 / 51..60 / empty.
	makePage := func(start, end int) string {
		out := "["
		for i := start; i <= end; i++ {
			if i > start {
				out += ","
			}
			out += fmt.Sprintf(`{"id":"%d","cert_sha256":"AA%d","dns_names":["x.com"],"not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","cert":{"data":"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"}}`, i, i)
		}
		return out + "]"
	}
	var calls int
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		after := r.URL.Query().Get("after")
		switch after {
		case "":
			w.Write([]byte(makePage(1, 50)))
		case "50":
			w.Write([]byte(makePage(51, 60)))
		case "60":
			w.Write([]byte(`[]`))
		default:
			t.Errorf("unexpected after=%q", after)
		}
	})
	issuances, cursor, err := c.QueryDomainAll(context.Background(), "x.com", false, "")
	if err != nil {
		t.Fatalf("QueryDomainAll: %v", err)
	}
	if len(issuances) != 60 {
		t.Errorf("len = %d, want 60", len(issuances))
	}
	if cursor != "60" {
		t.Errorf("cursor = %q, want 60", cursor)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
}

func TestClient_QueryDomainAll_429WithRetryAfter(t *testing.T) {
	var calls int
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(`[]`))
	})
	_, _, err := c.QueryDomainAll(context.Background(), "x.com", false, "")
	if err != nil {
		t.Fatalf("QueryDomainAll: %v", err)
	}
	if calls != 2 {
		t.Errorf("calls = %d, want 2 (1 retry)", calls)
	}
}

func TestClient_QueryDomainAll_429ExhaustsRetries(t *testing.T) {
	var calls int
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	_, _, err := c.QueryDomainAll(context.Background(), "x.com", false, "")
	if err == nil {
		t.Fatal("expected error after retry exhaustion")
	}
	if calls != 4 {
		t.Errorf("calls = %d, want 4 (1 + 3 retries)", calls)
	}
}

func TestClient_QueryDomainAll_5xxRetryThenSuccess(t *testing.T) {
	var calls int
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Write([]byte(`[]`))
	})
	_, _, err := c.QueryDomainAll(context.Background(), "x.com", false, "")
	if err != nil {
		t.Fatalf("QueryDomainAll: %v", err)
	}
}

func TestParseIssuances_AgainstRealCertSpotterResponse(t *testing.T) {
	data, err := os.ReadFile("testdata/real_certspotter_letsencrypt_org_response.json")
	if err != nil {
		t.Fatalf("ReadFile: %v (run testdata regen — see testdata/README.md)", err)
	}
	var issuances []Issuance
	if err := json.Unmarshal(data, &issuances); err != nil {
		t.Fatalf("Unmarshal: %v (SSLMate schema may have changed — regen fixture)", err)
	}
	if len(issuances) == 0 {
		t.Fatal("fixture is empty — regen against a current letsencrypt.org response")
	}
	first := issuances[0]
	if first.ID == "" {
		t.Error("first entry has empty ID")
	}
	if first.CertSHA256 == "" {
		t.Error("first entry has empty CertSHA256")
	}
	if first.NotBefore.IsZero() {
		t.Error("first entry has zero NotBefore")
	}
	if len(first.DNSNames) == 0 {
		t.Error("first entry has empty DNSNames")
	}
	t.Logf("decoded %d issuances; first id=%s sha=%s", len(issuances), first.ID, first.CertSHA256)
}

// PartialPageFailure: caller polls from a previous successful cursor
// ("input-cursor"); page 1 OK (ids 1..3), page 2 503-fails 3 times.
// Aggregator returns page-1 issuances + the ORIGINAL input cursor
// ("input-cursor"), not page-1's last id. Re-poll from "input-cursor"
// re-ingests page 1 (dedup downstream handles it) and retries page 2.
func TestClient_QueryDomainAll_PartialPageFailure_CursorStaysPut(t *testing.T) {
	page1 := `[
		{"id":"1","cert_sha256":"AA1","dns_names":["x.com"],"not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","cert":{"data":""}},
		{"id":"2","cert_sha256":"AA2","dns_names":["x.com"],"not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","cert":{"data":""}},
		{"id":"3","cert_sha256":"AA3","dns_names":["x.com"],"not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","cert":{"data":""}}
	]`
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		after := r.URL.Query().Get("after")
		// Server returns page1 when polled from the caller's input cursor
		// (the realistic incremental-poll scenario); fails on every
		// subsequent cursor to simulate a partial-page failure.
		if after == "input-cursor" {
			w.Write([]byte(page1))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	issuances, cursor, err := c.QueryDomainAll(context.Background(), "x.com", false, "input-cursor")
	if err == nil {
		t.Fatal("expected error after page-2 failure")
	}
	if len(issuances) != 3 {
		t.Errorf("len = %d, want 3 (page 1 preserved)", len(issuances))
	}
	if cursor != "input-cursor" {
		t.Errorf("cursor = %q, want input cursor preserved", cursor)
	}
}
