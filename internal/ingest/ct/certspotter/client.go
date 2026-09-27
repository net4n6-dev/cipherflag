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

package certspotter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Issuance mirrors the SSLMate CertSpotter /v1/issuances JSON entry.
// Only the fields ct_certspotter needs are mapped.
type Issuance struct {
	ID         string   `json:"id"`
	TBSSHA256  string   `json:"tbs_sha256"`
	CertSHA256 string   `json:"cert_sha256"`
	DNSNames   []string `json:"dns_names"`
	Issuer     struct {
		Name string `json:"name"`
	} `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Cert      struct {
		Data string `json:"data"` // base64-encoded DER
	} `json:"cert"`
}

const initialBackoff = time.Second

// defaultHTTPClient is used whenever a Client is constructed without an
// explicit HTTP field. The 60s timeout matches the http.Client ct_multi
// hands its certspotter children (multi.NewPoller), so the standalone
// and multi-composed paths behave identically.
var defaultHTTPClient = &http.Client{Timeout: 60 * time.Second}

// Client is the HTTP-layer wrapper around the SSLMate CertSpotter API.
// Construction is the poller's responsibility; Client itself is
// stateless modulo the rate limiter.
type Client struct {
	// HTTP may be nil — httpClient() then falls back to
	// defaultHTTPClient. (Previously a nil HTTP reached c.HTTP.Do
	// directly and panicked on every production ct_certspotter cycle,
	// because the standalone poller's lazily-built Client never set it.)
	HTTP     *http.Client
	APIToken string
	BaseURL  string // default "https://api.certspotter.com" — overridden in tests
	Limiter  *RateLimiter
}

// httpClient returns c.HTTP, or defaultHTTPClient when unset. Single
// point of truth so no construction site can reintroduce the nil-client
// panic.
func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return defaultHTTPClient
}

// QueryDomain fetches a single page of issuances. nextCursor is the
// last entry's ID (suitable as input to the next call's `after`
// argument) or "" if the page was empty. Caller paginates via
// QueryDomainAll (Task 1.5) — this method is exposed for tests + future
// callers that want page-at-a-time control.
func (c *Client) QueryDomain(ctx context.Context, domain string, includeSubdomains bool, after string) ([]Issuance, string, error) {
	if err := c.Limiter.Wait(ctx); err != nil {
		return nil, "", fmt.Errorf("rate limit: %w", err)
	}

	q := url.Values{}
	q.Set("domain", domain)
	if includeSubdomains {
		q.Set("include_subdomains", "true")
	} else {
		q.Set("include_subdomains", "false")
	}
	q.Add("expand", "dns_names")
	q.Add("expand", "issuer")
	q.Add("expand", "cert")
	if after != "" {
		q.Set("after", after)
	}

	reqURL := c.BaseURL + "/v1/issuances?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("build request: %w", err)
	}
	if c.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIToken)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return nil, "", fmt.Errorf("certspotter: read body: %w", readErr)
	}
	if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 429 {
		return nil, "", fmt.Errorf("certspotter: %d %s: %s", resp.StatusCode, resp.Status, string(body))
	}
	if resp.StatusCode != 200 {
		// 429 / 5xx handled in Task 1.5 (the retry wrapper). This
		// branch lets callers distinguish; the single-page method
		// surfaces non-2xx as an error so tests can assert it.
		return nil, "", &httpError{Status: resp.StatusCode, RetryAfter: resp.Header.Get("Retry-After"), Body: string(body)}
	}

	var issuances []Issuance
	if err := json.Unmarshal(body, &issuances); err != nil {
		return nil, "", fmt.Errorf("decode: %w (body: %s)", err, snippet(body, 200))
	}

	var nextCursor string
	if len(issuances) > 0 {
		nextCursor = issuances[len(issuances)-1].ID
	}
	return issuances, nextCursor, nil
}

// httpError carries the HTTP status + Retry-After so the QueryDomainAll
// retry wrapper (Task 1.5) can branch on 429 vs 5xx.
type httpError struct {
	Status     int
	RetryAfter string
	Body       string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("certspotter: HTTP %d (Retry-After=%q): %s", e.Status, e.RetryAfter, snippet([]byte(e.Body), 200))
}

func snippet(b []byte, max int) string {
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "..."
}

// QueryDomainAll paginates QueryDomain until an empty page is returned,
// applying 429 + 5xx retry policy. On partial-page failure (page 1
// succeeds, page N fails), returns the pages-1..N-1 issuances PLUS the
// ORIGINAL input `after` cursor (NOT page-N-1's last id) — re-polling
// from the original cursor re-ingests pages 1..N-1, which the
// downstream Ingester dedups by fingerprint. Safer than partial-advance.
func (c *Client) QueryDomainAll(ctx context.Context, domain string, includeSubdomains bool, after string) ([]Issuance, string, error) {
	const maxRetries = 3
	originalCursor := after
	var allIssuances []Issuance
	cursor := after
	for {
		issuances, next, err := c.queryDomainWithRetries(ctx, domain, includeSubdomains, cursor, maxRetries)
		if err != nil {
			// Partial-failure: stay at original cursor.
			return allIssuances, originalCursor, err
		}
		allIssuances = append(allIssuances, issuances...)
		if len(issuances) == 0 {
			// Caught up. Return aggregator cursor (last successful id, or empty if zero pages).
			return allIssuances, cursor, nil
		}
		cursor = next
	}
}

// queryDomainWithRetries wraps QueryDomain with 429 + 5xx retry policy.
// 429: read Retry-After (seconds or HTTP-date), sleep, retry up to N.
// 5xx: exponential backoff 1s/2s/4s, retry up to N.
// 4xx (non-429): no retry (handled inside QueryDomain).
func (c *Client) queryDomainWithRetries(ctx context.Context, domain string, includeSubdomains bool, after string, maxRetries int) ([]Issuance, string, error) {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		issuances, next, err := c.QueryDomain(ctx, domain, includeSubdomains, after)
		if err == nil {
			return issuances, next, nil
		}
		lastErr = err
		var he *httpError
		if !errors.As(err, &he) {
			return nil, "", err // not retryable (network, decode, etc — surface immediately)
		}
		if he.Status >= 400 && he.Status < 500 && he.Status != 429 {
			return nil, "", err // 4xx non-429: no retry
		}
		if attempt == maxRetries {
			break
		}
		// Compute sleep.
		var sleep time.Duration
		if he.Status == 429 {
			sleep = parseRetryAfter(he.RetryAfter)
		} else {
			// 5xx: exponential backoff — 1s, 2s, 4s (initialBackoff × 2^attempt)
			sleep = time.Duration(1<<attempt) * initialBackoff
		}
		select {
		case <-time.After(sleep):
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
	}
	return nil, "", fmt.Errorf("retries exhausted: %w", lastErr)
}

// parseRetryAfter accepts either a seconds count or an HTTP-date.
// Returns 1s as a sensible floor (CertSpotter typically uses seconds).
func parseRetryAfter(h string) time.Duration {
	if h == "" {
		return 1 * time.Second
	}
	// Try integer seconds. Negative values fall through to the 1s floor below.
	if secs, err := time.ParseDuration(h + "s"); err == nil && secs > 0 {
		return secs
	}
	// Try HTTP-date.
	if t, err := http.ParseTime(h); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 1 * time.Second
}
