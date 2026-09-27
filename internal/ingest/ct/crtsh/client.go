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

package crtsh

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// CrtShEntry is the JSON shape returned by https://crt.sh/?q=...&output=json.
// Subset of fields — we ignore log-specific metadata not needed for ingest.
type CrtShEntry struct {
	ID             int64  `json:"id"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"` // newline-separated SAN list
	IssuerName     string `json:"issuer_name"`
	NotBefore      string `json:"not_before"` // ISO-ish (no Z); crt.sh's quirky format
	NotAfter       string `json:"not_after"`
	EntryTimestamp string `json:"entry_timestamp"`
}

// Client wraps the crt.sh HTTP surface. Production callers construct
// with BaseURL = "https://crt.sh" and a default HTTPClient. Tests inject
// httptest.NewServer's URL.
type Client struct {
	BaseURL     string
	HTTPClient  *http.Client
	BackoffBase time.Duration // 0 → use default 5s; tests override to 1ms
}

const defaultBackoffBase = 5 * time.Second

// queryMaxRetries bounds the entry-list call (QueryDomain). The first
// query is the gateway to any cert discovery; aggressive retry on
// transient crt.sh failures is justified because failure here =
// scan returns nothing. 5 retries with exponential backoff (cap 60s)
// gives the scheduler ~3 minutes to weather a flap.
const queryMaxRetries = 5

// pemMaxRetries bounds individual PEM fetches (FetchPEM). Per-cert
// retries multiply: a domain with hundreds of historical certs and a
// flaky crt.sh upstream produces dozens of 502s, each taking ~90s with
// queryMaxRetries semantics. That ballooned single scans to hours and
// caused the "scanning forever" symptom. 2 retries is enough to ride
// out a transient nginx blip. A PEM whose fetch still fails is retried on
// the next poll cycle — Poller.pollDomain records an ID in its persisted
// seen-set only after a successful fetch — so there's no persistent data
// loss; the cycle's summary log just reports a non-zero fetch_failures.
const pemMaxRetries = 2

const maxBackoff = 60 * time.Second

func (c *Client) backoffBase() time.Duration {
	if c.BackoffBase > 0 {
		return c.BackoffBase
	}
	return defaultBackoffBase
}

// isTransientStatus reports whether an HTTP status from crt.sh's nginx
// front-end should be retried. 429/502/503/504 are all observed in
// practice — crt.sh's upstream is flaky and the nginx surface is the
// first thing to flap; 502 (Bad Gateway, upstream errored) and 504
// (Gateway Timeout) clear within seconds just like 503.
func isTransientStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, // 429
		http.StatusBadGateway,         // 502
		http.StatusServiceUnavailable, // 503
		http.StatusGatewayTimeout:     // 504
		return true
	}
	return false
}

// QueryDomain returns all crt.sh entries for the domain. If
// includeSubdomains is true, queries `%.<domain>` (URL-encoded as
// `%25.<domain>`); otherwise queries the bare domain. Retries on
// 429/502/503/504 with exponential backoff (cap 60s, max 5 retries).
func (c *Client) QueryDomain(ctx context.Context, domain string, includeSubdomains bool) ([]CrtShEntry, error) {
	q := domain
	if includeSubdomains {
		q = "%." + domain
	}
	u := fmt.Sprintf("%s/?q=%s&output=json", c.BaseURL, url.QueryEscape(q))

	var lastErr error
	backoff := c.backoffBase()
	for attempt := 0; attempt <= queryMaxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, fmt.Errorf("ct: build crt.sh request: %w", err)
		}
		req.Header.Set("User-Agent", "CipherFlag/1.x (+https://cipherflag.io)")
		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("ct: crt.sh GET %s: %w", u, err)
		} else {
			if isTransientStatus(resp.StatusCode) {
				_ = resp.Body.Close()
				lastErr = fmt.Errorf("ct: crt.sh status %d", resp.StatusCode)
			} else if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
				_ = resp.Body.Close()
				return nil, fmt.Errorf("ct: crt.sh status %d: %s", resp.StatusCode, body)
			} else {
				defer resp.Body.Close()
				var entries []CrtShEntry
				if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
					return nil, fmt.Errorf("ct: decode crt.sh JSON: %w", err)
				}
				return entries, nil
			}
		}
		if attempt == queryMaxRetries {
			break
		}
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return nil, fmt.Errorf("ct: crt.sh exhausted %d retries: %w", queryMaxRetries, lastErr)
}

// FetchPEM returns the PEM-encoded cert body for a single crt.sh ID.
// Uses pemMaxRetries (2) — fewer than QueryDomain because a missed PEM
// is recoverable on the next poll, and per-cert retries multiply badly
// across a domain with many historical certs.
func (c *Client) FetchPEM(ctx context.Context, id int64) (string, error) {
	u := fmt.Sprintf("%s/?d=%d", c.BaseURL, id)

	var lastErr error
	backoff := c.backoffBase()
	for attempt := 0; attempt <= pemMaxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return "", fmt.Errorf("ct: build crt.sh PEM request: %w", err)
		}
		req.Header.Set("User-Agent", "CipherFlag/1.x (+https://cipherflag.io)")
		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("ct: crt.sh PEM GET %s: %w", u, err)
		} else {
			if isTransientStatus(resp.StatusCode) {
				_ = resp.Body.Close()
				lastErr = fmt.Errorf("ct: crt.sh PEM status %d", resp.StatusCode)
			} else if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
				_ = resp.Body.Close()
				return "", fmt.Errorf("ct: crt.sh PEM status %d: %s", resp.StatusCode, body)
			} else {
				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return "", fmt.Errorf("ct: read crt.sh PEM body: %w", err)
				}
				return string(body), nil
			}
		}
		if attempt == pemMaxRetries {
			break
		}
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return "", fmt.Errorf("ct: crt.sh PEM exhausted %d retries: %w", pemMaxRetries, lastErr)
}
