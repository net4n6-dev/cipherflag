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
package defender

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultAPIBaseURL = "https://api.security.microsoft.com"
	defaultScope      = "https://api.security.microsoft.com/.default"
	defaultTimeout    = 60 * time.Second
	// Refresh tokens 5 minutes before they expire to avoid edge-case races.
	tokenSafetyMargin = 5 * time.Minute
)

// OAuthClient is the production APIClient — talks to Microsoft Defender's
// Advanced Hunting API over HTTPS using Entra ID OAuth client_credentials.
type OAuthClient struct {
	cfg  Config
	http *http.Client

	mu          sync.Mutex
	cachedToken string
	tokenExpiry time.Time
}

// NewClient constructs an APIClient using the production OAuth implementation.
// Tests use NewMockClient instead.
func NewClient(cfg Config) (APIClient, error) {
	if cfg.TenantID == "" {
		return nil, fmt.Errorf("defender: TenantID is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("defender: ClientID is required")
	}
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("defender: ClientSecret is required")
	}

	if cfg.APIBaseURL == "" {
		cfg.APIBaseURL = defaultAPIBaseURL
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", cfg.TenantID)
	}
	timeout := cfg.HTTPTimeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	return &OAuthClient{
		cfg:  cfg,
		http: &http.Client{Timeout: timeout},
	}, nil
}

// tokenResponse is the OAuth token endpoint response shape.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// acquireToken returns a valid bearer token, fetching a new one if the
// cache is empty or the cached token is within the safety margin of expiry.
func (c *OAuthClient) acquireToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.cachedToken != "" && time.Now().Add(tokenSafetyMargin).Before(c.tokenExpiry) {
		token := c.cachedToken
		c.mu.Unlock()
		return token, nil
	}
	c.mu.Unlock()

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", c.cfg.ClientID)
	form.Set("client_secret", c.cfg.ClientSecret)
	form.Set("scope", defaultScope)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("token response missing access_token: %s", string(body))
	}

	c.mu.Lock()
	c.cachedToken = tr.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	c.mu.Unlock()

	return tr.AccessToken, nil
}

// queryRequest is the body POSTed to /api/advancedqueries/run.
type queryRequest struct {
	Query string `json:"Query"`
}

// queryResponse is the response shape from /api/advancedqueries/run.
// Schema and Stats fields exist in the API response but are not consumed by
// the mapper (which uses the column names that already appear as keys in
// each Results row). If schema-aware type coercion is needed in the future
// (e.g., to handle DateTime → time.Time conversion), restore Schema here.
type queryResponse struct {
	Results []map[string]any `json:"Results"`
}

// RunAdvancedQuery executes a KQL query and returns the result rows.
func (c *OAuthClient) RunAdvancedQuery(ctx context.Context, kql string) ([]QueryRow, error) {
	token, err := c.acquireToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire token: %w", err)
	}

	body, err := json.Marshal(queryRequest{Query: kql})
	if err != nil {
		return nil, fmt.Errorf("marshal query request: %w", err)
	}

	url := strings.TrimRight(c.cfg.APIBaseURL, "/") + "/api/advancedqueries/run"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build query request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query request: %w", err)
	}
	defer resp.Body.Close()

	respBody, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return nil, fmt.Errorf("read query response: %w", readErr)
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
		return nil, &RateLimitError{RetryAfter: retryAfter}
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("query returned %d: %s", resp.StatusCode, string(respBody))
	}

	var qr queryResponse
	if err := json.Unmarshal(respBody, &qr); err != nil {
		return nil, fmt.Errorf("decode query response: %w", err)
	}

	out := make([]QueryRow, 0, len(qr.Results))
	for _, r := range qr.Results {
		out = append(out, QueryRow{Columns: r})
	}
	return out, nil
}

// Close releases idle connections.
func (c *OAuthClient) Close() error {
	c.http.CloseIdleConnections()
	return nil
}

// parseRetryAfter parses the Retry-After header. It accepts either a delta
// in seconds (integer) or an HTTP-date. Returns 0 if both fail.
func parseRetryAfter(s string) time.Duration {
	if s == "" {
		return 0
	}
	if secs, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(s); err == nil {
		d := time.Until(t)
		if d > 0 {
			return d
		}
	}
	return 0
}
