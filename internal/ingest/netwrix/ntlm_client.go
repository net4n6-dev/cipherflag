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
package netwrix

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/go-ntlmssp"
	"github.com/rs/zerolog/log"
)

// NTLMClient is the production APIClient — talks to Netwrix's REST API
// over HTTPS with NTLM authentication.
type NTLMClient struct {
	cfg   Config
	http  *http.Client
	close func()
}

// NewClient constructs an APIClient using the production NTLM implementation.
// Tests use NewMockClient instead.
func NewClient(cfg Config) (APIClient, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("netwrix: BaseURL is required")
	}
	if cfg.Username == "" || cfg.Password == "" {
		return nil, fmt.Errorf("netwrix: Username and Password are required")
	}

	timeout := cfg.HTTPTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipTLS,
		},
	}
	if cfg.InsecureSkipTLS {
		log.Warn().Str("base_url", cfg.BaseURL).Msg("netwrix: TLS verification disabled (insecure_skip_tls=true) — use only in test environments")
	}

	client := &http.Client{
		Transport: ntlmssp.Negotiator{RoundTripper: transport},
		Timeout:   timeout,
	}

	return &NTLMClient{
		cfg:   cfg,
		http:  client,
		close: func() { transport.CloseIdleConnections() },
	}, nil
}

// searchRequest is the body posted to Netwrix's /api/v1/activity/search.
// Field names follow Netwrix's documented schema; unknown fields the API
// returns are preserved in ActivityRecord.Raw for the mapper.
type searchRequest struct {
	Filter searchRequestFilter `json:"filter"`
	Page   searchRequestPage   `json:"page"`
}

type searchRequestFilter struct {
	Since       string   `json:"since,omitempty"`
	Until       string   `json:"until,omitempty"`
	DataSource  string   `json:"dataSource,omitempty"`
	ObjectTypes []string `json:"objectTypes,omitempty"`
	Actions     []string `json:"actions,omitempty"`
}

type searchRequestPage struct {
	PageToken string `json:"pageToken,omitempty"`
	PageSize  int    `json:"pageSize"`
}

// searchResponse is the response shape returned by Netwrix's search endpoint.
// Records are decoded into map[string]interface{} so the mapper can extract
// fields tolerantly across Netwrix versions.
type searchResponse struct {
	Records       []map[string]interface{} `json:"records"`
	HasMore       bool                     `json:"hasMore,omitempty"`
	NextPageToken string                   `json:"nextPageToken,omitempty"`
}

// SearchActivity calls /api/v1/activity/search, paging until HasMore is false.
func (c *NTLMClient) SearchActivity(ctx context.Context, filter SearchFilter) ([]ActivityRecord, error) {
	pageSize := filter.MaxResults
	if pageSize <= 0 {
		pageSize = 1000
	}

	url := strings.TrimRight(c.cfg.BaseURL, "/") + "/api/v1/activity/search"

	var all []ActivityRecord
	pageToken := ""

	for {
		body := searchRequest{
			Filter: searchRequestFilter{
				DataSource:  filter.DataSource,
				ObjectTypes: filter.ObjectTypes,
				Actions:     filter.Actions,
			},
			Page: searchRequestPage{
				PageToken: pageToken,
				PageSize:  pageSize,
			},
		}
		if !filter.Since.IsZero() {
			body.Filter.Since = filter.Since.UTC().Format(time.RFC3339)
		}
		if !filter.Until.IsZero() {
			body.Filter.Until = filter.Until.UTC().Format(time.RFC3339)
		}

		buf, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal search request: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
		if err != nil {
			return nil, fmt.Errorf("build search request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		// ntlmssp.Negotiator converts BasicAuth to NTLM when challenged.
		req.SetBasicAuth(c.cfg.Username, c.cfg.Password)

		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("netwrix search request: %w", err)
		}

		respBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read netwrix response: %w", readErr)
		}
		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("netwrix search returned %d: %s", resp.StatusCode, string(respBody))
		}

		var page searchResponse
		if err := json.Unmarshal(respBody, &page); err != nil {
			return nil, fmt.Errorf("decode netwrix response: %w", err)
		}

		for _, raw := range page.Records {
			rec := ActivityRecord{Raw: raw}
			if ts, ok := raw["EventTime"].(string); ok {
				rec.EventTime = parseRFC3339(ts)
			}
			all = append(all, rec)
		}

		if !page.HasMore {
			break
		}
		pageToken = page.NextPageToken
		if pageToken == "" {
			// Defensive: if HasMore=true but no token, avoid infinite loop.
			break
		}
	}

	return all, nil
}

// Close releases idle connections.
func (c *NTLMClient) Close() error {
	if c.close != nil {
		c.close()
	}
	return nil
}
