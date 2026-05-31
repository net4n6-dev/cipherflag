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

package absolute

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
	"time"
)

const defaultHTTPTimeout = 60 * time.Second

// httpClient is the production APIClient. Requests are signed via the
// embedded Signer before being executed.
type httpClient struct {
	cfg    Config
	http   *http.Client
	signer Signer
}

// NewClient constructs a production APIClient.
func NewClient(cfg Config) (APIClient, error) {
	if cfg.TokenID == "" {
		return nil, fmt.Errorf("absolute: TokenID is required")
	}
	if cfg.SecretKey == "" {
		return nil, fmt.Errorf("absolute: SecretKey is required")
	}
	if cfg.ConsoleURL == "" {
		return nil, fmt.Errorf("absolute: ConsoleURL is required")
	}
	timeout := cfg.HTTPTimeout
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	return &httpClient{
		cfg:    cfg,
		http:   &http.Client{Timeout: timeout},
		signer: NewHMACSigner(cfg.TokenID, cfg.SecretKey),
	}, nil
}

// doJSON performs an authenticated request and returns the response body.
// Returns *RateLimitError on 429, *AuthError on 401/403, plain error on
// other non-2xx.
func (c *httpClient) doJSON(ctx context.Context, method, path string, query url.Values, body []byte) ([]byte, error) {
	u := strings.TrimRight(c.cfg.ConsoleURL, "/") + path
	if len(query) > 0 {
		u = u + "?" + query.Encode()
	}

	var reqBody io.Reader
	if len(body) > 0 {
		reqBody = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reqBody)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if err := c.signer.Sign(req, body); err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	respBody, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return nil, fmt.Errorf("read body: %w", readErr)
	}

	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		retry := parseRetryAfter(resp.Header.Get("Retry-After"))
		return nil, &RateLimitError{RetryAfter: retry}
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, &AuthError{StatusCode: resp.StatusCode, Body: string(respBody)}
	case resp.StatusCode >= 400:
		return nil, fmt.Errorf("absolute %s %s returned %d: %.512s", method, path, resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// installedAppsResponse mirrors the software-inventory response envelope.
type installedAppsResponse struct {
	Data []struct {
		DeviceUID   string `json:"deviceUid"`
		DeviceName  string `json:"deviceName"`
		OSFamily    string `json:"osFamily"`
		AppName     string `json:"appName"`
		AppVendor   string `json:"appVendor"`
		AppVersion  string `json:"appVersion"`
		InstalledAt string `json:"installedAt"`
	} `json:"data"`
}

func (c *httpClient) ListInstalledApplications(ctx context.Context, since time.Time, nameFilters []string) ([]DeviceApp, error) {
	q := url.Values{}
	if len(nameFilters) > 0 {
		parts := make([]string, 0, len(nameFilters))
		for _, f := range nameFilters {
			parts = append(parts, fmt.Sprintf("contains(tolower(appName),'%s')", strings.ToLower(f)))
		}
		q.Set("$filter", strings.Join(parts, " or "))
	}
	if !since.IsZero() {
		q.Set("installedAt__gt", since.UTC().Format(time.RFC3339Nano))
	}
	q.Set("$top", "1000")

	body, err := c.doJSON(ctx, http.MethodGet, "/v2/reporting/installed-applications", q, nil)
	if err != nil {
		return nil, err
	}

	var env installedAppsResponse
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("decode installed-applications: %w", err)
	}

	out := make([]DeviceApp, 0, len(env.Data))
	for _, e := range env.Data {
		var installedAt time.Time
		if e.InstalledAt != "" {
			if t, err := time.Parse(time.RFC3339Nano, e.InstalledAt); err == nil {
				installedAt = t
			} else if t, err := time.Parse(time.RFC3339, e.InstalledAt); err == nil {
				installedAt = t
			}
		}
		out = append(out, DeviceApp{
			DeviceID:    e.DeviceUID,
			DeviceName:  e.DeviceName,
			OSPlatform:  e.OSFamily,
			AppName:     e.AppName,
			AppVendor:   e.AppVendor,
			AppVersion:  e.AppVersion,
			InstalledAt: installedAt,
		})
	}
	return out, nil
}

// executeRequest is the JSON body POSTed to /v2/reach/executions.
type executeRequest struct {
	ScriptID string `json:"scriptId"`
	Target   struct {
		Scope string `json:"scope"`
	} `json:"target"`
}

type executeResponse struct {
	Data struct {
		ExecutionID string `json:"executionId"`
	} `json:"data"`
}

// ExecuteReachScript implements APIClient. v1 only supports target="all".
func (c *httpClient) ExecuteReachScript(ctx context.Context, scriptID, target string) (string, error) {
	if target != "all" {
		return "", fmt.Errorf("absolute: unsupported Reach target %q (v1 supports 'all' only)", target)
	}
	body := executeRequest{ScriptID: scriptID}
	body.Target.Scope = "all"
	buf, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal execute: %w", err)
	}

	respBody, err := c.doJSON(ctx, http.MethodPost, "/v2/reach/executions", nil, buf)
	if err != nil {
		return "", err
	}
	var env executeResponse
	if err := json.Unmarshal(respBody, &env); err != nil {
		return "", fmt.Errorf("decode execute response: %w", err)
	}
	if env.Data.ExecutionID == "" {
		return "", fmt.Errorf("absolute: execute response missing executionId: %s", string(respBody))
	}
	return env.Data.ExecutionID, nil
}

type statusResponse struct {
	Data struct {
		ExecutionID  string `json:"executionId"`
		Status       string `json:"status"`
		StatusReason string `json:"statusReason"`
	} `json:"data"`
}

// GetReachExecutionStatus implements APIClient.
func (c *httpClient) GetReachExecutionStatus(ctx context.Context, executionID string) (ReachTaskStatus, error) {
	path := "/v2/reach/executions/" + url.PathEscape(executionID)
	body, err := c.doJSON(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return ReachTaskStatus{}, err
	}
	var env statusResponse
	if err := json.Unmarshal(body, &env); err != nil {
		return ReachTaskStatus{}, fmt.Errorf("decode status: %w", err)
	}
	return ReachTaskStatus{
		ExecutionID: env.Data.ExecutionID,
		State:       normaliseReachState(env.Data.Status),
		Detail:      env.Data.StatusReason,
	}, nil
}

func normaliseReachState(raw string) ReachTaskState {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "pending", "queued", "scheduled":
		return ReachTaskStatePending
	case "running", "in_progress", "executing":
		return ReachTaskStateRunning
	case "completed", "succeeded", "success":
		return ReachTaskStateCompleted
	case "failed", "error":
		return ReachTaskStateFailed
	case "expired", "timeout", "timed_out":
		return ReachTaskStateExpired
	}
	return ReachTaskStatePending
}

// GetReachExecutionResults implements APIClient. Caller must Close the
// returned reader.
func (c *httpClient) GetReachExecutionResults(ctx context.Context, executionID string) (io.ReadCloser, error) {
	path := "/v2/reach/executions/" + url.PathEscape(executionID) + "/results"
	u := strings.TrimRight(c.cfg.ConsoleURL, "/") + path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("build results request: %w", err)
	}
	req.Header.Set("Accept", "application/x-ndjson, application/json")
	if err := c.signer.Sign(req, nil); err != nil {
		return nil, fmt.Errorf("sign results: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("results request: %w", err)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		retry := parseRetryAfter(resp.Header.Get("Retry-After"))
		resp.Body.Close()
		return nil, &RateLimitError{RetryAfter: retry}
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, &AuthError{StatusCode: resp.StatusCode, Body: string(body)}
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("absolute GET results returned %d: %.512s", resp.StatusCode, string(body))
	}
	return resp.Body, nil
}

func (c *httpClient) Close() error {
	c.http.CloseIdleConnections()
	return nil
}

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
