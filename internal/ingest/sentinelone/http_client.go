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
package sentinelone

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

const defaultHTTPTimeout = 60 * time.Second

// httpClient is the production APIClient for SentinelOne.
type httpClient struct {
	cfg  Config
	http *http.Client
}

// NewClient constructs a production APIClient.
func NewClient(cfg Config) (APIClient, error) {
	if cfg.APIToken == "" {
		return nil, fmt.Errorf("sentinelone: APIToken is required")
	}
	if cfg.ConsoleURL == "" {
		return nil, fmt.Errorf("sentinelone: ConsoleURL is required")
	}
	timeout := cfg.HTTPTimeout
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	return &httpClient{
		cfg:  cfg,
		http: &http.Client{Timeout: timeout},
	}, nil
}

// doJSON performs an authenticated request and returns the body bytes.
// Returns *RateLimitError on 429 and a plain error on any other non-2xx.
func (c *httpClient) doJSON(ctx context.Context, method, path string, query url.Values, body io.Reader) ([]byte, error) {
	u := strings.TrimRight(c.cfg.ConsoleURL, "/") + path
	if len(query) > 0 {
		u = u + "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "ApiToken "+c.cfg.APIToken)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
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
	if resp.StatusCode == http.StatusTooManyRequests {
		retry := parseRetryAfter(resp.Header.Get("Retry-After"))
		return nil, &RateLimitError{RetryAfter: retry}
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, &AuthError{StatusCode: resp.StatusCode, Body: string(respBody)}
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("sentinelone %s %s returned %d: %s", method, path, resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

// installedAppsResponse is the envelope returned by /installed-applications.
type installedAppsResponse struct {
	Data []struct {
		AgentDetails struct {
			UUID         string `json:"uuid"`
			ComputerName string `json:"computerName"`
			OSType       string `json:"osType"`
		} `json:"agentDetails"`
		Name        string `json:"name"`
		Vendor      string `json:"vendor"`
		Version     string `json:"version"`
		InstalledAt string `json:"installedAt"`
	} `json:"data"`
}

func (c *httpClient) ListInstalledApplications(ctx context.Context, since time.Time, nameFilters []string) ([]AppRecord, error) {
	q := url.Values{}
	if len(nameFilters) > 0 {
		// SentinelOne's installed-applications endpoint supports
		// "name__contains" with a comma-separated list of substrings.
		q.Set("name__contains", strings.Join(nameFilters, ","))
	}
	if !since.IsZero() {
		q.Set("installedAt__gt", since.UTC().Format(time.RFC3339Nano))
	}
	q.Set("limit", "1000")

	body, err := c.doJSON(ctx, http.MethodGet, "/web/api/v2.1/installed-applications", q, nil)
	if err != nil {
		return nil, err
	}

	var env installedAppsResponse
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("decode installed-applications: %w", err)
	}

	out := make([]AppRecord, 0, len(env.Data))
	for _, e := range env.Data {
		var installedAt time.Time
		if e.InstalledAt != "" {
			t, err := time.Parse(time.RFC3339Nano, e.InstalledAt)
			if err != nil {
				t, err = time.Parse(time.RFC3339, e.InstalledAt)
			}
			if err == nil {
				installedAt = t
			} else {
				log.Warn().Str("installed_at", e.InstalledAt).Str("app", e.Name).Msg("sentinelone: could not parse installedAt, leaving zero")
			}
		}
		out = append(out, AppRecord{
			AgentUUID:   e.AgentDetails.UUID,
			AgentName:   e.AgentDetails.ComputerName,
			OSType:      e.AgentDetails.OSType,
			AppName:     e.Name,
			AppVendor:   e.Vendor,
			AppVersion:  e.Version,
			InstalledAt: installedAt,
		})
	}
	return out, nil
}

// executeRequest is the JSON body sent to /remote-scripts/execute.
type executeRequest struct {
	Data   executeRequestData `json:"data"`
	Filter map[string]any     `json:"filter"`
}

type executeRequestData struct {
	ScriptID     string `json:"scriptId"`
	OutputDest   string `json:"outputDestination"`
	TaskDesc     string `json:"taskDescription"`
	SingletonKey string `json:"singletonKey,omitempty"`
}

// executeResponse is the envelope returned by /remote-scripts/execute.
type executeResponse struct {
	Data struct {
		ParentTaskID string `json:"parentTaskId"`
		Affected     int    `json:"affected"`
	} `json:"data"`
}

// ExecuteRemoteScript implements APIClient.
func (c *httpClient) ExecuteRemoteScript(ctx context.Context, scriptID, target string) (string, error) {
	if target != "all" {
		return "", fmt.Errorf("sentinelone: unsupported RSO target %q (v1 supports 'all' only)", target)
	}
	// target=all: empty filter selects all agents visible to the token's scope.
	body := executeRequest{
		Data: executeRequestData{
			ScriptID:   scriptID,
			OutputDest: "SentinelCloud",
			TaskDesc:   "CipherFlag crypto discovery",
		},
		Filter: map[string]any{},
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal execute body: %w", err)
	}

	respBody, err := c.doJSON(ctx, http.MethodPost, "/web/api/v2.1/remote-scripts/execute", nil, strings.NewReader(string(buf)))
	if err != nil {
		return "", err
	}
	var env executeResponse
	if err := json.Unmarshal(respBody, &env); err != nil {
		return "", fmt.Errorf("decode execute response: %w", err)
	}
	if env.Data.ParentTaskID == "" {
		return "", fmt.Errorf("sentinelone: execute response missing parentTaskId: %s", string(respBody))
	}
	return env.Data.ParentTaskID, nil
}

// statusResponseRow is one per-agent row in the status envelope.
type statusResponseRow struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	StatusReason string `json:"statusReason"`
}

// statusResponse is the envelope returned by /remote-scripts/status.
type statusResponse struct {
	Data []statusResponseRow `json:"data"`
}

// GetRemoteScriptStatus implements APIClient.
func (c *httpClient) GetRemoteScriptStatus(ctx context.Context, taskID string) (TaskStatus, error) {
	q := url.Values{}
	q.Set("parentTaskId", taskID)
	body, err := c.doJSON(ctx, http.MethodGet, "/web/api/v2.1/remote-scripts/status", q, nil)
	if err != nil {
		return TaskStatus{}, err
	}
	var env statusResponse
	if err := json.Unmarshal(body, &env); err != nil {
		return TaskStatus{}, fmt.Errorf("decode status: %w", err)
	}
	if len(env.Data) == 0 {
		return TaskStatus{TaskID: taskID, State: TaskStateExpired, Detail: "no status returned"}, nil
	}
	// Collapse per-agent statuses into a single parent-task state.
	state := collapseStates(env.Data)
	detail := env.Data[0].StatusReason
	return TaskStatus{TaskID: taskID, State: state, Detail: detail}, nil
}

// collapseStates picks a single TaskState from per-agent rows using priority:
// running > pending > expired > failed > completed. This reflects "still in
// flight" beating "terminal" so the poller keeps waiting for slow agents.
func collapseStates(rows []statusResponseRow) TaskState {
	has := map[TaskState]bool{}
	for _, r := range rows {
		has[normaliseState(r.Status)] = true
	}
	switch {
	case has[TaskStateRunning]:
		return TaskStateRunning
	case has[TaskStatePending]:
		return TaskStatePending
	case has[TaskStateExpired]:
		return TaskStateExpired
	case has[TaskStateFailed]:
		return TaskStateFailed
	case has[TaskStateCompleted]:
		return TaskStateCompleted
	}
	return TaskStatePending
}

func normaliseState(raw string) TaskState {
	switch strings.ToLower(raw) {
	case "in_progress", "running", "executing":
		return TaskStateRunning
	case "pending", "queued", "scheduled":
		return TaskStatePending
	case "completed", "succeeded", "success":
		return TaskStateCompleted
	case "failed", "error":
		return TaskStateFailed
	case "expired", "timeout", "timed_out":
		return TaskStateExpired
	}
	return TaskStatePending
}

// GetRemoteScriptResults implements APIClient. The caller must Close the returned reader.
func (c *httpClient) GetRemoteScriptResults(ctx context.Context, taskID string) (io.ReadCloser, error) {
	q := url.Values{}
	q.Set("parentTaskId", taskID)
	u := strings.TrimRight(c.cfg.ConsoleURL, "/") + "/web/api/v2.1/remote-scripts/results?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("build results request: %w", err)
	}
	req.Header.Set("Authorization", "ApiToken "+c.cfg.APIToken)
	req.Header.Set("Accept", "application/x-ndjson, application/json")

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
		return nil, fmt.Errorf("sentinelone GET results returned %d: %s", resp.StatusCode, string(body))
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
