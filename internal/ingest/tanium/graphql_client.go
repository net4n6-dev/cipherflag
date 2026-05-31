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
package tanium

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	defaultHTTPTimeout = 60 * time.Second
	defaultPageSize    = 500
	graphqlPath        = "/plugin/products/gateway/graphql"
)

// discoveryQuery is the single GraphQL query issued each cycle.
const discoveryQuery = `query CipherFlagDiscovery($after: String, $first: Int!) {
  endpoints(first: $first, after: $after) {
    pageInfo { hasNextPage endCursor }
    edges {
      node {
        id
        name
        ipAddress
        operatingSystem { platform }
        sensorReadings(sensors: [
          { name: "CipherFlag.Crypto.Certificates" }
          { name: "CipherFlag.Crypto.SSHKeys" }
          { name: "CipherFlag.Crypto.Libraries" }
          { name: "CipherFlag.Crypto.Configs" }
          { name: "Installed Applications" }
        ]) {
          sensor { name }
          columns { name values }
        }
      }
    }
  }
}`

// graphqlClient is the production APIClient for Tanium.
type graphqlClient struct {
	cfg      Config
	http     *http.Client
	pageSize int
}

// NewClient constructs a production APIClient.
func NewClient(cfg Config) (APIClient, error) {
	if cfg.APIToken == "" {
		return nil, fmt.Errorf("tanium: APIToken is required")
	}
	if cfg.ConsoleURL == "" {
		return nil, fmt.Errorf("tanium: ConsoleURL is required")
	}
	timeout := cfg.HTTPTimeout
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	pageSize := cfg.PageSize
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	return &graphqlClient{
		cfg:      cfg,
		http:     &http.Client{Timeout: timeout},
		pageSize: pageSize,
	}, nil
}

// graphqlRequest is the JSON body POSTed to the GraphQL endpoint.
type graphqlRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

// graphqlError is one entry in the GraphQL response's "errors" envelope.
type graphqlError struct {
	Message string `json:"message"`
}

// rawResponse mirrors the GraphQL response envelope.
type rawResponse struct {
	Data struct {
		Endpoints struct {
			PageInfo struct {
				HasNextPage bool   `json:"hasNextPage"`
				EndCursor   string `json:"endCursor"`
			} `json:"pageInfo"`
			Edges []struct {
				Node struct {
					ID              string `json:"id"`
					Name            string `json:"name"`
					IPAddress       string `json:"ipAddress"`
					OperatingSystem struct {
						Platform string `json:"platform"`
					} `json:"operatingSystem"`
					SensorReadings []struct {
						Sensor struct {
							Name string `json:"name"`
						} `json:"sensor"`
						Columns []struct {
							Name   string   `json:"name"`
							Values []string `json:"values"`
						} `json:"columns"`
					} `json:"sensorReadings"`
				} `json:"node"`
			} `json:"edges"`
		} `json:"endpoints"`
	} `json:"data"`
	Errors []graphqlError `json:"errors"`
}

// ListEndpoints implements APIClient.
func (c *graphqlClient) ListEndpoints(ctx context.Context, after string) (EndpointPage, error) {
	body := graphqlRequest{
		Query: discoveryQuery,
		Variables: map[string]any{
			"after": after,
			"first": c.pageSize,
		},
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return EndpointPage{}, fmt.Errorf("marshal graphql body: %w", err)
	}

	u := strings.TrimRight(c.cfg.ConsoleURL, "/") + graphqlPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(buf))
	if err != nil {
		return EndpointPage{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("session", c.cfg.APIToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return EndpointPage{}, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	respBody, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return EndpointPage{}, fmt.Errorf("read body: %w", readErr)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		retry := parseRetryAfter(resp.Header.Get("Retry-After"))
		return EndpointPage{}, &RateLimitError{RetryAfter: retry}
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return EndpointPage{}, &AuthError{StatusCode: resp.StatusCode, Body: string(respBody)}
	}
	if resp.StatusCode >= 400 {
		return EndpointPage{}, fmt.Errorf("tanium GraphQL returned %d: %s", resp.StatusCode, string(respBody))
	}

	var raw rawResponse
	if err := json.Unmarshal(respBody, &raw); err != nil {
		return EndpointPage{}, fmt.Errorf("decode graphql response: %w", err)
	}
	if len(raw.Errors) > 0 {
		msgs := make([]string, 0, len(raw.Errors))
		for _, e := range raw.Errors {
			msgs = append(msgs, e.Message)
		}
		return EndpointPage{}, fmt.Errorf("tanium GraphQL errors: %s", strings.Join(msgs, "; "))
	}

	page := EndpointPage{
		EndCursor: raw.Data.Endpoints.PageInfo.EndCursor,
		HasNext:   raw.Data.Endpoints.PageInfo.HasNextPage,
		Endpoints: make([]EndpointResult, 0, len(raw.Data.Endpoints.Edges)),
	}
	for _, edge := range raw.Data.Endpoints.Edges {
		er := EndpointResult{
			EndpointID: edge.Node.ID,
			Hostname:   edge.Node.Name,
			IPAddress:  edge.Node.IPAddress,
			OSPlatform: edge.Node.OperatingSystem.Platform,
			Sensors:    make([]SensorReading, 0, len(edge.Node.SensorReadings)),
		}
		for _, sr := range edge.Node.SensorReadings {
			reading := SensorReading{
				SensorName: sr.Sensor.Name,
				Columns:    make([]SensorColumn, 0, len(sr.Columns)),
			}
			for _, col := range sr.Columns {
				reading.Columns = append(reading.Columns, SensorColumn{Name: col.Name, Values: col.Values})
			}
			er.Sensors = append(er.Sensors, reading)
		}
		page.Endpoints = append(page.Endpoints, er)
	}
	return page, nil
}

// Close releases idle connections.
func (c *graphqlClient) Close() error {
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
