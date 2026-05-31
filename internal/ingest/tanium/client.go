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
// Package tanium implements the CipherFlag adapter for Tanium.
//
// The adapter polls the Tanium GraphQL API Gateway each cycle, issuing a
// single paginated query for all managed endpoints. The query requests
// sensorReadings for four CipherFlag custom sensors (certificates, SSH keys,
// libraries, configs) plus the built-in Installed Applications sensor. The
// custom sensors emit NDJSON (one finding per line), which the mapper parses
// via the shared scriptparse package.
//
// v1 uses Core platform features only — custom sensors, Installed
// Applications, GraphQL API Gateway, Authoring. Module-gated data (Asset,
// SBOM, Certificate Manager) is deferred to Future Enhancements.
package tanium

import (
	"context"
	"fmt"
	"time"
)

// APIClient is the abstract interface CipherFlag uses to talk to Tanium.
// The real implementation (graphql_client.go) posts GraphQL queries over
// HTTPS using API token auth. Tests use MockClient.
type APIClient interface {
	// ListEndpoints paginates through the endpoints query with sensorReadings
	// for the four CipherFlag custom sensors plus Installed Applications.
	// "after" is empty on the first call; subsequent pages pass the previous
	// page's EndCursor. Returns *RateLimitError on 429, *AuthError on 401/403.
	ListEndpoints(ctx context.Context, after string) (EndpointPage, error)

	// Close releases idle connections held by the client.
	Close() error
}

// Config holds connection parameters for a real APIClient.
type Config struct {
	APIToken    string
	ConsoleURL  string        // e.g. https://customer-api.cloud.tanium.com
	HTTPTimeout time.Duration // defaults to 60s when zero
	PageSize    int           // defaults to 500 when zero
}

// EndpointPage is one page of endpoint results from the GraphQL query.
type EndpointPage struct {
	Endpoints []EndpointResult
	EndCursor string
	HasNext   bool
}

// EndpointResult is one endpoint with its sensor readings.
type EndpointResult struct {
	EndpointID string
	Hostname   string
	IPAddress  string
	OSPlatform string
	Sensors    []SensorReading
}

// SensorReading is one sensor's output for a given endpoint.
type SensorReading struct {
	SensorName string
	Columns    []SensorColumn
}

// SensorColumn is one column's name + values from a sensor reading.
type SensorColumn struct {
	Name   string
	Values []string
}

// RateLimitError is returned on HTTP 429 so the poller can skip cursor
// advance without conflating with other failures.
type RateLimitError struct {
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("tanium: rate limited (retry after %s)", e.RetryAfter)
	}
	return "tanium: rate limited"
}

// AuthError is returned on HTTP 401/403 so the poller can disable itself
// for the remainder of the process lifetime (preventing a hot-loop retry
// that could lock out the API token).
type AuthError struct {
	StatusCode int
	Body       string
}

func (e *AuthError) Error() string {
	body := e.Body
	const maxBody = 256
	if len(body) > maxBody {
		body = body[:maxBody] + "...(truncated)"
	}
	return fmt.Sprintf("tanium: auth failed (HTTP %d): %s", e.StatusCode, body)
}
