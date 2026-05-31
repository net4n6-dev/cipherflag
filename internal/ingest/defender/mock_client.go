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
	"context"
	"sync"
)

// MockClient is a test fake implementing APIClient. Tests preconfigure the
// rows returned by RunAdvancedQuery and optionally an error to return.
type MockClient struct {
	mu sync.Mutex

	// Rows returned by RunAdvancedQuery.
	Rows []QueryRow

	// Err returned by RunAdvancedQuery if non-nil.
	Err error

	// LastQuery captures the KQL passed to the most recent call.
	LastQuery string

	// CallCount is incremented on each RunAdvancedQuery call.
	CallCount int
}

// NewMockClient returns an empty MockClient.
func NewMockClient() *MockClient {
	return &MockClient{}
}

func (m *MockClient) RunAdvancedQuery(_ context.Context, kql string) ([]QueryRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CallCount++
	m.LastQuery = kql
	if m.Err != nil {
		return nil, m.Err
	}
	out := make([]QueryRow, len(m.Rows))
	copy(out, m.Rows)
	return out, nil
}

func (m *MockClient) Close() error { return nil }
