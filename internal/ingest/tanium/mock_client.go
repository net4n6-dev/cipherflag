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
	"context"
	"sync"
)

// MockClient is a test fake implementing APIClient. Tests preconfigure the
// responses for ListEndpoints either as a single page (Page) or a slice of
// pages (Pages, consumed in order) and read back captured inputs.
type MockClient struct {
	mu sync.Mutex

	// Page is the single-page response returned when Pages is nil.
	Page EndpointPage

	// Pages, when non-nil, returns one entry per ListEndpoints call (in order).
	// Useful for multi-page pagination tests.
	Pages []EndpointPage

	// Err is returned by ListEndpoints if non-nil.
	Err error

	// CallCount increments on each ListEndpoints call.
	CallCount int

	// LastAfter captures the "after" argument of the most recent call.
	LastAfter string
}

// NewMockClient returns an empty MockClient.
func NewMockClient() *MockClient { return &MockClient{} }

func (m *MockClient) ListEndpoints(_ context.Context, after string) (EndpointPage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CallCount++
	m.LastAfter = after
	if m.Err != nil {
		return EndpointPage{}, m.Err
	}
	if m.Pages != nil {
		idx := m.CallCount - 1
		if idx >= len(m.Pages) {
			return EndpointPage{}, nil
		}
		return m.Pages[idx], nil
	}
	return m.Page, nil
}

func (m *MockClient) Close() error { return nil }
