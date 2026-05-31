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
	"context"
	"sync"
)

// MockClient is a test fake implementing APIClient. Tests preconfigure the
// records returned by SearchActivity and optionally an error to return.
type MockClient struct {
	mu sync.Mutex

	// Records returned by SearchActivity (filter is captured but not applied —
	// tests configure exactly what each call should return).
	Records []ActivityRecord

	// Err returned by SearchActivity if non-nil.
	Err error

	// LastFilter captures the filter passed to the most recent call.
	LastFilter SearchFilter

	// CallCount is incremented on each SearchActivity call.
	CallCount int
}

// NewMockClient returns an empty MockClient.
func NewMockClient() *MockClient {
	return &MockClient{}
}

func (m *MockClient) SearchActivity(_ context.Context, filter SearchFilter) ([]ActivityRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CallCount++
	m.LastFilter = filter
	if m.Err != nil {
		return nil, m.Err
	}
	out := make([]ActivityRecord, len(m.Records))
	copy(out, m.Records)
	return out, nil
}

func (m *MockClient) Close() error { return nil }
