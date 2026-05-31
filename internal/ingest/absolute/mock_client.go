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
	"io"
	"sync"
	"time"
)

// MockClient is a test fake implementing APIClient. Tests preconfigure the
// responses for each method and read back captured inputs.
type MockClient struct {
	mu sync.Mutex

	// Inventory
	Apps       []DeviceApp
	AppErr     error
	AppCalls   int
	LastSince  time.Time
	LastFilter []string

	// Reach execute
	ExecuteExecutionID string
	ExecuteErr         error
	ExecuteCalls       []ExecuteCall

	// Reach status
	Statuses      map[string]ReachTaskStatus
	DefaultStatus ReachTaskStatus
	StatusErr     error
	StatusCalls   []string

	// Reach results
	Results     map[string][]byte
	ResultsErr  error
	ResultCalls []string
}

// ExecuteCall captures ExecuteReachScript arguments.
type ExecuteCall struct {
	ScriptID string
	Target   string
}

// NewMockClient returns an empty MockClient with initialized maps.
func NewMockClient() *MockClient {
	return &MockClient{
		Statuses: make(map[string]ReachTaskStatus),
		Results:  make(map[string][]byte),
	}
}

func (m *MockClient) ListInstalledApplications(_ context.Context, since time.Time, filters []string) ([]DeviceApp, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.AppCalls++
	m.LastSince = since
	m.LastFilter = append([]string(nil), filters...)
	if m.AppErr != nil {
		return nil, m.AppErr
	}
	out := make([]DeviceApp, len(m.Apps))
	copy(out, m.Apps)
	return out, nil
}

func (m *MockClient) ExecuteReachScript(_ context.Context, scriptID, target string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ExecuteCalls = append(m.ExecuteCalls, ExecuteCall{ScriptID: scriptID, Target: target})
	if m.ExecuteErr != nil {
		return "", m.ExecuteErr
	}
	return m.ExecuteExecutionID, nil
}

func (m *MockClient) GetReachExecutionStatus(_ context.Context, executionID string) (ReachTaskStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.StatusCalls = append(m.StatusCalls, executionID)
	if m.StatusErr != nil {
		return ReachTaskStatus{}, m.StatusErr
	}
	if s, ok := m.Statuses[executionID]; ok {
		return s, nil
	}
	if m.DefaultStatus.State == "" {
		return ReachTaskStatus{ExecutionID: executionID, State: ReachTaskStateRunning}, nil
	}
	s := m.DefaultStatus
	s.ExecutionID = executionID
	return s, nil
}

func (m *MockClient) GetReachExecutionResults(_ context.Context, executionID string) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ResultCalls = append(m.ResultCalls, executionID)
	if m.ResultsErr != nil {
		return nil, m.ResultsErr
	}
	body, ok := m.Results[executionID]
	if !ok {
		body = nil
	}
	return io.NopCloser(bytes.NewReader(body)), nil
}

func (m *MockClient) Close() error { return nil }
