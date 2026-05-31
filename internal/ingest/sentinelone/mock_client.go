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

	// App Inventory
	AppRecords []AppRecord
	AppErr     error
	AppCalls   int
	LastSince  time.Time
	LastFilter []string

	// Execute
	ExecuteTaskID string
	ExecuteErr    error
	ExecuteCalls  []ExecuteCall

	// Status — either fixed or script-id-keyed
	Statuses      map[string]TaskStatus // keyed by taskID
	DefaultStatus TaskStatus
	StatusErr     error
	StatusCalls   []string

	// Results — keyed by taskID; value is the NDJSON body.
	Results     map[string][]byte
	ResultsErr  error
	ResultCalls []string
}

// ExecuteCall captures arguments passed to ExecuteRemoteScript.
type ExecuteCall struct {
	ScriptID string
	Target   string
}

// NewMockClient returns a zero-valued MockClient with initialized maps.
func NewMockClient() *MockClient {
	return &MockClient{
		Statuses: make(map[string]TaskStatus),
		Results:  make(map[string][]byte),
	}
}

func (m *MockClient) ListInstalledApplications(_ context.Context, since time.Time, filters []string) ([]AppRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.AppCalls++
	m.LastSince = since
	m.LastFilter = append([]string(nil), filters...)
	if m.AppErr != nil {
		return nil, m.AppErr
	}
	out := make([]AppRecord, len(m.AppRecords))
	copy(out, m.AppRecords)
	return out, nil
}

func (m *MockClient) ExecuteRemoteScript(_ context.Context, scriptID, target string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ExecuteCalls = append(m.ExecuteCalls, ExecuteCall{ScriptID: scriptID, Target: target})
	if m.ExecuteErr != nil {
		return "", m.ExecuteErr
	}
	return m.ExecuteTaskID, nil
}

func (m *MockClient) GetRemoteScriptStatus(_ context.Context, taskID string) (TaskStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.StatusCalls = append(m.StatusCalls, taskID)
	if m.StatusErr != nil {
		return TaskStatus{}, m.StatusErr
	}
	if s, ok := m.Statuses[taskID]; ok {
		return s, nil
	}
	if m.DefaultStatus.State == "" {
		return TaskStatus{TaskID: taskID, State: TaskStateRunning}, nil
	}
	s := m.DefaultStatus
	s.TaskID = taskID
	return s, nil
}

func (m *MockClient) GetRemoteScriptResults(_ context.Context, taskID string) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ResultCalls = append(m.ResultCalls, taskID)
	if m.ResultsErr != nil {
		return nil, m.ResultsErr
	}
	body, ok := m.Results[taskID]
	if !ok {
		body = nil
	}
	return io.NopCloser(bytes.NewReader(body)), nil
}

func (m *MockClient) Close() error { return nil }
