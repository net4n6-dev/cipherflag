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

package sse

import (
	"encoding/json"
	"testing"
	"time"
)

func TestHub_PublishToRegisteredClient(t *testing.T) {
	h := NewHub()
	go h.Run()

	c := h.Register()
	defer h.Unregister(c)

	evt := Event{
		Type:      "asset.discovered",
		Data:      json.RawMessage(`{"asset_type":"certificate"}`),
		Timestamp: time.Now(),
	}
	h.Publish(evt)

	select {
	case got := <-c.Events:
		if got.Type != "asset.discovered" {
			t.Errorf("expected type asset.discovered, got %s", got.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for event")
	}
}

func TestHub_UnregisteredClientDoesNotReceive(t *testing.T) {
	h := NewHub()
	go h.Run()

	c := h.Register()
	h.Unregister(c)

	// Give hub time to process unregister
	time.Sleep(50 * time.Millisecond)

	evt := Event{
		Type:      "test",
		Data:      json.RawMessage(`{}`),
		Timestamp: time.Now(),
	}
	h.Publish(evt)

	select {
	case evt, ok := <-c.Events:
		if ok {
			t.Fatalf("unregistered client should not receive events, got %+v", evt)
		}
		// Channel was closed cleanly — expected
	case <-time.After(100 * time.Millisecond):
		// expected — no event received
	}
}

func TestHub_SlowClientDropsEvents(t *testing.T) {
	h := NewHub()
	go h.Run()

	c := h.Register()
	defer h.Unregister(c)

	// Fill the buffer (capacity 64)
	for i := 0; i < 100; i++ {
		h.Publish(Event{
			Type:      "flood",
			Data:      json.RawMessage(`{}`),
			Timestamp: time.Now(),
		})
	}

	// Give the hub goroutine time to process
	time.Sleep(100 * time.Millisecond)

	// Drain what we can — should be <= 64
	count := 0
	for {
		select {
		case <-c.Events:
			count++
		default:
			goto done
		}
	}
done:
	if count > 64 {
		t.Errorf("expected at most 64 buffered events, got %d", count)
	}
}
