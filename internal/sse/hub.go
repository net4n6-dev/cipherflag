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
	"sync"
	"time"
)

// Event is the envelope for all SSE events.
type Event struct {
	Type      string          `json:"type"`
	Data      json.RawMessage `json:"data"`
	Timestamp time.Time       `json:"timestamp"`
}

// Client represents a connected SSE consumer.
type Client struct {
	Events chan Event
}

// Hub manages SSE client connections and fans out events.
type Hub struct {
	clients    map[*Client]struct{}
	mu         sync.RWMutex
	broadcast  chan Event
	register   chan *Client
	unregister chan *Client
}

const clientBufferSize = 64

func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*Client]struct{}),
		broadcast:  make(chan Event, 256),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

func (h *Hub) Register() *Client {
	c := &Client{Events: make(chan Event, clientBufferSize)}
	h.register <- c
	return c
}

func (h *Hub) Unregister(c *Client) {
	h.unregister <- c
}

func (h *Hub) Publish(evt Event) {
	h.broadcast <- evt
}

// Run is the main event loop. Start in a goroutine: go hub.Run()
func (h *Hub) Run() {
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case c := <-h.register:
			h.mu.Lock()
			h.clients[c] = struct{}{}
			h.mu.Unlock()

		case c := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[c]; ok {
				delete(h.clients, c)
				close(c.Events)
			}
			h.mu.Unlock()

		case evt := <-h.broadcast:
			h.mu.RLock()
			for c := range h.clients {
				select {
				case c.Events <- evt:
				default:
					// Slow client — drop event
				}
			}
			h.mu.RUnlock()

		case <-heartbeat.C:
			hb := Event{
				Type:      "heartbeat",
				Timestamp: time.Now(),
			}
			h.mu.RLock()
			for c := range h.clients {
				select {
				case c.Events <- hb:
				default:
				}
			}
			h.mu.RUnlock()
		}
	}
}
