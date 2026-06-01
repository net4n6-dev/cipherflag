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
	"fmt"
	"net/http"

	"github.com/rs/zerolog/log"
)

// NewHandler returns an HTTP handler that streams SSE events from the hub.
func NewHandler(hub *Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			log.Error().Str("path", r.URL.Path).Msg("sse: hub is nil")
			http.Error(w, "sse hub unavailable", http.StatusInternalServerError)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			log.Error().
				Str("path", r.URL.Path).
				Str("writer_type", fmt.Sprintf("%T", w)).
				Msg("sse: response writer does not implement Flusher")
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		flusher.Flush()

		client := hub.Register()
		defer hub.Unregister(client)

		ctx := r.Context()
		for {
			select {
			case evt, ok := <-client.Events:
				if !ok {
					return
				}
				data, err := json.Marshal(evt.Data)
				if err != nil || evt.Data == nil {
					data = []byte("{}")
				}
				fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt.Type, string(data))
				flusher.Flush()
			case <-ctx.Done():
				return
			}
		}
	}
}
