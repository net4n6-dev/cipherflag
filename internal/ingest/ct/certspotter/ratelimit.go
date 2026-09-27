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

package certspotter

import (
	"context"

	"golang.org/x/time/rate"
)

// RateLimiter caps outgoing HTTP calls to a per-hour quota. Wraps
// golang.org/x/time/rate.Limiter — the wrapper makes the per-hour
// semantics explicit in the constructor signature and lets us evolve
// the policy (e.g. burst behavior) without touching call sites.
type RateLimiter struct {
	lim *rate.Limiter
}

// NewRateLimiter constructs a limiter sized for `requestsPerHour`
// tokens, refilled smoothly across the hour. Burst is set to 1 — we
// want strict per-request gating, not burst-then-starve.
func NewRateLimiter(requestsPerHour int) *RateLimiter {
	perSecond := float64(requestsPerHour) / 3600.0
	return &RateLimiter{lim: rate.NewLimiter(rate.Limit(perSecond), 1)}
}

// Wait blocks until a token is available or ctx is done.
func (r *RateLimiter) Wait(ctx context.Context) error {
	return r.lim.Wait(ctx)
}
