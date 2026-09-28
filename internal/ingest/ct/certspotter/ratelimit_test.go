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
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRateLimiter_FirstCallSucceedsImmediately(t *testing.T) {
	rl := NewRateLimiter(60) // 60/hr
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := rl.Wait(ctx); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Millisecond {
		t.Errorf("first Wait took %v, expected <10ms", elapsed)
	}
}

func TestRateLimiter_BlocksWhenExhausted(t *testing.T) {
	// 3600/hr = 1/sec. Drain 1 token, second Wait should block ~1s.
	rl := NewRateLimiter(3600)
	rl.Wait(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := rl.Wait(ctx)
	if err == nil {
		t.Fatal("second Wait should have hit context deadline")
	}
	// Accept either form: golang.org/x/time/rate v0.14.0 returns
	// fmt.Errorf("rate: Wait(n=%d) would exceed context deadline", n)
	// WITHOUT %w wrapping, so errors.Is(err, context.DeadlineExceeded)
	// returns false against that path. The errors.Is arm is kept for
	// future library versions that DO wrap the deadline error.
	if !errors.Is(err, context.DeadlineExceeded) && !strings.HasPrefix(err.Error(), "rate: Wait") {
		t.Errorf("err = %v, want DeadlineExceeded or rate deadline error", err)
	}
}

func TestRateLimiter_RespectsContextCancellation(t *testing.T) {
	rl := NewRateLimiter(1)
	rl.Wait(context.Background()) // drain the one token
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := rl.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want Canceled", err)
	}
}
