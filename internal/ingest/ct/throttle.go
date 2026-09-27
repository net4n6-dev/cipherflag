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
package ct

import (
	"sync"
	"time"
)

// globalDomainQueryGap is enforced across the whole CipherFlag instance
// — crt.sh is public-goods infrastructure and we don't want concurrent
// CT polls from the same instance to hammer it. 2s matches the spec
// §4.4. The 1s per-PEM gap is enforced per-Poll inside the client.
const globalDomainQueryGap = 2 * time.Second

var (
	domainGateMu sync.Mutex
	lastDomainAt time.Time
)

// WaitForDomainGate blocks until at least globalDomainQueryGap has
// elapsed since the last domain query begun by any goroutine in this
// process. Updates the timestamp on entry so callers serialize.
// Exported so subpackages (crtsh/, static/, etc.) can call the single
// shared gate without duplicating state.
func WaitForDomainGate() {
	domainGateMu.Lock()
	defer domainGateMu.Unlock()
	now := time.Now()
	wait := globalDomainQueryGap - now.Sub(lastDomainAt)
	if wait > 0 {
		time.Sleep(wait)
		now = time.Now()
	}
	lastDomainAt = now
}
