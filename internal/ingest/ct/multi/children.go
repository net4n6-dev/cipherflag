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

package multi

import (
	"fmt"
	"net/http"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/ingest/ct"
	"github.com/net4n6-dev/cipherflag/internal/ingest/ct/certspotter"
	"github.com/net4n6-dev/cipherflag/internal/ingest/ct/crtsh"
	"github.com/net4n6-dev/cipherflag/internal/ingest/ct/static"
)

// buildChildren constructs ct.Provider instances from a parsed group's
// children. Mirrors EE's buildChildren (multi/children.go) — child
// Pollers/Providers only need QueryDomain to be called (never Poll/Run),
// so they're constructed without a Store: no child ever reads or writes
// a persisted ingestion_state cursor (that happens only in each
// standalone poller's pollDomain).
//
// The static child is the one stateful exception, in memory only: with
// Cfg.Cache nil it bootstraps to the log's current head on its first
// call and thereafter walks forward from its own LastSeenTreeSize (see
// static.Provider.QueryDomain). That relies on the Poller caching the
// Composer — and so these child instances — per group for the process
// lifetime; rebuilding children every cycle would re-bootstrap and the
// static child would never see a new leaf.
func buildChildren(group config.CtMultiGroupConfig, httpClient *http.Client) ([]ct.Provider, error) {
	out := make([]ct.Provider, 0, len(group.Children))
	for i, child := range group.Children {
		var p ct.Provider
		switch {
		case child.Crtsh != nil:
			p = &crtsh.Poller{} // QueryDomain builds its own client internally when p.client is nil
		case child.Static != nil:
			p = &static.Provider{
				Cfg: static.Config{
					Domain:       group.Domain,
					LogURL:       child.Static.LogURL,
					Origin:       child.Static.Origin,
					PublicKeyPEM: child.Static.PublicKeyPEM,
				},
				HTTPClient: httpClient,
			}
		case child.Certspotter != nil:
			requestsPerHour := child.Certspotter.RequestsPerHour
			if requestsPerHour == 0 {
				requestsPerHour = certspotter.DefaultRequestsPerHour
			}
			// certspotter.Poller's fields are unexported, so a bare
			// &certspotter.Poller{} from this package can never carry a
			// per-child APIToken/RequestsPerHour — it would silently fall
			// back to certspotterClient's hardcoded defaults (empty token,
			// DefaultRequestsPerHour) every time, discarding whatever the
			// operator configured for this multi-group child. Use the
			// exported NewPoller constructor with a properly configured
			// *certspotter.Client instead. ingester/store are nil: buildChildren
			// only ever calls QueryDomain on the result (never Poll/pollDomain),
			// and Task 4's QueryDomain never touches p.ingester or p.store.
			p = certspotter.NewPoller(&certspotter.Client{
				BaseURL:  "https://api.certspotter.com",
				HTTP:     httpClient,
				APIToken: child.Certspotter.APIToken,
				Limiter:  certspotter.NewRateLimiter(requestsPerHour),
			}, nil, nil, config.CtCertspotterSourceConfig{})
		default:
			return nil, fmt.Errorf("multi: group %q children[%d]: no sub-config (validation should have caught)", group.Domain, i)
		}
		out = append(out, p)
	}
	return out, nil
}
