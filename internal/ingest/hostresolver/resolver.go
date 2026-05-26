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

package hostresolver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// Resolver resolves discovery results to canonical host identities.
type Resolver struct {
	store store.CryptoStore
}

// NewResolver creates a new host identity Resolver.
func NewResolver(st store.CryptoStore) *Resolver {
	return &Resolver{store: st}
}

// ResolveHost finds or creates a host using the resolution order:
// 1. Source host ID match
// 2. IP match
// 3. Hostname match
// 4. Create new
func (r *Resolver) ResolveHost(ctx context.Context, sourceHostID, hostname string, ips []string, source, osFamily string) (*model.Host, error) {
	now := time.Now()
	normalizedHostname := normalizeHostname(hostname)

	// 1. Source host ID match
	if sourceHostID != "" {
		host, err := r.store.FindHostBySourceID(ctx, source, sourceHostID)
		if err != nil {
			return nil, fmt.Errorf("find host by source id: %w", err)
		}
		if host != nil {
			mergeHostFields(host, normalizedHostname, ips, source, osFamily, now)
			if err := r.store.UpsertHost(ctx, host); err != nil {
				return nil, fmt.Errorf("update host after source id match: %w", err)
			}
			return host, nil
		}
	}

	// 2. IP match
	for _, ip := range ips {
		host, err := r.store.FindHostByIP(ctx, ip)
		if err != nil {
			return nil, fmt.Errorf("find host by ip: %w", err)
		}
		if host != nil {
			mergeHostFields(host, normalizedHostname, ips, source, osFamily, now)
			if err := r.store.UpsertHost(ctx, host); err != nil {
				return nil, fmt.Errorf("update host after ip match: %w", err)
			}
			if sourceHostID != "" {
				r.store.UpsertHostIdentifier(ctx, &model.HostIdentifier{
					HostID: host.ID, Source: source, SourceHostID: sourceHostID,
				})
			}
			return host, nil
		}
	}

	// 3. Hostname match
	if normalizedHostname != "" {
		host, err := r.store.FindHostByHostname(ctx, normalizedHostname)
		if err != nil {
			return nil, fmt.Errorf("find host by hostname: %w", err)
		}
		if host != nil {
			mergeHostFields(host, normalizedHostname, ips, source, osFamily, now)
			if err := r.store.UpsertHost(ctx, host); err != nil {
				return nil, fmt.Errorf("update host after hostname match: %w", err)
			}
			if sourceHostID != "" {
				r.store.UpsertHostIdentifier(ctx, &model.HostIdentifier{
					HostID: host.ID, Source: source, SourceHostID: sourceHostID,
				})
			}
			return host, nil
		}
	}

	// 4. Create new host
	host := &model.Host{
		CanonicalHostname: normalizedHostname,
		Aliases:           []string{},
		IPAddresses:       ips,
		OSFamily:          osFamily,
		DiscoverySources:  []string{source},
		FirstSeen:         now,
		LastSeen:          now,
	}

	if err := r.store.UpsertHost(ctx, host); err != nil {
		return nil, fmt.Errorf("create new host: %w", err)
	}

	if sourceHostID != "" {
		r.store.UpsertHostIdentifier(ctx, &model.HostIdentifier{
			HostID: host.ID, Source: source, SourceHostID: sourceHostID,
		})
	}

	return host, nil
}

func normalizeHostname(hostname string) string {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	hostname = strings.TrimSuffix(hostname, ".")
	return hostname
}

func mergeHostFields(host *model.Host, hostname string, ips []string, source, osFamily string, now time.Time) {
	// Set OSFamily if not already known.
	if host.OSFamily == "" && osFamily != "" {
		host.OSFamily = osFamily
	}
	// Merge IPs
	ipSet := map[string]bool{}
	for _, ip := range host.IPAddresses {
		ipSet[ip] = true
	}
	for _, ip := range ips {
		if !ipSet[ip] {
			host.IPAddresses = append(host.IPAddresses, ip)
		}
	}

	// Merge discovery sources
	srcSet := map[string]bool{}
	for _, s := range host.DiscoverySources {
		srcSet[s] = true
	}
	if !srcSet[source] {
		host.DiscoverySources = append(host.DiscoverySources, source)
	}

	// Merge hostname into aliases if different from canonical
	if hostname != "" && hostname != host.CanonicalHostname {
		aliasSet := map[string]bool{}
		for _, a := range host.Aliases {
			aliasSet[a] = true
		}
		if !aliasSet[hostname] {
			host.Aliases = append(host.Aliases, hostname)
		}
	}

	// Update last_seen
	if now.After(host.LastSeen) {
		host.LastSeen = now
	}
}
