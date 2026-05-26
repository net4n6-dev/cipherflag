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

package zeek

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/model"
	"github.com/net4n6-dev/cipherflag/internal/store"
)

// DefaultLeaseFallback is the sighting window applied when a DHCP
// record lacks an explicit `lease_time` field. Enterprise DHCP servers
// typically configure 8h–7d leases; 24h is a conservative middle-ground
// that doesn't over-extend attribution for leases whose real duration
// we can't read.
const DefaultLeaseFallback = 24 * time.Hour

// dhcpMacIdentSource is the host_identifiers.source value used by the
// DHCP attribution path. First operational use of the host_identifiers
// table — introduced by v1.5.0 per spec §10.
const dhcpMacIdentSource = "dhcp_mac"

// dhcpHostStore is the narrow interface the DHCP mapper needs. Lives
// here (not in store.CryptoStore) so unit tests can supply a fake
// without implementing the full store surface.
type dhcpHostStore interface {
	FindHostBySourceID(ctx context.Context, source, sourceHostID string) (*model.Host, error)
	UpsertHost(ctx context.Context, host *model.Host) error
	UpsertHostIdentifier(ctx context.Context, ident *model.HostIdentifier) error
	UpsertHostIPSighting(ctx context.Context, sighting *store.HostIPSighting) error
}

// IngestDHCPRecord materialises a DHCP lease observation as a sighting.
// Flow:
//
//  1. Skip the record if we can't build a usable (ip, mac) identity
//     — MAC missing or assigned_addr missing means nothing to attribute.
//  2. Look up the host by (source='dhcp_mac', source_host_id=mac). Hit
//     → use existing host_id. Miss → create a new host (auto-create
//     per user decision #2) with canonical_hostname = ClientFQDN ∥
//     HostName ∥ '', os_family='', host_type='unknown',
//     ip_addresses=[assigned_addr], discovery_sources=['zeek_dhcp'],
//     then UpsertHostIdentifier so the next lease on the same MAC
//     resolves.
//  3. Upsert host_ip_sightings with source='dhcp', confidence='attested',
//     window=[ts, ts + leaseTime]. Attribution JSONB carries mac,
//     host_name, client_fqdn, domain, lease_time_sec, requested_addr,
//     msg_types per spec §5 attribution shape.
//
// Errors: returns nil for skip-worthy records (missing mac/ip) so the
// caller can log-and-continue. Returns the underlying error only for
// unexpected DB failures that should surface.
func IngestDHCPRecord(ctx context.Context, st dhcpHostStore, rec *DHCPRecord) error {
	if rec == nil {
		return errors.New("nil DHCPRecord")
	}
	if rec.MAC == "" || rec.AssignedAddr == "" {
		// Nothing to attribute — DHCP option 53 message exchanges
		// without a fully-formed lease (NAK, INFORM-only) land here.
		return nil
	}

	host, err := st.FindHostBySourceID(ctx, dhcpMacIdentSource, rec.MAC)
	if err != nil {
		return fmt.Errorf("find host by dhcp_mac=%s: %w", rec.MAC, err)
	}
	if host == nil {
		// Auto-create (user decision #2). The host gets a minimal
		// record; richer fields (os_family, host_type) are the job of
		// endpoint pollers that know more than DHCP can tell us.
		canonical := rec.ClientFQDN
		if canonical == "" {
			canonical = rec.HostName
		}
		host = &model.Host{
			CanonicalHostname: canonical,
			IPAddresses:       []string{rec.AssignedAddr},
			DiscoverySources:  []string{"zeek_dhcp"},
		}
		if err := st.UpsertHost(ctx, host); err != nil {
			return fmt.Errorf("upsert host for dhcp mac=%s: %w", rec.MAC, err)
		}
		if err := st.UpsertHostIdentifier(ctx, &model.HostIdentifier{
			HostID:       host.ID,
			Source:       dhcpMacIdentSource,
			SourceHostID: rec.MAC,
		}); err != nil {
			return fmt.Errorf("upsert dhcp_mac identifier for %s: %w", rec.MAC, err)
		}
	}

	leaseWindow := rec.LeaseTime
	if leaseWindow <= 0 {
		leaseWindow = DefaultLeaseFallback
	}

	sighting := &store.HostIPSighting{
		HostID:     host.ID,
		IP:         rec.AssignedAddr,
		FirstSeen:  rec.Timestamp,
		LastSeen:   rec.Timestamp.Add(leaseWindow),
		Source:     "dhcp",
		Confidence: "attested",
		Attribution: map[string]any{
			"mac":            rec.MAC,
			"host_name":      rec.HostName,
			"client_fqdn":    rec.ClientFQDN,
			"domain":         rec.Domain,
			"lease_time_sec": int(leaseWindow / time.Second),
			"requested_addr": rec.RequestedAddr,
			"msg_types":      rec.MsgTypes,
		},
	}
	if err := st.UpsertHostIPSighting(ctx, sighting); err != nil {
		return fmt.Errorf("upsert dhcp sighting for %s: %w", rec.AssignedAddr, err)
	}
	return nil
}
