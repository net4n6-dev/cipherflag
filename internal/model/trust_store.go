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

package model

import "time"

// TrustStoreHolding represents a single (host, trusted-CA, source) record
// from host_trust_store. One row per discovered declaration; one host can
// trust the same CA via multiple sources (OS bundle + nginx config).
type TrustStoreHolding struct {
	HostID        string    `json:"host_id"`
	CAFingerprint string    `json:"ca_fingerprint_sha256"`
	Source        string    `json:"source"`
	SourceDetail  string    `json:"source_detail"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
}

// TrustStoreObservation is what the truststore scanner emits per (host,
// bundle, cert) tuple; written to host_trust_store by the store layer.
type TrustStoreObservation struct {
	HostID        string
	CAFingerprint string
	Source        string // os_bundle | app_config | jvm_cacerts | lang_runtime
	SourceDetail  string
}

// PrivateKeyHolding is one row from cert_private_key_holding. Records that
// HostID holds the private key for CertFingerprint, with the discovery
// evidence type recorded so the resolver can apply the
// protected_path-excluded scoring policy.
type PrivateKeyHolding struct {
	HostID          string    `json:"host_id"`
	CertFingerprint string    `json:"cert_fingerprint"`
	Evidence        string    `json:"evidence"`
	Source          string    `json:"source"`
	SourceDetail    string    `json:"source_detail"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
}

// PrivateKeyObservation is what the scanner emits; written to
// cert_private_key_holding by the store layer.
type PrivateKeyObservation struct {
	HostID          string
	CertFingerprint string
	Evidence        string // colocated_pem | pkcs12_entry | jks_private_key_entry | protected_path
	Source          string
	SourceDetail    string
}

// PKITrustedByDetail mirrors PKIEdgeDetail (from L4-C). Populated by the
// store layer when GetHostDependencies or the subgraph endpoint LEFT JOINs
// pki_trusted_by_edge_details onto a host_dependency_edges row of kind
// pki_trusted_by.
type PKITrustedByDetail struct {
	CAFingerprint      string `json:"ca_fingerprint_sha256"`
	CASubjectCN        string `json:"ca_subject_cn"`
	IsSelfSigned       bool   `json:"is_self_signed"`
	IsOperatorDeclared bool   `json:"is_operator_declared"`
	HolderEvidence     string `json:"holder_evidence,omitempty"`
}
