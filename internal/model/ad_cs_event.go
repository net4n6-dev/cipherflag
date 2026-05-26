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

// ADCSEvent represents a single AD CS change event ingested from Netwrix.
// Events live in their own table (ad_cs_events) — they intentionally do NOT
// populate the certificates table because Netwrix lacks the cryptographic
// detail required for the cert inventory. Correlation with the certificates
// table is done post hoc via (SerialNumber, IssuerDN) when both exist.
type ADCSEvent struct {
	ID             string                 `json:"id"`
	EventType      string                 `json:"event_type"`
	EventTimestamp time.Time              `json:"event_timestamp"`
	IngestedAt     time.Time              `json:"ingested_at"`

	CAName       string `json:"ca_name"`
	TemplateName string `json:"template_name,omitempty"`
	RequestedBy  string `json:"requested_by,omitempty"`

	SerialNumber string `json:"serial_number"`
	IssuerDN     string `json:"issuer_dn"`
	SubjectDN    string `json:"subject_dn,omitempty"`

	Source   string                 `json:"source"`
	RawEvent map[string]interface{} `json:"raw_event,omitempty"`
}

// ADCSEvent type values.
const (
	ADCSEventTypeIssued  = "issued"
	ADCSEventTypeRenewed = "renewed"
	ADCSEventTypeRevoked = "revoked"
)
