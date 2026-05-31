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
package netwrix

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

// CipherFlagNamespace is the UUIDv5 namespace used to derive deterministic
// event IDs. This is a fixed CipherFlag-internal constant — do not change
// without a migration plan, since changing it would cause re-ingest to
// produce duplicate rows for the same logical event.
var CipherFlagNamespace = uuid.MustParse("6b3c1c3d-5b9e-4f2a-9c8b-1f3e5a7c9d2b")

// MapActivityRecord converts a Netwrix Activity Record into an ADCSEvent.
// Returns an error if the record is missing required fields (SerialNumber,
// Issuer, CA name) or has an unrecognized Action.
//
// The mapper uses tolerant field extraction — optional fields default to
// the empty string when missing. Required fields produce an error.
func MapActivityRecord(record ActivityRecord) (*model.ADCSEvent, error) {
	eventType, err := classifyAction(record)
	if err != nil {
		return nil, err
	}

	caName := stringField(record.Raw, "Where")
	if caName == "" {
		return nil, fmt.Errorf("activity record missing CA name (Where)")
	}

	details := mapField(record.Raw, "Details")
	serial := stringField(details, "SerialNumber")
	if serial == "" {
		return nil, fmt.Errorf("activity record missing SerialNumber in Details")
	}
	issuer := stringField(details, "Issuer")
	if issuer == "" {
		return nil, fmt.Errorf("activity record missing Issuer in Details")
	}

	template := stringField(details, "Template")
	requestedBy := stringField(record.Raw, "Who")
	subject := stringField(record.Raw, "What")

	eventTime := record.EventTime
	if eventTime.IsZero() {
		if ts := stringField(record.Raw, "EventTime"); ts != "" {
			eventTime = parseRFC3339(ts)
		}
	}

	id := deterministicID(eventType, caName, serial, issuer, eventTime)

	return &model.ADCSEvent{
		ID:             id,
		EventType:      eventType,
		EventTimestamp: eventTime,
		CAName:         caName,
		TemplateName:   template,
		RequestedBy:    requestedBy,
		SerialNumber:   serial,
		IssuerDN:       issuer,
		SubjectDN:      subject,
		Source:         "netwrix",
		RawEvent:       record.Raw,
	}, nil
}

// classifyAction maps Netwrix's Action + ObjectType to a CipherFlag event type.
func classifyAction(record ActivityRecord) (string, error) {
	action := strings.ToLower(stringField(record.Raw, "Action"))
	switch action {
	case "added":
		return model.ADCSEventTypeIssued, nil
	case "renewed":
		return model.ADCSEventTypeRenewed, nil
	case "revoked", "removed":
		return model.ADCSEventTypeRevoked, nil
	default:
		return "", fmt.Errorf("unrecognized Netwrix Action %q", action)
	}
}

// deterministicID generates a UUIDv5 from the CipherFlag namespace + the
// event's identity fields. Re-ingest of the same logical event produces
// the same ID, enabling INSERT ... ON CONFLICT (id) DO NOTHING idempotency.
func deterministicID(eventType, caName, serial, issuer string, eventTime time.Time) string {
	key := strings.Join([]string{
		eventType,
		caName,
		serial,
		issuer,
		eventTime.UTC().Format(time.RFC3339Nano),
	}, "|")
	return uuid.NewSHA1(CipherFlagNamespace, []byte(key)).String()
}

// --- Helpers for tolerant field extraction ---

func stringField(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func mapField(m map[string]interface{}, key string) map[string]interface{} {
	if m == nil {
		return nil
	}
	if v, ok := m[key].(map[string]interface{}); ok {
		return v
	}
	return nil
}

func parseRFC3339(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
