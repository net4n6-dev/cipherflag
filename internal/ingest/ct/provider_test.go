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
	"context"
	"testing"
	"time"
)

type fakeProvider struct {
	name    string
	entries []CTEntry
}

func (f *fakeProvider) Name() string { return f.name }
func (f *fakeProvider) QueryDomain(ctx context.Context, domain string) ([]CTEntry, error) {
	return f.entries, nil
}

func TestProviderContract(t *testing.T) {
	var p Provider = &fakeProvider{
		name: "fake",
		entries: []CTEntry{{
			Fingerprint: "abc123",
			PEM:         []byte("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"),
			CommonName:  "example.com",
			NameValue:   "example.com\nwww.example.com",
			IssuerName:  "Test CA",
			NotBefore:   time.Now().Add(-24 * time.Hour),
			NotAfter:    time.Now().Add(24 * time.Hour),
			Source:      "fake",
		}},
	}
	entries, err := p.QueryDomain(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("QueryDomain: %v", err)
	}
	if len(entries) != 1 || entries[0].Fingerprint != "abc123" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
	if p.Name() != "fake" {
		t.Fatalf("Name() = %q, want fake", p.Name())
	}
}
