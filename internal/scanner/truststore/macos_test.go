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

package truststore

import (
	"context"
	"errors"
	"testing"
)

// fakeRunner stubs CommandRunner.Run.
type fakeRunner struct {
	responses map[string][]byte
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, []byte, error) {
	key := name
	for _, a := range args {
		key += " " + a
	}
	if out, ok := f.responses[key]; ok {
		return out, nil, nil
	}
	return nil, nil, errors.New("no fake response")
}

func TestDiscoverMacOSKeychains_RunsSecurityCommand(t *testing.T) {
	pem := []byte("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")
	runner := &fakeRunner{responses: map[string][]byte{
		"security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain": pem,
		"security find-certificate -a -p /Library/Keychains/System.keychain":                        pem,
	}}
	s := &Scanner{runner: runner}
	got, _ := discoverMacOSKeychains(context.Background(), s)
	if len(got) != 2 {
		t.Errorf("got %d bundles, want 2", len(got))
	}
	for _, b := range got {
		if b.Source != "os_bundle" || b.Format != "pem" {
			t.Errorf("got %+v, want source=os_bundle format=pem", b)
		}
	}
}

func TestDiscoverMacOSKeychains_NilRunnerReturnsNil(t *testing.T) {
	s := &Scanner{runner: nil}
	if got, _ := discoverMacOSKeychains(context.Background(), s); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}
