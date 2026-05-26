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

package scoring

import (
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/model"
)

func TestCFG001_OpenSSLLegacyProvider(t *testing.T) {
	cfg := &model.CryptoConfig{
		ID:         "c1",
		ConfigType: "openssl",
		Settings:   map[string]string{"provider": "legacy", "activate": "1"},
	}
	r := ScoreConfig(cfg)
	if findFinding(r, "CFG-001") == nil {
		t.Error("CFG-001 did not fire for legacy provider active")
	}
}

func TestCFG001_NoLegacy(t *testing.T) {
	cfg := &model.CryptoConfig{
		ID:         "c1",
		ConfigType: "openssl",
		Settings:   map[string]string{"provider": "default"},
	}
	r := ScoreConfig(cfg)
	if findFinding(r, "CFG-001") != nil {
		t.Error("CFG-001 fired for non-legacy config")
	}
}

func TestCFG002_SSHDPasswordAuth(t *testing.T) {
	cfg := &model.CryptoConfig{
		ID:         "c1",
		ConfigType: "sshd",
		Settings:   map[string]string{"PasswordAuthentication": "yes"},
	}
	r := ScoreConfig(cfg)
	if findFinding(r, "CFG-002") == nil {
		t.Error("CFG-002 did not fire")
	}
}

func TestCFG002_PasswordAuthDisabled(t *testing.T) {
	cfg := &model.CryptoConfig{
		ID:         "c1",
		ConfigType: "sshd",
		Settings:   map[string]string{"PasswordAuthentication": "no"},
	}
	r := ScoreConfig(cfg)
	if findFinding(r, "CFG-002") != nil {
		t.Error("CFG-002 fired when PasswordAuthentication=no")
	}
}

func TestCFG003_SSHDWeakCiphers(t *testing.T) {
	cfg := &model.CryptoConfig{
		ID:         "c1",
		ConfigType: "sshd",
		Settings:   map[string]string{"Ciphers": "aes128-cbc,3des-cbc"},
	}
	r := ScoreConfig(cfg)
	if findFinding(r, "CFG-003") == nil {
		t.Error("CFG-003 did not fire for weak ciphers (3des-cbc is Vulnerable)")
	}
}

func TestCFG003_SSHDStrongCiphers(t *testing.T) {
	cfg := &model.CryptoConfig{
		ID:         "c1",
		ConfigType: "sshd",
		Settings:   map[string]string{"Ciphers": "aes-256-gcm,aes-256-ctr"},
	}
	r := ScoreConfig(cfg)
	if findFinding(r, "CFG-003") != nil {
		t.Error("CFG-003 fired for strong ciphers (aes-256-gcm)")
	}
}

func TestCFG004_JavaDisabledAlgorithmsEmpty(t *testing.T) {
	cfg := &model.CryptoConfig{
		ID:         "c1",
		ConfigType: "java-security",
		Settings:   map[string]string{"jdk.tls.disabledAlgorithms": ""},
	}
	r := ScoreConfig(cfg)
	if findFinding(r, "CFG-004") == nil {
		t.Error("CFG-004 did not fire for empty disabledAlgorithms")
	}
}

func TestCFG004_JavaDisabledAlgorithmsMissing(t *testing.T) {
	cfg := &model.CryptoConfig{
		ID:         "c1",
		ConfigType: "java-security",
		Settings:   map[string]string{},
	}
	r := ScoreConfig(cfg)
	if findFinding(r, "CFG-004") == nil {
		t.Error("CFG-004 did not fire for missing disabledAlgorithms key")
	}
}

func TestCFG004_JavaDisabledAlgorithmsConfigured(t *testing.T) {
	cfg := &model.CryptoConfig{
		ID:         "c1",
		ConfigType: "java-security",
		Settings:   map[string]string{"jdk.tls.disabledAlgorithms": "SSLv3, MD5, RC4"},
	}
	r := ScoreConfig(cfg)
	if findFinding(r, "CFG-004") != nil {
		t.Error("CFG-004 fired for configured disabledAlgorithms")
	}
}
