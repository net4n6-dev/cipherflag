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

import "encoding/json"

// SSHRecord represents a parsed Zeek ssh.log entry.
type SSHRecord struct {
	Timestamp    float64
	UID          string
	ClientIP     string
	ClientPort   int
	ServerIP     string
	ServerPort   int
	Version      int
	AuthSuccess  bool
	AuthAttempts int
	Direction    string
	Cipher       string
	MAC          string
	KexAlg       string
	HostKeyAlg   string
	HostKey      string
	HASSH        string
	HASSHServer  string
}

// rawSSH maps Zeek's dotted JSON key names for ssh.log entries.
type rawSSH struct {
	Ts           float64 `json:"ts"`
	UID          string  `json:"uid"`
	OrigH        string  `json:"id.orig_h"`
	OrigP        int     `json:"id.orig_p"`
	RespH        string  `json:"id.resp_h"`
	RespP        int     `json:"id.resp_p"`
	Version      int     `json:"version"`
	AuthSuccess  bool    `json:"auth_success"`
	AuthAttempts int     `json:"auth_attempts"`
	Direction    string  `json:"direction"`
	Cipher       string  `json:"cipher_alg"`
	MAC          string  `json:"mac_alg"`
	KexAlg       string  `json:"kex_alg"`
	HostKeyAlg   string  `json:"host_key_alg"`
	HostKey      string  `json:"host_key"`
	HASSH        string  `json:"hassh"`
	HASSHServer  string  `json:"hasshServer"`
}

// ParseSSHRecord parses a Zeek ssh.log JSON line into an SSHRecord.
func ParseSSHRecord(data []byte) (*SSHRecord, error) {
	var raw rawSSH
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	return &SSHRecord{
		Timestamp:    raw.Ts,
		UID:          raw.UID,
		ClientIP:     raw.OrigH,
		ClientPort:   raw.OrigP,
		ServerIP:     raw.RespH,
		ServerPort:   raw.RespP,
		Version:      raw.Version,
		AuthSuccess:  raw.AuthSuccess,
		AuthAttempts: raw.AuthAttempts,
		Direction:    raw.Direction,
		Cipher:       raw.Cipher,
		MAC:          raw.MAC,
		KexAlg:       raw.KexAlg,
		HostKeyAlg:   raw.HostKeyAlg,
		HostKey:      raw.HostKey,
		HASSH:        raw.HASSH,
		HASSHServer:  raw.HASSHServer,
	}, nil
}
