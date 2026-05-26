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

// Package configs scans hosts for cryptographic configuration files.
package configs

import "time"

// ConfigFinding represents settings extracted from a crypto config file.
type ConfigFinding struct {
	// ConfigType identifies the config format.
	ConfigType string // openssl_cnf, sshd_config, java_security, nginx_ssl, apache_ssl

	// FilePath is the absolute path to the config file.
	FilePath string

	// Settings contains extracted key-value pairs.
	Settings map[string]string

	// --- Scanner metadata (not mapped to discovery types) ---

	// RawContent is the full file content for future analysis.
	RawContent string

	// ModifiedAt is the file modification time.
	ModifiedAt time.Time

	// FileMode is the file permission bits.
	FileMode uint32
}
