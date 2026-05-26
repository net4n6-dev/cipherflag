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

package config

import (
	"fmt"
)

// HTTPSinkConfig — HTTP POST destination (5.1 migrated to nested form).
type HTTPSinkConfig struct {
	URL            string `toml:"url"`
	Auth           string `toml:"auth"`             // "none" | "bearer" | "header"
	AuthRef        string `toml:"auth_ref"`         // env var holding secret (bearer/header)
	AuthHeaderName string `toml:"auth_header_name"` // required when Auth="header"
}

func (c *HTTPSinkConfig) Validate(location string) error {
	if c.URL == "" {
		return fmt.Errorf("%s: url is required", location)
	}
	switch c.Auth {
	case "", "none", "bearer", "header":
	default:
		return fmt.Errorf("%s: auth %q must be \"none\", \"bearer\", or \"header\"", location, c.Auth)
	}
	if c.Auth == "header" && c.AuthHeaderName == "" {
		return fmt.Errorf("%s: auth_header_name is required when auth=\"header\"", location)
	}
	return nil
}

// FileSinkConfig — local filesystem destination (5.1 migrated).
type FileSinkConfig struct {
	PathTemplate string `toml:"path_template"` // supports {output_dir}/{scope}/{timestamp}
}

func (c *FileSinkConfig) Validate(location string) error {
	if c.PathTemplate == "" {
		return fmt.Errorf("%s: path_template is required", location)
	}
	return nil
}

// S3SinkConfig — S3-compatible object storage destination.
type S3SinkConfig struct {
	Bucket          string `toml:"bucket"`
	Region          string `toml:"region"`
	Prefix          string `toml:"prefix"`           // supports {scope}/{date}/{timestamp}
	EndpointURL     string `toml:"endpoint_url"`     // MinIO/GCS/LocalStack
	ContentEncoding string `toml:"content_encoding"` // "" | "gzip"
}

func (c *S3SinkConfig) Validate(location string) error {
	if c.Bucket == "" {
		return fmt.Errorf("%s: bucket is required", location)
	}
	if c.Region == "" {
		return fmt.Errorf("%s: region is required", location)
	}
	switch c.ContentEncoding {
	case "", "gzip":
	default:
		return fmt.Errorf("%s: content_encoding %q must be \"\" or \"gzip\"", location, c.ContentEncoding)
	}
	return nil
}

// SplunkSinkConfig — Splunk HTTP Event Collector destination.
type SplunkSinkConfig struct {
	URL         string `toml:"url"`
	TokenRef    string `toml:"token_ref"` // env var holding HEC token
	Index       string `toml:"index"`
	Source      string `toml:"source"`
	Sourcetype  string `toml:"sourcetype"`
	BatchSize   int    `toml:"batch_size"`
	TLSInsecure bool   `toml:"tls_insecure"`
}

func (c *SplunkSinkConfig) Validate(location string) error {
	if c.URL == "" {
		return fmt.Errorf("%s: url is required", location)
	}
	if c.TokenRef == "" {
		return fmt.Errorf("%s: token_ref is required", location)
	}
	if c.BatchSize < 0 {
		return fmt.Errorf("%s: batch_size must be >= 0", location)
	}
	return nil
}

// SyslogSinkConfig — UDP/TCP/TLS syslog destination.
type SyslogSinkConfig struct {
	Protocol string `toml:"protocol"` // "udp" | "tcp" | "tls"
	Address  string `toml:"address"`
	Format   string `toml:"format"`   // "rfc5424" | "cef"
	Facility int    `toml:"facility"` // default 16 (local0)
	CAFile   string `toml:"ca_file"`
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
}

func (c *SyslogSinkConfig) Validate(location string) error {
	switch c.Protocol {
	case "udp", "tcp", "tls":
	default:
		return fmt.Errorf("%s: protocol %q must be \"udp\", \"tcp\", or \"tls\"", location, c.Protocol)
	}
	if c.Address == "" {
		return fmt.Errorf("%s: address is required", location)
	}
	switch c.Format {
	case "rfc5424", "cef":
	default:
		return fmt.Errorf("%s: format %q must be \"rfc5424\" or \"cef\"", location, c.Format)
	}
	if c.Protocol == "tls" {
		if c.CertFile == "" || c.KeyFile == "" {
			return fmt.Errorf("%s: cert_file and key_file are required for protocol=\"tls\"", location)
		}
	}
	if c.Facility < 0 || c.Facility > 23 {
		return fmt.Errorf("%s: facility %d must be 0-23", location, c.Facility)
	}
	return nil
}
