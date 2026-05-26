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

// Package syslog implements the Layer 5.3 Syslog/CEF sink.
// Supports UDP, TCP, and TLS transports with persistent connections and
// auto-reconnect. Two wire formats: RFC 5424 (structured syslog) and CEF
// (ArcSight Common Event Format).
package syslog

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom/sinks/types"
	"github.com/rs/zerolog/log"
)

// Sink emits one line per event over UDP/TCP/TLS to a syslog receiver.
type Sink struct {
	cfg       config.SyslogSinkConfig
	common    config.SinkConfig
	scopeName string
	formatter lineFormatter

	mu   sync.Mutex
	conn net.Conn
}

// lineFormatter produces one wire-format line per event.
type lineFormatter interface {
	Format(event types.SinkEvent, facility int) ([]byte, error)
}

// New constructs a SyslogSink; does not dial until the first Send.
func New(cfg config.SyslogSinkConfig, common config.SinkConfig, scopeName string) (*Sink, error) {
	var formatter lineFormatter
	switch cfg.Format {
	case "rfc5424":
		formatter = &rfc5424Formatter{}
	case "cef":
		formatter = &cefFormatter{}
	default:
		return nil, configError("format must be rfc5424 or cef")
	}
	return &Sink{cfg: cfg, common: common, scopeName: scopeName, formatter: formatter}, nil
}

// Send formats each event and writes it over the transport.
// Event payloads are always expected — CBOM payload returns an error.
// For CEF granularity=asset, expands to one line per finding inside the asset.
func (s *Sink) Send(ctx context.Context, payload *types.SinkPayload) error {
	if payload == nil || payload.Events == nil {
		return configError("events payload required")
	}
	if len(payload.Events) == 0 {
		return nil
	}

	for i := range payload.Events {
		line, err := s.formatter.Format(payload.Events[i], s.facility())
		if err != nil {
			return fmt.Errorf("cbom syslogsink: format: %w", err)
		}
		if line == nil {
			continue // formatter may skip no-finding asset events for CEF
		}
		if err := s.writeLine(ctx, line); err != nil {
			return err
		}
	}
	return nil
}

func (s *Sink) facility() int {
	if s.cfg.Facility > 0 {
		return s.cfg.Facility
	}
	return 16 // local0
}

// writeLine writes a formatted line, reconnecting once on failure.
// UDP messages exceeding the MTU ceiling are truncated with a warn log.
func (s *Sink) writeLine(ctx context.Context, line []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn == nil {
		if err := s.dial(ctx); err != nil {
			return &types.RetryableError{Err: err}
		}
	}

	if s.cfg.Protocol == "udp" && len(line) > 1472 {
		log.Warn().Int("size", len(line)).Str("scope", s.scopeName).Msg("cbom: syslog UDP line truncated to 1472 bytes")
		line = line[:1472]
	}

	if _, err := s.conn.Write(line); err != nil {
		_ = s.conn.Close()
		s.conn = nil
		if dialErr := s.dial(ctx); dialErr != nil {
			return &types.RetryableError{Err: fmt.Errorf("reconnect: %w", dialErr)}
		}
		if _, err := s.conn.Write(line); err != nil {
			return &types.RetryableError{Err: err}
		}
	}
	return nil
}

// dial opens the appropriate net.Conn (UDP datagram, TCP stream, or TLS).
func (s *Sink) dial(ctx context.Context) error {
	d := net.Dialer{Timeout: s.common.Timeout}
	switch s.cfg.Protocol {
	case "udp":
		conn, err := d.DialContext(ctx, "udp", s.cfg.Address)
		if err != nil {
			return err
		}
		s.conn = conn
	case "tcp":
		conn, err := d.DialContext(ctx, "tcp", s.cfg.Address)
		if err != nil {
			return err
		}
		s.conn = conn
	case "tls":
		cert, err := tls.LoadX509KeyPair(s.cfg.CertFile, s.cfg.KeyFile)
		if err != nil {
			return fmt.Errorf("load cert: %w", err)
		}
		serverName, _, _ := net.SplitHostPort(s.cfg.Address)
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			ServerName:   serverName,
		}
		if s.cfg.CAFile != "" {
			caBytes, err := os.ReadFile(s.cfg.CAFile)
			if err != nil {
				return fmt.Errorf("read ca_file %s: %w", s.cfg.CAFile, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caBytes) {
				return fmt.Errorf("ca_file %s: no valid PEM certificates", s.cfg.CAFile)
			}
			tlsCfg.RootCAs = pool
		}
		tcpConn, err := d.DialContext(ctx, "tcp", s.cfg.Address)
		if err != nil {
			return err
		}
		tlsConn := tls.Client(tcpConn, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			_ = tcpConn.Close()
			return fmt.Errorf("tls handshake: %w", err)
		}
		s.conn = tlsConn
	}
	return nil
}

// Close releases the underlying connection. Call on shutdown.
func (s *Sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}

// configError is a sentinel-style non-retryable error.
func configError(msg string) error {
	return fmt.Errorf("cbom syslogsink: %s", msg)
}
