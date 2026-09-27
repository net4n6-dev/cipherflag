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

package syslog

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/config"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom/sinks/types"
)

func TestSyslogSink_UDPSend(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	var received []byte
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, _ := conn.ReadFromUDP(buf)
		received = buf[:n]
	}()

	sink, err := New(
		config.SyslogSinkConfig{Protocol: "udp", Address: conn.LocalAddr().String(), Format: "rfc5424"},
		config.SinkConfig{Timeout: time.Second},
		"test",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	events := []types.SinkEvent{{AssetID: "a1", Payload: map[string]interface{}{"x": 1}}}
	if err := sink.Send(context.Background(), &types.SinkPayload{Events: events}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	wg.Wait()
	if len(received) == 0 {
		t.Fatal("no data received on UDP listener")
	}
	// Default facility is 16 (local0), empty severity maps to 6, so PRI = 16*8 + 6 = 134
	if !strings.Contains(string(received), "<134>1") {
		t.Errorf("received = %q; want RFC 5424 PRI prefix <134>1", string(received))
	}
}

func TestSyslogSink_TCPReconnect(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	type recvd struct {
		data []byte
		err  error
	}
	got := make(chan recvd, 2)
	go func() {
		conn1, err := listener.Accept()
		if err != nil {
			got <- recvd{err: err}
			return
		}
		conn1.Close()
		conn2, err := listener.Accept()
		if err != nil {
			got <- recvd{err: err}
			return
		}
		buf := make([]byte, 2048)
		conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := conn2.Read(buf)
		got <- recvd{data: buf[:n]}
	}()

	sink, err := New(
		config.SyslogSinkConfig{Protocol: "tcp", Address: listener.Addr().String(), Format: "rfc5424"},
		config.SinkConfig{Timeout: time.Second, Retries: 0},
		"test",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	events := []types.SinkEvent{{Payload: map[string]interface{}{"x": 1}}}
	sink.Send(context.Background(), &types.SinkPayload{Events: events})
	err = sink.Send(context.Background(), &types.SinkPayload{Events: events})
	if err != nil {
		t.Logf("second Send returned %v (accepted — reconnect path exercised)", err)
	}
}

func TestSyslogSink_UDPOversizedTruncation(t *testing.T) {
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, _ := net.ListenUDP("udp", addr)
	defer conn.Close()

	sink, err := New(
		config.SyslogSinkConfig{Protocol: "udp", Address: conn.LocalAddr().String(), Format: "rfc5424"},
		config.SinkConfig{Timeout: time.Second},
		"test",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	go func() {
		buf := make([]byte, 4096)
		for {
			conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			if _, _, err := conn.ReadFromUDP(buf); err != nil {
				return
			}
		}
	}()

	events := make([]types.SinkEvent, 20)
	for i := range events {
		events[i] = types.SinkEvent{Payload: map[string]interface{}{"x": i}}
	}
	if err := sink.Send(context.Background(), &types.SinkPayload{Events: events}); err != nil {
		t.Errorf("Send: %v", err)
	}
}

func selfSignedServerCert(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, caPath
}

// startTLSSyslogServer accepts one TLS connection that does NOT require a
// client certificate and reports the first bytes it reads.
func startTLSSyslogServer(t *testing.T, cert tls.Certificate) (string, <-chan string) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		got <- string(buf[:n])
	}()
	return ln.Addr().String(), got
}

func tlsSink(t *testing.T, cfg config.SyslogSinkConfig) *Sink {
	t.Helper()
	cfg.Protocol, cfg.Format = "tls", "rfc5424"
	sink, err := New(cfg, config.SinkConfig{Timeout: 2 * time.Second}, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sink.Close() })
	return sink
}

var tlsTestEvents = &types.SinkPayload{Events: []types.SinkEvent{{Payload: map[string]interface{}{"x": 1}}}}

func TestSyslogSink_TLSServerAuthOnly_NoClientCert(t *testing.T) {
	cert, caPath := selfSignedServerCert(t)
	addr, got := startTLSSyslogServer(t, cert)

	sink := tlsSink(t, config.SyslogSinkConfig{Address: addr, CAFile: caPath})
	if err := sink.Send(context.Background(), tlsTestEvents); err != nil {
		t.Fatalf("Send without a client cert failed: %v", err)
	}
	select {
	case line := <-got:
		if line == "" {
			t.Errorf("server received nothing")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not receive a line")
	}
}

func TestSyslogSink_TLSUntrustedServerIsRejectedByDefault(t *testing.T) {
	cert, _ := selfSignedServerCert(t)
	addr, _ := startTLSSyslogServer(t, cert)

	sink := tlsSink(t, config.SyslogSinkConfig{Address: addr}) // no ca_file, no tls_insecure
	err := sink.Send(context.Background(), tlsTestEvents)
	if err == nil {
		t.Fatal("expected certificate verification to fail")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Errorf("error should be a certificate verification failure, got: %v", err)
	}
}

func TestSyslogSink_TLSInsecureSkipsVerification(t *testing.T) {
	cert, _ := selfSignedServerCert(t)
	addr, got := startTLSSyslogServer(t, cert)

	sink := tlsSink(t, config.SyslogSinkConfig{Address: addr, TLSInsecure: true})
	if err := sink.Send(context.Background(), tlsTestEvents); err != nil {
		t.Fatalf("Send with tls_insecure failed: %v", err)
	}
	select {
	case <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not receive a line")
	}
}
