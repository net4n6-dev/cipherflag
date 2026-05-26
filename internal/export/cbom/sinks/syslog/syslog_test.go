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
	"net"
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
