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
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/net4n6-dev/cipherflag/internal/export/cbom/sinks/types"
)

// rfc5424Formatter produces lines in RFC 5424 format:
//   <PRI>1 TIMESTAMP HOSTNAME APPNAME PROCID MSGID - MSG\n
// PRI = facility*8 + severity
// MSG = JSON-encoded event.Payload
type rfc5424Formatter struct{}

// Format returns one newline-terminated RFC 5424 line.
func (r *rfc5424Formatter) Format(e types.SinkEvent, facility int) ([]byte, error) {
	sev := severityToSyslog(e.Severity)
	pri := facility*8 + sev

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "-"
	}

	ts := e.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	msg, err := json.Marshal(e.Payload)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "<%d>1 %s %s cipherflag - %s - %s\n",
		pri,
		ts.UTC().Format(time.RFC3339Nano),
		hostname,
		nonEmpty(e.AssetID, "-"),
		msg,
	)
	return buf.Bytes(), nil
}

// severityToSyslog maps CipherFlag severity names to RFC 5424 severity codes.
// Critical→2, High→3, Medium→4, Low→6, Info→6.
func severityToSyslog(s string) int {
	switch s {
	case "Critical":
		return 2
	case "High":
		return 3
	case "Medium":
		return 4
	case "Low", "Info", "":
		return 6
	}
	return 6
}

func nonEmpty(s, fallback string) string {
	if s != "" {
		return s
	}
	return fallback
}
