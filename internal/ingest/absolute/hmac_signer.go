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

package absolute

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Signer adds authentication headers to an outgoing request.
//
// The body parameter is the exact bytes that will be sent on the wire (for
// hashing). The caller is responsible for passing the same bytes that were
// used to construct the request body reader — HMAC signing requires the
// hash of the exact body bytes that the server will receive.
type Signer interface {
	Sign(req *http.Request, body []byte) error
}

// HMACSigner signs requests with Absolute's HMAC-SHA256 scheme.
//
// The canonical request format is (subject to verification against Absolute's
// published API docs):
//
//	<METHOD>\n<canonical-path>\n<canonical-query>\n<signed-headers-block>\n<hex-sha256(body)>
//
// The string-to-sign:
//
//	ABS1-HMAC-SHA-256\n<iso8601-utc-date>\n<hex-sha256(canonical-request)>
//
// Signature: hex(HMAC-SHA256(secret_key, string-to-sign)).
//
// The scheme name and header format are a best-effort match for AWS-style
// signing and may need adjustment during production validation against a
// real Absolute API endpoint. The module boundary is stable either way —
// only this file needs to change.
type HMACSigner struct {
	tokenID   string
	secretKey string
	// now is a test seam; production callers should leave it nil.
	now func() time.Time
}

// NewHMACSigner constructs a new signer with the given token ID + secret.
func NewHMACSigner(tokenID, secretKey string) *HMACSigner {
	return &HMACSigner{tokenID: tokenID, secretKey: secretKey}
}

func (s *HMACSigner) timestamp() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now().UTC()
}

// Sign mutates req's headers in place to add Absolute authentication.
// body must be the exact bytes that will be written to the wire (may be nil
// or empty for GET / DELETE).
func (s *HMACSigner) Sign(req *http.Request, body []byte) error {
	ts := s.timestamp().UTC().Format("2006-01-02T15:04:05Z")

	bodyHash := sha256Hex(body)
	host := req.URL.Host
	if req.Host != "" {
		host = req.Host
	}

	req.Header.Set("Host", host)
	req.Header.Set("X-Abs-Date", ts)
	if len(body) > 0 && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	canonicalPath := req.URL.EscapedPath()
	if canonicalPath == "" {
		canonicalPath = "/"
	}
	canonicalQuery := canonicalQueryString(req.URL.RawQuery)
	signedHeadersBlock := "host:" + host + "\n" + "x-abs-date:" + ts + "\n"
	signedHeaderNames := "host;x-abs-date"

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalPath,
		canonicalQuery,
		signedHeadersBlock,
		bodyHash,
	}, "\n")

	stringToSign := strings.Join([]string{
		"ABS1-HMAC-SHA-256",
		ts,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	mac := hmac.New(sha256.New, []byte(s.secretKey))
	if _, err := mac.Write([]byte(stringToSign)); err != nil {
		return fmt.Errorf("hmac write: %w", err)
	}
	signature := hex.EncodeToString(mac.Sum(nil))

	auth := fmt.Sprintf(
		"ABS1-HMAC-SHA-256 Credential=%s, SignedHeaders=%s, Signature=%s",
		s.tokenID, signedHeaderNames, signature,
	)
	req.Header.Set("Authorization", auth)
	return nil
}

// canonicalQueryString returns the query string sorted canonically — by
// key first, then by value for duplicate keys. This matches AWS SigV4-style
// canonical request rules and ensures signatures remain stable regardless
// of client-side parameter ordering.
func canonicalQueryString(raw string) string {
	if raw == "" {
		return ""
	}
	pairs := strings.Split(raw, "&")
	sort.SliceStable(pairs, func(i, j int) bool {
		ki, vi := splitPair(pairs[i])
		kj, vj := splitPair(pairs[j])
		if ki != kj {
			return ki < kj
		}
		return vi < vj
	})
	return strings.Join(pairs, "&")
}

func splitPair(pair string) (key, value string) {
	if idx := strings.IndexByte(pair, '='); idx >= 0 {
		return pair[:idx], pair[idx+1:]
	}
	return pair, ""
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
