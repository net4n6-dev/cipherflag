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

// Package secrets resolves opaque reference strings (e.g. "env:GITHUB_PAT",
// "file:/etc/creds/pat") to plaintext secrets at runtime. Resolved values
// are returned by-value to the caller; the resolver never persists them.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrUnknownScheme is returned when the reference does not carry a
	// recognised prefix.
	ErrUnknownScheme = errors.New("secrets: unknown resolver scheme")

	// ErrResolverNotImplemented is returned by stub resolvers whose full
	// impls are deferred (vault, k8s, aws-sm, gcp-sm).
	ErrResolverNotImplemented = errors.New("secrets: resolver not implemented in v1")
)

// Resolve parses ref as "<scheme>:<payload>" and dispatches to the right
// resolver. The returned string is the plaintext secret.
//
// Supported schemes (v1):
//   - env:VAR_NAME          read from process env
//   - file:/abs/or/rel/path read file contents (trailing whitespace trimmed)
//
// Stubbed schemes (return ErrResolverNotImplemented):
//   - vault:<mount>/<path>#<field>
//   - k8s:<namespace>/<secret-name>#<key>
//   - aws-sm:<secret-name>
//   - gcp-sm:<resource-name>
//
// All callers must treat the returned string as sensitive — never log.
func Resolve(ctx context.Context, ref string) (string, error) {
	scheme, payload, ok := strings.Cut(ref, ":")
	if !ok || scheme == "" {
		return "", fmt.Errorf("secrets: malformed reference %q (want <scheme>:<payload>)", ref)
	}
	switch scheme {
	case "env":
		return resolveEnv(payload)
	case "file":
		return resolveFile(payload)
	case "vault", "k8s", "aws-sm", "gcp-sm":
		return "", fmt.Errorf("%w: %s", ErrResolverNotImplemented, scheme)
	default:
		return "", fmt.Errorf("%w: %q", ErrUnknownScheme, scheme)
	}
}
