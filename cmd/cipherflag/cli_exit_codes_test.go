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

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// The subcommands' exit codes: 0 did what was asked, 1 tried and failed,
// 2 called wrong and nothing was done. They used flag.ExitOnError, so -h
// exited 0 (read by scripts as success, though nothing ran), an unknown flag
// exited 2 but a missing required flag exited 1 (read as a failure), and a
// stray argument was silently ignored: `generate-signing-key foo` wrote
// cbom-signing.* without complaint. (verify-cbom has its own 0-3 contract.)
func TestSubcommandExitCodes(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the cipherflag binary")
	}
	bin := buildCipherflag(t)
	dir := t.TempDir()
	// Database commands get a config whose database refuses connections, so
	// a valid invocation fails (1) at the connect, after argument checks.
	cfg := writePreflightConfig(t, dir, "")
	missing := filepath.Join(dir, "does-not-exist")
	host := "00000000-0000-0000-0000-000000000001"

	key := filepath.Join(dir, "k")
	if out, code := runCipherflag(t, bin, cfg, "generate-signing-key", "--out", key); code != 0 {
		t.Fatalf("generate-signing-key exit %d: %s", code, out)
	}
	bom := writeUnsignedBOM(t, dir)

	type tc struct {
		name string
		args []string
		want int
	}
	usage := func(cmd []string, valid []string, extra ...tc) []tc {
		with := func(more ...string) []string {
			return append(append(append([]string{}, cmd...), valid...), more...)
		}
		name := strings.Join(cmd, " ")
		return append([]tc{
			{name + " -h", append(append([]string{}, cmd...), "-h"), 2},
			{name + " unknown flag", with("--no-such-flag"), 2},
			{name + " stray argument", with("stray"), 2},
		}, extra...)
	}

	var cases []tc
	// Controls: real successes and real failures, so an "exit 2 everywhere"
	// bug fails.
	cases = append(cases,
		tc{"generate-signing-key succeeds", []string{"generate-signing-key", "--out", filepath.Join(dir, "k2")}, 0},
		tc{"sign-cbom succeeds", []string{"sign-cbom", "--bom", bom, "--key", key + ".key", "--out", filepath.Join(dir, "signed.json")}, 0},
		tc{"sign-cbom with a missing key file fails", []string{"sign-cbom", "--bom", bom, "--key", missing}, 1},
		tc{"scan-truststore valid, database down", []string{"scan-truststore", "--host-id", host}, 1},
		tc{"declared-cas import valid, database down", []string{"declared-cas", "import", "--starter"}, 1},
		tc{"ownership declare valid, database down", []string{"ownership", "declare", "--asset-type", "certificate", "--asset-id", "ab", "--team", "t"}, 1},
		tc{"ownership import with a missing file fails", []string{"ownership", "import", "--file", missing}, 1},
		tc{"ownership backfill valid, database down", []string{"ownership", "backfill"}, 1},
		tc{"application-metadata declare valid, database down", []string{"application-metadata", "declare", "--tag", "t", "--ttl-years", "5"}, 1},
		tc{"application-metadata import with a missing file fails", []string{"application-metadata", "import", "--file", missing}, 1},
	)
	cases = append(cases, usage([]string{"generate-signing-key"}, []string{"--out", filepath.Join(dir, "k3")})...)
	cases = append(cases, usage([]string{"sign-cbom"}, []string{"--bom", bom, "--key", key + ".key", "--out", filepath.Join(dir, "s.json")},
		tc{"sign-cbom without --key", []string{"sign-cbom", "--bom", bom}, 2})...)
	cases = append(cases, usage([]string{"scan-truststore"}, []string{"--host-id", host},
		tc{"scan-truststore without --host-id", []string{"scan-truststore"}, 2})...)
	cases = append(cases, usage([]string{"declared-cas", "import"}, []string{"--starter"},
		tc{"declared-cas import without --starter or --file", []string{"declared-cas", "import"}, 2},
		tc{"declared-cas import with both", []string{"declared-cas", "import", "--starter", "--file", missing}, 2})...)
	cases = append(cases, usage([]string{"ownership", "declare"}, []string{"--asset-type", "certificate", "--asset-id", "ab", "--team", "t"},
		tc{"ownership declare without --team", []string{"ownership", "declare", "--asset-type", "certificate", "--asset-id", "ab"}, 2},
		tc{"ownership declare with an unknown asset type", []string{"ownership", "declare", "--asset-type", "bogus", "--asset-id", "ab", "--team", "t"}, 2})...)
	cases = append(cases, usage([]string{"ownership", "import"}, []string{"--file", missing},
		tc{"ownership import without --file", []string{"ownership", "import"}, 2})...)
	cases = append(cases, usage([]string{"ownership", "backfill"}, nil)...)
	cases = append(cases, usage([]string{"application-metadata", "declare"}, []string{"--tag", "t", "--ttl-years", "5"},
		tc{"application-metadata declare without --tag", []string{"application-metadata", "declare", "--ttl-years", "5"}, 2},
		tc{"application-metadata declare with --preset and --ttl-years", []string{"application-metadata", "declare", "--tag", "t", "--preset", "p", "--ttl-years", "5"}, 2})...)
	cases = append(cases, usage([]string{"application-metadata", "import"}, []string{"--file", missing},
		tc{"application-metadata import without --file", []string{"application-metadata", "import"}, 2})...)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, code := runCipherflag(t, bin, cfg, c.args...)
			if code != c.want {
				t.Errorf("exit code = %d, want %d; output:\n%s", code, c.want, out)
			}
			if c.want == 2 && strings.Contains(out, "connect") {
				t.Errorf("a usage error must stop before any work, but the command tried to connect; output:\n%s", out)
			}
		})
	}
}
