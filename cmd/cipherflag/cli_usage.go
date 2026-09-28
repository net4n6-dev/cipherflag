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
	"flag"
	"fmt"
	"os"
)

// Subcommand exit codes: 0 did what was asked, 1 tried and failed, 2 was
// invoked wrongly and did nothing (-h, an unknown flag, a stray argument, a
// missing, conflicting or invalid flag value). verify-cbom keeps its own
// 0-3 contract (exitCouldNotVerify).
const exitUsage = 2

// parseSubcommandFlags parses a flags-only subcommand's arguments. The flag
// set must use flag.ContinueOnError. On -h or an invalid flag it exits
// exitUsage (the flag package has already printed the error or the usage);
// flag.ExitOnError would exit 0 for -h, which a script reads as success
// although nothing ran. None of these subcommands takes positional
// arguments, so one is a usage error too rather than being ignored.
func parseSubcommandFlags(fs *flag.FlagSet, args []string) {
	if err := fs.Parse(args); err != nil {
		os.Exit(exitUsage)
	}
	if fs.NArg() > 0 {
		usageError(fs, fmt.Sprintf("unexpected argument %q", fs.Arg(0)))
	}
}

// usageError reports an invalid invocation and exits exitUsage, before the
// command has done anything.
func usageError(fs *flag.FlagSet, msg string) {
	fmt.Fprintf(os.Stderr, "%s: %s\n", fs.Name(), msg)
	fs.Usage()
	os.Exit(exitUsage)
}
