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

package libraries

import "testing"

func TestMapFindings(t *testing.T) {
	findings := []LibraryFinding{
		{
			LibraryName:    "openssl",
			Version:        "3.0.14",
			PackageName:    "libssl3",
			PackageManager: "dpkg",
			InstallPath:    "/usr/lib/x86_64-linux-gnu/libssl.so.3",
			SourceRepo:     "Ubuntu 22.04",
			Architecture:   "amd64",
		},
		{
			LibraryName:    "gnutls",
			Version:        "3.7.9",
			PackageName:    "libgnutls30",
			PackageManager: "dpkg",
			InstallPath:    "",
			SourceRepo:     "",
			Architecture:   "",
		},
	}

	discoveries := MapFindings(findings)

	if len(discoveries) != 2 {
		t.Fatalf("got %d discoveries, want 2", len(discoveries))
	}

	d0 := discoveries[0]
	if d0.LibraryName != "openssl" {
		t.Errorf("d0.LibraryName = %q, want openssl", d0.LibraryName)
	}
	if d0.Version != "3.0.14" {
		t.Errorf("d0.Version = %q", d0.Version)
	}
	if d0.PackageName != "libssl3" {
		t.Errorf("d0.PackageName = %q", d0.PackageName)
	}
	if d0.PackageManager != "dpkg" {
		t.Errorf("d0.PackageManager = %q", d0.PackageManager)
	}
	if d0.InstallPath != "/usr/lib/x86_64-linux-gnu/libssl.so.3" {
		t.Errorf("d0.InstallPath = %q", d0.InstallPath)
	}
	if d0.PQCCapable {
		t.Error("d0.PQCCapable should be false (Layer 4 sets this)")
	}

	d1 := discoveries[1]
	if d1.LibraryName != "gnutls" {
		t.Errorf("d1.LibraryName = %q, want gnutls", d1.LibraryName)
	}
}

func TestMapFindings_Empty(t *testing.T) {
	discoveries := MapFindings(nil)
	if len(discoveries) != 0 {
		t.Errorf("got %d, want 0", len(discoveries))
	}
}
