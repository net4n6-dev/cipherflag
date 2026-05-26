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

package b3

import (
	"context"
	"testing"

	"github.com/net4n6-dev/cipherflag/internal/scanner/enumerate"
	"github.com/net4n6-dev/cipherflag/internal/scanner/finding"
)

func TestPythonDetector_HashlibMD5(t *testing.T) {
	src := `import hashlib

def hash(b):
    return hashlib.md5(b).hexdigest()
`
	d := NewPythonDetector()
	findings, err := d.Detect(context.Background(), enumerate.Blob{Path: "hash.py"}, []byte(src))
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("want >=1 MD5 finding")
	}
	if findings[0].RuleID != "CRYPTO-WEAK-HASH-MD5" || findings[0].Bucket != finding.BucketB3 {
		t.Errorf("bad finding: %+v", findings[0])
	}
}

func TestPythonDetector_FromImport_Hashes(t *testing.T) {
	src := `from cryptography.hazmat.primitives import hashes

def x():
    return hashes.MD5()
`
	d := NewPythonDetector()
	findings, _ := d.Detect(context.Background(), enumerate.Blob{Path: "x.py"}, []byte(src))
	if len(findings) == 0 {
		t.Fatal("want >=1 finding for hashes.MD5()")
	}
}

func TestPythonDetector_PyCryptoARC4(t *testing.T) {
	src := `from Crypto.Cipher import ARC4

def x(key):
    return ARC4.new(key)
`
	d := NewPythonDetector()
	findings, _ := d.Detect(context.Background(), enumerate.Blob{Path: "x.py"}, []byte(src))
	var hasRC4 bool
	for _, f := range findings {
		if f.RuleID == "CRYPTO-WEAK-CIPHER-RC4" {
			hasRC4 = true
		}
	}
	if !hasRC4 {
		t.Errorf("expected RC4; got %+v", findings)
	}
}

func TestPythonDetector_SkipsNonPythonFiles(t *testing.T) {
	d := NewPythonDetector()
	findings, _ := d.Detect(context.Background(), enumerate.Blob{Path: "README.md"}, []byte("# hi"))
	if len(findings) != 0 {
		t.Errorf("non-.py file should not be scanned; got %d", len(findings))
	}
}

func TestPythonDetector_IgnoresParseErrors(t *testing.T) {
	src := `def broken(:::`
	d := NewPythonDetector()
	findings, err := d.Detect(context.Background(), enumerate.Blob{Path: "x.py"}, []byte(src))
	if err != nil {
		t.Errorf("parse failure should not error; got %v", err)
	}
	_ = findings
}

func TestPythonDetector_NoFalsePositiveOnNonCrypto(t *testing.T) {
	src := `import os

print(os.getcwd())
`
	d := NewPythonDetector()
	findings, _ := d.Detect(context.Background(), enumerate.Blob{Path: "x.py"}, []byte(src))
	if len(findings) != 0 {
		t.Errorf("os module should not trigger; got %d", len(findings))
	}
}
