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

func TestGoDetector_MD5_Hash(t *testing.T) {
	src := `package main

import "crypto/md5"

func hash(b []byte) []byte {
	h := md5.New()
	h.Write(b)
	return h.Sum(nil)
}`
	d := NewGoDetector()
	blob := enumerate.Blob{Path: "auth/hash.go", Size: int64(len(src))}
	findings, err := d.Detect(context.Background(), blob, []byte(src))
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("want >=1 finding for md5.New()")
	}
	var hasMD5 bool
	for _, f := range findings {
		if f.RuleID == "CRYPTO-WEAK-HASH-MD5" && f.Bucket == finding.BucketB3 {
			hasMD5 = true
			if f.CBOM == nil || f.CBOM.Algorithm != "MD5" {
				t.Errorf("CBOM not populated: %+v", f.CBOM)
			}
			if f.LineRange[0] == 0 {
				t.Error("expected line_range populated")
			}
		}
	}
	if !hasMD5 {
		t.Errorf("expected MD5 rule_id; got %+v", findings)
	}
}

func TestGoDetector_DES_NewCipher(t *testing.T) {
	src := `package x

import "crypto/des"

func enc(key []byte) {
	_, _ = des.NewCipher(key)
}`
	d := NewGoDetector()
	findings, _ := d.Detect(context.Background(), enumerate.Blob{Path: "x.go"}, []byte(src))
	if len(findings) != 1 || findings[0].RuleID != "CRYPTO-WEAK-CIPHER-DES" {
		t.Errorf("want 1 DES finding; got %+v", findings)
	}
}

func TestGoDetector_NoFalsePositiveOnNonCryptoImport(t *testing.T) {
	src := `package x

import "fmt"

func y() { fmt.Println("hi") }`
	d := NewGoDetector()
	findings, _ := d.Detect(context.Background(), enumerate.Blob{Path: "x.go"}, []byte(src))
	if len(findings) != 0 {
		t.Errorf("want 0 findings on non-crypto file; got %d", len(findings))
	}
}

func TestGoDetector_AliasedImport(t *testing.T) {
	src := `package x

import md5alias "crypto/md5"

func y() { _ = md5alias.New() }`
	d := NewGoDetector()
	findings, _ := d.Detect(context.Background(), enumerate.Blob{Path: "x.go"}, []byte(src))
	if len(findings) == 0 {
		t.Error("alias import should still resolve crypto/md5")
	}
}

func TestGoDetector_SkipsNonGoFiles(t *testing.T) {
	d := NewGoDetector()
	findings, _ := d.Detect(context.Background(), enumerate.Blob{Path: "README.md"}, []byte("# hi"))
	if len(findings) != 0 {
		t.Errorf("non-.go file should not be scanned; got %d", len(findings))
	}
}

func TestGoDetector_IgnoresParseErrors(t *testing.T) {
	src := `not valid go {`
	d := NewGoDetector()
	findings, err := d.Detect(context.Background(), enumerate.Blob{Path: "x.go"}, []byte(src))
	if err != nil {
		t.Errorf("parse failure should not error; got %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("parse failure -> 0 findings; got %d", len(findings))
	}
}
