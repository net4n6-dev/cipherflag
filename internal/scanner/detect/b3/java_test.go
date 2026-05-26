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

func TestJavaDetector_MessageDigest_MD5(t *testing.T) {
	src := `import java.security.MessageDigest;

class X {
    public byte[] hash(byte[] b) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(b);
    }
}`
	d := NewJavaDetector()
	findings, err := d.Detect(context.Background(), enumerate.Blob{Path: "X.java"}, []byte(src))
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

func TestJavaDetector_Cipher_DES_CBC(t *testing.T) {
	src := `import javax.crypto.Cipher;

class X {
    public void enc() throws Exception {
        Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");
    }
}`
	d := NewJavaDetector()
	findings, _ := d.Detect(context.Background(), enumerate.Blob{Path: "X.java"}, []byte(src))
	if len(findings) == 0 {
		t.Fatal("want >=1 finding for DES/CBC")
	}
	var hasDES bool
	for _, f := range findings {
		if f.RuleID == "CRYPTO-WEAK-CIPHER-DES" {
			hasDES = true
			if f.CBOM == nil || f.CBOM.Mode != "CBC" || f.CBOM.Padding != "PKCS5Padding" {
				t.Errorf("CBOM not parsed from JCA string: %+v", f.CBOM)
			}
		}
	}
	if !hasDES {
		t.Errorf("expected DES rule_id; got %+v", findings)
	}
}

func TestJavaDetector_Cipher_AES_ECB_FlagsMode(t *testing.T) {
	src := `import javax.crypto.Cipher;
class X {
    public void e() throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
    }
}`
	d := NewJavaDetector()
	findings, _ := d.Detect(context.Background(), enumerate.Blob{Path: "X.java"}, []byte(src))
	var hasECB bool
	for _, f := range findings {
		if f.RuleID == "CRYPTO-WEAK-MODE-ECB" {
			hasECB = true
		}
	}
	if !hasECB {
		t.Errorf("AES/ECB should trigger ECB rule; got %+v", findings)
	}
}

func TestJavaDetector_NonLiteralArgument_Skipped(t *testing.T) {
	// Variable arg — detector cannot resolve, must emit nothing.
	src := `import javax.crypto.Cipher;
class X {
    public void e(String alg) throws Exception {
        Cipher c = Cipher.getInstance(alg);
    }
}`
	d := NewJavaDetector()
	findings, _ := d.Detect(context.Background(), enumerate.Blob{Path: "X.java"}, []byte(src))
	if len(findings) != 0 {
		t.Errorf("non-literal arg should be skipped; got %+v", findings)
	}
}

func TestJavaDetector_SkipsNonJavaFiles(t *testing.T) {
	d := NewJavaDetector()
	findings, _ := d.Detect(context.Background(), enumerate.Blob{Path: "README.md"}, []byte("# hi"))
	if len(findings) != 0 {
		t.Errorf("non-.java file should not be scanned; got %d", len(findings))
	}
}
