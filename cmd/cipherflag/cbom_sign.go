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

// cbom_sign.go — CLI subcommands for CBOM Ed25519 signing operations.
//
// Subcommands:
//
//	generate-signing-key  Generate a fresh Ed25519 keypair for CBOM signing.
//	sign-cbom             Sign a CycloneDX BOM JSON file with an Ed25519 private key.
//	verify-cbom           Verify a signed CycloneDX BOM JSON file.
//
// Spec ref: docs/superpowers/plans/2026-05-16-l4-d-cbom-depth-pass.md §Task 14.
//
// Note on cdx.JSFSignature serialization: the CycloneDX library embeds *JSFSigner
// with tag json:"-", so json.Marshal on cdx.BOM does not write the algorithm/value/
// publicKey fields. The production emit path uses cbom.MarshalSignedBOM to work
// around this. The verify-cbom subcommand reads the signature directly from the
// raw JSON map (keyed by "signature") to avoid the same issue in the decode path.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/net4n6-dev/cipherflag/internal/export/cbom"
)

// verifySignatureBlock is the wire shape decoded from the raw "signature" key
// when running verify-cbom. Kept local to this file; the production serialization
// path uses cbom.jsfSignatureJSON (package-private) via cbom.MarshalSignedBOM.
type verifySignatureBlock struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
	PublicKey struct {
		KTY string `json:"kty"`
		CRV string `json:"crv"`
		X   string `json:"x"`
	} `json:"publicKey"`
}

// runGenerateSigningKey generates a fresh Ed25519 keypair and writes:
//   - outPrefix+".key"  — private key, PEM type "PRIVATE KEY", mode 0600
//   - outPrefix+".pub"  — public key,  PEM type "PUBLIC KEY",  mode 0644
//
// A SHA-256 fingerprint of the public key is printed so operators can record
// it in an out-of-band trust registry.
func runGenerateSigningKey(_ context.Context, outPrefix string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})

	if err := os.WriteFile(outPrefix+".key", privPEM, 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(outPrefix+".pub", pubPEM, 0644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	sum := sha256.Sum256(pub)
	fmt.Printf("Wrote %s.key (private, mode 0600)\n", outPrefix)
	fmt.Printf("Wrote %s.pub (public)\n", outPrefix)
	fmt.Printf("Public key SHA-256 fingerprint: %s\n", hex.EncodeToString(sum[:]))
	return nil
}

// runSignCBOM reads a CycloneDX BOM from inPath, attaches a JSF detached
// Ed25519 signature using the key at keyPath, and writes the signed BOM to
// outPath. When outPath is empty the signed BOM is written back to inPath
// (in-place update).
//
// Because cdx.JSFSignature embeds *JSFSigner with json:"-", standard
// json.MarshalIndent would produce an empty "signature":{} block. Instead
// we capture the signature fields directly from the in-memory cdx.BOM after
// SignBOM runs, then inject them as a proper JSON object into the output.
func runSignCBOM(_ context.Context, inPath, outPath, keyPath string) error {
	raw, err := os.ReadFile(inPath)
	if err != nil {
		return fmt.Errorf("read BOM: %w", err)
	}

	var bom cdx.BOM
	if err := json.Unmarshal(raw, &bom); err != nil {
		return fmt.Errorf("parse BOM: %w", err)
	}

	signer, err := cbom.NewFileSigner(keyPath)
	if err != nil {
		return fmt.Errorf("load signing key: %w", err)
	}

	if err := cbom.SignBOM(&bom, signer); err != nil {
		return fmt.Errorf("sign BOM: %w", err)
	}

	if bom.Signature == nil || bom.Signature.JSFSigner == nil {
		return fmt.Errorf("SignBOM did not set signature")
	}

	// MarshalSignedBOM injects the JSF signature block into the JSON output,
	// working around cdx.JSFSignature's json:"-" tag on *JSFSigner which would
	// otherwise silently drop Algorithm/Value/PublicKey. The result is compact
	// JSON; we pretty-print it below for human-readable CLI output.
	compact, err := cbom.MarshalSignedBOM(&bom)
	if err != nil {
		return fmt.Errorf("marshal signed BOM: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(compact, &fields); err != nil {
		return fmt.Errorf("unmarshal for indent: %w", err)
	}
	signed, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return fmt.Errorf("indent signed BOM: %w", err)
	}

	target := outPath
	if target == "" {
		target = inPath
	}
	if err := os.WriteFile(target, append(signed, '\n'), 0644); err != nil {
		return fmt.Errorf("write signed BOM: %w", err)
	}
	return nil
}

// runVerifyCBOM verifies the JSF Ed25519 signature on the BOM at bomPath.
// Exit-code semantics (returned as the first int, never an error unless I/O
// or parse fails):
//
//	0 — signature cryptographically valid AND embedded public key matches the
//	    trusted key at trustedKeyPath (if provided).
//	1 — signature cryptographically valid BUT the embedded public key does NOT
//	    match the operator's trusted key (trust mismatch).
//	2 — signature invalid, BOM malformed, or no signature block present.
//
// When trustedKeyPath is empty the function returns 0 on a valid signature
// without a trust check (self-attest mode — the 1-case never fires).
//
// Because cdx.JSFSignature embeds *JSFSigner with json:"-", we read the
// signature from the raw JSON map directly rather than via bom.Signature.
// We strip the "signature" key from the raw JSON map, canonicalize the
// remaining fields, and verify against the embedded public key.
func runVerifyCBOM(_ context.Context, bomPath, trustedKeyPath string) (int, error) {
	raw, err := os.ReadFile(bomPath)
	if err != nil {
		return 2, fmt.Errorf("read BOM: %w", err)
	}

	// Parse as a raw field map so we can extract and strip the signature key
	// without relying on cdx.BOM's json:"-"-tagged embedded pointer.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return 2, fmt.Errorf("parse BOM JSON: %w", err)
	}

	sigRaw, ok := fields["signature"]
	if !ok {
		// No signature block — not a cryptographic failure, just absent.
		fmt.Fprintln(os.Stderr, "verify-cbom: BOM has no signature block")
		return 2, nil
	}

	var sig verifySignatureBlock
	if err := json.Unmarshal(sigRaw, &sig); err != nil {
		// Malformed signature JSON — format failure, not I/O.
		fmt.Fprintf(os.Stderr, "verify-cbom: parse signature block: %v\n", err)
		return 2, nil
	}
	if sig.Value == "" {
		// Signature block present but value field empty or absent — tampered/stripped.
		fmt.Fprintln(os.Stderr, "verify-cbom: signature block is missing value field")
		return 2, nil
	}

	// Decode the base64-encoded signature value and the embedded public key.
	sigBytes, err := base64.StdEncoding.DecodeString(sig.Value)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify-cbom: decode signature value: %v\n", err)
		return 2, nil
	}
	pubBytes, err := base64.RawURLEncoding.DecodeString(sig.PublicKey.X)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify-cbom: decode embedded public key: %v\n", err)
		return 2, nil
	}

	// Strip the signature key and canonicalize the remaining fields. The canonical
	// form must match exactly what SignBOM signed — the BOM JSON with no
	// "signature" key, RFC 8785 (JCS) canonicalized.
	delete(fields, "signature")
	stripped, err := json.Marshal(fields)
	if err != nil {
		return 2, fmt.Errorf("marshal stripped BOM: %w", err)
	}
	canonical, err := cbom.Canonicalize(stripped)
	if err != nil {
		return 2, fmt.Errorf("canonicalize BOM: %w", err)
	}

	embeddedPub := ed25519.PublicKey(pubBytes)
	if !ed25519.Verify(embeddedPub, canonical, sigBytes) {
		fmt.Fprintln(os.Stderr, "verify-cbom: signature verification failed")
		return 2, nil
	}

	embeddedSum := sha256.Sum256(pubBytes)
	fmt.Printf("Signature valid. Embedded public key SHA-256: %s\n", hex.EncodeToString(embeddedSum[:]))

	if trustedKeyPath == "" {
		return 0, nil
	}

	// Trust check: compare the embedded public key bytes against the operator's
	// trusted public key from trustedKeyPath.
	trustedPEM, err := os.ReadFile(trustedKeyPath)
	if err != nil {
		return 1, fmt.Errorf("read trusted key: %w", err)
	}
	block, _ := pem.Decode(trustedPEM)
	if block == nil {
		return 1, fmt.Errorf("trusted-key PEM parse failed")
	}
	trustedPub := ed25519.PublicKey(block.Bytes)

	if !ed25519KeyEqual(trustedPub, embeddedPub) {
		trustedSum := sha256.Sum256(trustedPub)
		fmt.Fprintf(os.Stderr,
			"Trust mismatch: BOM was signed with a different key than --trusted-key.\n  Trusted key SHA-256:  %s\n  Embedded key SHA-256: %s\n",
			hex.EncodeToString(trustedSum[:]),
			hex.EncodeToString(embeddedSum[:]),
		)
		return 1, nil
	}

	fmt.Println("Trust verified: embedded key matches --trusted-key.")
	return 0, nil
}

// ed25519KeyEqual returns true when a and b are byte-for-byte identical.
// Avoids importing bytes.Equal to keep the dependency surface minimal.
func ed25519KeyEqual(a, b ed25519.PublicKey) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// cliGenerateSigningKey is the entry point for `cipherflag generate-signing-key`.
// Parses --out flag and delegates to runGenerateSigningKey.
func cliGenerateSigningKey(ctx context.Context) {
	fs := flag.NewFlagSet("generate-signing-key", flag.ExitOnError)
	out := fs.String("out", "cbom-signing", "output file prefix (writes <prefix>.key and <prefix>.pub)")
	fs.Parse(os.Args[2:]) //nolint:errcheck // ExitOnError handles errors
	if err := runGenerateSigningKey(ctx, *out); err != nil {
		fmt.Fprintf(os.Stderr, "generate-signing-key: %v\n", err)
		os.Exit(1)
	}
}

// cliSignCBOM is the entry point for `cipherflag sign-cbom`.
// Parses --bom, --out, and --key flags and delegates to runSignCBOM.
func cliSignCBOM(ctx context.Context) {
	fs := flag.NewFlagSet("sign-cbom", flag.ExitOnError)
	bomPath := fs.String("bom", "", "path to the CycloneDX BOM JSON file to sign (required)")
	outPath := fs.String("out", "", "output path for signed BOM (default: overwrite --bom in-place)")
	keyPath := fs.String("key", "", "path to the Ed25519 private key PEM file (required)")
	fs.Parse(os.Args[2:]) //nolint:errcheck // ExitOnError handles errors

	if *bomPath == "" || *keyPath == "" {
		fmt.Fprintln(os.Stderr, "sign-cbom: --bom and --key are required")
		fs.Usage()
		os.Exit(1)
	}

	if err := runSignCBOM(ctx, *bomPath, *outPath, *keyPath); err != nil {
		fmt.Fprintf(os.Stderr, "sign-cbom: %v\n", err)
		os.Exit(1)
	}
}

// cliVerifyCBOM is the entry point for `cipherflag verify-cbom`.
// Parses --bom and --trusted-key flags and delegates to runVerifyCBOM.
// Exit code mirrors the semantics documented on runVerifyCBOM (0/1/2).
func cliVerifyCBOM(ctx context.Context) {
	fs := flag.NewFlagSet("verify-cbom", flag.ExitOnError)
	bomPath := fs.String("bom", "", "path to the signed CycloneDX BOM JSON file (required)")
	trustedKey := fs.String("trusted-key", "", "path to the trusted Ed25519 public key PEM file (optional; omit for self-attest mode)")
	fs.Parse(os.Args[2:]) //nolint:errcheck // ExitOnError handles errors

	if *bomPath == "" {
		fmt.Fprintln(os.Stderr, "verify-cbom: --bom is required")
		fs.Usage()
		os.Exit(1)
	}

	code, err := runVerifyCBOM(ctx, *bomPath, *trustedKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify-cbom: %v\n", err)
	}
	os.Exit(code)
}
