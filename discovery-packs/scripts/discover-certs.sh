#!/usr/bin/env bash
# Copyright 2026 net4n6-dev
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# CipherFlag — certificate discovery script for Linux/macOS.
# Scans for PEM/DER certificate files and macOS keychain certs.
# Output: NDJSON to stdout. Diagnostics to stderr.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/output-format.sh"

OS="$(uname -s)"

###############################################################################
# Argument parsing
###############################################################################

CONTAINERS_ONLY=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --containers-only)
            CONTAINERS_ONLY=1
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--containers-only]"
            echo "  --containers-only   Only emit findings for PKCS12, JKS, and macOS keychain certs."
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

###############################################################################
# Helpers
###############################################################################

# Parse an x509 cert from a file and emit JSON.
# $1=file_path (actual file to parse)
# $2=store_type
# $3=display_path (optional — override file_path in JSON output, e.g. for keychain certs)
emit_cert_from_file() {
    local file_path="$1"
    local store_type="$2"
    local display_path="${3:-$file_path}"

    # Build openssl command
    local openssl_cmd
    if [[ "$store_type" == "der" ]]; then
        openssl_cmd="openssl x509 -inform DER -in"
    else
        openssl_cmd="openssl x509 -inform PEM -in"
    fi

    local text
    if ! text="$($openssl_cmd "$file_path" -noout \
        -fingerprint -sha256 \
        -subject -issuer \
        -startdate -enddate \
        -pubkey \
        -serial \
        -text 2>/dev/null)"; then
        emit_error "SKIP: cannot parse $file_path"
        return 0
    fi

    local fp
    fp="$(printf '%s' "$text" | grep -i 'sha256 Fingerprint' | head -1 | sed 's/.*=//;s/://g' | tr '[:upper:]' '[:lower:]' | tr -d ' \n')"

    local subject_cn issuer_cn
    subject_cn="$(printf '%s' "$text" | grep '^subject=' | head -1 | sed 's/.*CN *= *//' | sed 's/,.*//' | tr -d '\n')"
    issuer_cn="$(printf '%s' "$text"  | grep '^issuer='  | head -1 | sed 's/.*CN *= *//' | sed 's/,.*//' | tr -d '\n')"

    local not_before not_after
    not_before="$(printf '%s' "$text" | grep '^notBefore=' | head -1 | sed 's/^notBefore=//')"
    not_after="$(printf '%s' "$text"  | grep '^notAfter='  | head -1 | sed 's/^notAfter=//')"

    # Convert dates to ISO 8601
    not_before="$(convert_date "$not_before")"
    not_after="$(convert_date "$not_after")"

    local serial
    serial="$(printf '%s' "$text" | grep '^serial=' | head -1 | sed 's/^serial=//' | tr -d '\n')"

    # Key algorithm + size from -text output
    local key_algo key_size sig_algo
    key_algo="RSA"
    key_size=0
    sig_algo=""

    local pubkey_line
    pubkey_line="$(printf '%s' "$text" | grep -i 'Public Key Algorithm' | head -1 || true)"
    if printf '%s' "$pubkey_line" | grep -qi 'rsaEncryption'; then
        key_algo="RSA"
    elif printf '%s' "$pubkey_line" | grep -qi 'id-ecPublicKey\|EC'; then
        key_algo="ECDSA"
    elif printf '%s' "$pubkey_line" | grep -qi 'ED25519\|Ed25519'; then
        key_algo="Ed25519"
    fi

    local rsa_line
    rsa_line="$(printf '%s' "$text" | grep -i 'RSA Public-Key\|Public-Key' | head -1 || true)"
    if [[ -n "$rsa_line" ]]; then
        key_size="$(printf '%s' "$rsa_line" | grep -o '[0-9]\+' | head -1 || echo 0)"
    fi

    sig_algo="$(printf '%s' "$text" | grep -i 'Signature Algorithm' | head -1 | sed 's/.*Signature Algorithm: //' | tr -d '\n' || true)"

    # JSON-escape strings
    local fp_e subject_cn_e issuer_cn_e not_before_e not_after_e key_algo_e sig_algo_e serial_e file_path_e store_type_e
    fp_e="$(json_escape "$fp")"
    subject_cn_e="$(json_escape "$subject_cn")"
    issuer_cn_e="$(json_escape "$issuer_cn")"
    not_before_e="$(json_escape "$not_before")"
    not_after_e="$(json_escape "$not_after")"
    key_algo_e="$(json_escape "$key_algo")"
    sig_algo_e="$(json_escape "$sig_algo")"
    serial_e="$(json_escape "$serial")"
    file_path_e="$(json_escape "$display_path")"
    store_type_e="$(json_escape "$store_type")"

    emit_json "{\"type\":\"certificate\",\"fingerprint_sha256\":\"${fp_e}\",\"subject_cn\":\"${subject_cn_e}\",\"issuer_cn\":\"${issuer_cn_e}\",\"not_before\":\"${not_before_e}\",\"not_after\":\"${not_after_e}\",\"key_algorithm\":\"${key_algo_e}\",\"key_size\":${key_size},\"signature_algorithm\":\"${sig_algo_e}\",\"serial_number\":\"${serial_e}\",\"file_path\":\"${file_path_e}\",\"store_type\":\"${store_type_e}\"}"
}

# Convert openssl date string to ISO 8601 UTC
convert_date() {
    local d="$1"
    if [[ -z "$d" ]]; then
        printf ''
        return
    fi
    local result=""
    # Try macOS date first, then GNU date
    if [[ "$OS" == "Darwin" ]]; then
        result="$(date -u -j -f "%b %d %T %Y %Z" "$d" "+%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || true)"
    fi
    if [[ -z "$result" ]]; then
        result="$(date -u -d "$d" "+%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || true)"
    fi
    if [[ -z "$result" ]]; then
        result="$d"
    fi
    printf '%s' "$result"
}

# Detect whether a file is DER-encoded (binary)
is_der() {
    local f="$1"
    # PEM files start with "-----BEGIN"
    local header
    header="$(head -c 10 "$f" 2>/dev/null || true)"
    if printf '%s' "$header" | grep -q '^-----'; then
        return 1  # PEM
    fi
    return 0  # DER
}

###############################################################################
# Scan filesystem paths
###############################################################################

scan_path() {
    local dir="$1"
    [[ -d "$dir" ]] || return 0

    # Use find with multiple -name patterns (no -o needed with a loop)
    while IFS= read -r -d '' f; do
        [[ -r "$f" ]] || { emit_error "SKIP (unreadable): $f"; continue; }
        [[ -f "$f" ]] || continue

        if is_der "$f"; then
            emit_cert_from_file "$f" "der"
        else
            emit_cert_from_file "$f" "pem"
        fi
    done < <(find "$dir" \( -name "*.pem" -o -name "*.crt" -o -name "*.cer" -o -name "*.der" \) -type f -print0 2>/dev/null)
}

if [ "$CONTAINERS_ONLY" -eq 0 ]; then
    SCAN_PATHS=(
        "/etc/ssl/certs"
        "/etc/pki/tls/certs"
        "/usr/local/share/ca-certificates"
    )

    for sp in "${SCAN_PATHS[@]}"; do
        scan_path "$sp"
    done
fi

###############################################################################
# macOS Keychain
###############################################################################

if [[ "$OS" == "Darwin" ]]; then
    emit_error "INFO: scanning macOS keychain"
    # Write each PEM cert to a temp file, parse, delete
    TMP_CERT="$(mktemp /tmp/cipherflag_cert_XXXXXX.pem)"
    trap 'rm -f "$TMP_CERT"' EXIT

    current_cert=""
    in_cert=0
    keychain_idx=0

    while IFS= read -r line; do
        if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
            in_cert=1
            current_cert="$line"$'\n'
        elif [[ "$line" == "-----END CERTIFICATE-----" ]]; then
            current_cert+="$line"$'\n'
            printf '%s' "$current_cert" > "$TMP_CERT"
            emit_cert_from_file "$TMP_CERT" "macos_keychain" "macos-keychain://System[${keychain_idx}]"
            keychain_idx=$((keychain_idx + 1))
            current_cert=""
            in_cert=0
        elif [[ $in_cert -eq 1 ]]; then
            current_cert+="$line"$'\n'
        fi
    done < <(security find-certificate -a -p 2>/dev/null || true)
fi

exit 0
