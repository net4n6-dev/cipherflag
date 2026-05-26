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

# CipherFlag — SSH key discovery script for Linux/macOS.
# Discovers private keys, host keys, and authorized_keys files.
# Output: NDJSON to stdout. Diagnostics to stderr.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/output-format.sh"

OS="$(uname -s)"

###############################################################################
# Helpers
###############################################################################

# Get file owner username — macOS vs Linux
file_owner() {
    local f="$1"
    local owner=""
    if [[ "$OS" == "Darwin" ]]; then
        owner="$(stat -f '%Su' "$f" 2>/dev/null || true)"
    fi
    if [[ -z "$owner" ]]; then
        owner="$(stat -c '%U' "$f" 2>/dev/null || true)"
    fi
    printf '%s' "$owner"
}

# Compute SHA256 fingerprint from a public key file or public key string
# $1 = path to public key file (or temp file containing one public key line)
fingerprint_from_pubkey_file() {
    local f="$1"
    local fp=""
    fp="$(ssh-keygen -l -E sha256 -f "$f" 2>/dev/null | awk '{print $2}' | sed 's/SHA256://' || true)"
    printf '%s' "$fp"
}

# Parse key type and size from ssh-keygen -l output
# $1 = ssh-keygen -l output line
parse_keygen_line() {
    local line="$1"
    # Format: "bits SHA256:xxx comment (type)"
    KEY_SIZE="$(printf '%s' "$line" | awk '{print $1}')"
    KEY_TYPE_RAW="$(printf '%s' "$line" | sed 's/.*(//;s/)//' | tr '[:upper:]' '[:lower:]')"
    case "$KEY_TYPE_RAW" in
        rsa*)   KEY_TYPE="rsa" ;;
        ecdsa*) KEY_TYPE="ecdsa" ;;
        ed25519*) KEY_TYPE="ed25519" ;;
        dsa*)   KEY_TYPE="dsa" ;;
        *)      KEY_TYPE="$KEY_TYPE_RAW" ;;
    esac
}

# Test if a private key has no passphrase
# Returns 0 if unprotected, 1 if protected or unknown
key_has_no_passphrase() {
    local f="$1"
    ssh-keygen -y -P "" -f "$f" >/dev/null 2>&1
}

# Emit a JSON record for a private key file
emit_private_key() {
    local file_path="$1"
    local is_authorized="${2:-false}"
    local grants_root="${3:-false}"

    [[ -r "$file_path" ]] || { emit_error "SKIP (unreadable): $file_path"; return 0; }

    local keygen_out=""
    keygen_out="$(ssh-keygen -l -f "$file_path" 2>/dev/null || true)"
    if [[ -z "$keygen_out" ]]; then
        emit_error "SKIP (cannot parse): $file_path"
        return 0
    fi

    KEY_SIZE=0
    KEY_TYPE="unknown"
    parse_keygen_line "$keygen_out"

    local fp
    fp="$(printf '%s' "$keygen_out" | awk '{print $2}' | sed 's/SHA256://' || true)"

    local owner
    owner="$(file_owner "$file_path")"

    local is_protected="true"
    if key_has_no_passphrase "$file_path"; then
        is_protected="false"
    fi

    # JSON-escape
    local fp_e kt_e fp_path_e owner_e
    fp_e="$(json_escape "$fp")"
    kt_e="$(json_escape "$KEY_TYPE")"
    fp_path_e="$(json_escape "$file_path")"
    owner_e="$(json_escape "$owner")"

    emit_json "{\"type\":\"ssh_key\",\"fingerprint_sha256\":\"${fp_e}\",\"key_type\":\"${kt_e}\",\"key_size\":${KEY_SIZE},\"file_path\":\"${fp_path_e}\",\"owner\":\"${owner_e}\",\"is_protected\":${is_protected},\"is_authorized\":${is_authorized},\"grants_root\":${grants_root}}"
}

# Emit a JSON record from a public key line (for authorized_keys entries)
emit_authorized_key_entry() {
    local pubkey_line="$1"
    local auth_file="$2"
    local grants_root="$3"

    # Skip empty lines and comments
    [[ -z "$pubkey_line" ]] && return 0
    [[ "$pubkey_line" == \#* ]] && return 0

    # Write to temp file for ssh-keygen
    local tmp
    tmp="$(mktemp /tmp/cipherflag_ak_XXXXXX)"
    printf '%s\n' "$pubkey_line" > "$tmp"

    local keygen_out=""
    keygen_out="$(ssh-keygen -l -f "$tmp" 2>/dev/null || true)"
    rm -f "$tmp"

    if [[ -z "$keygen_out" ]]; then
        return 0
    fi

    KEY_SIZE=0
    KEY_TYPE="unknown"
    parse_keygen_line "$keygen_out"

    local fp
    fp="$(printf '%s' "$keygen_out" | awk '{print $2}' | sed 's/SHA256://' || true)"

    local owner
    owner="$(file_owner "$auth_file")"

    # JSON-escape
    local fp_e kt_e fp_path_e owner_e
    fp_e="$(json_escape "$fp")"
    kt_e="$(json_escape "$KEY_TYPE")"
    fp_path_e="$(json_escape "$auth_file")"
    owner_e="$(json_escape "$owner")"

    emit_json "{\"type\":\"ssh_key\",\"fingerprint_sha256\":\"${fp_e}\",\"key_type\":\"${kt_e}\",\"key_size\":${KEY_SIZE},\"file_path\":\"${fp_path_e}\",\"owner\":\"${owner_e}\",\"is_protected\":false,\"is_authorized\":true,\"grants_root\":${grants_root}}"
}

###############################################################################
# Determine user home directories to scan
###############################################################################

if [[ "$OS" == "Darwin" ]]; then
    USER_SSH_GLOB="/Users/*/.ssh"
else
    USER_SSH_GLOB="/home/*/.ssh"
fi

###############################################################################
# Scan user private keys (skip .pub files)
###############################################################################

emit_error "INFO: scanning user SSH private keys"

for ssh_dir in $USER_SSH_GLOB /root/.ssh; do
    [[ -d "$ssh_dir" ]] || continue
    while IFS= read -r -d '' f; do
        # Skip public keys
        [[ "$f" == *.pub ]] && continue
        emit_private_key "$f" "false" "false"
    done < <(find "$ssh_dir" -maxdepth 1 -name "id_*" -type f -print0 2>/dev/null)
done

###############################################################################
# Scan SSH host keys
###############################################################################

emit_error "INFO: scanning SSH host keys"

while IFS= read -r -d '' f; do
    [[ "$f" == *.pub ]] && continue
    emit_private_key "$f" "false" "false"
done < <(find /etc/ssh -maxdepth 1 -name "ssh_host_*_key" -type f -print0 2>/dev/null)

###############################################################################
# Scan authorized_keys files
###############################################################################

emit_error "INFO: scanning authorized_keys files"

scan_authorized_keys() {
    local auth_file="$1"
    local grants_root="$2"

    [[ -r "$auth_file" ]] || { emit_error "SKIP (unreadable): $auth_file"; return 0; }

    while IFS= read -r line; do
        emit_authorized_key_entry "$line" "$auth_file" "$grants_root"
    done < "$auth_file"
}

# Root authorized_keys
[[ -f /root/.ssh/authorized_keys ]] && scan_authorized_keys "/root/.ssh/authorized_keys" "true"

# User authorized_keys
for ssh_dir in $USER_SSH_GLOB; do
    [[ -d "$ssh_dir" ]] || continue
    auth_file="${ssh_dir}/authorized_keys"
    [[ -f "$auth_file" ]] || continue
    # Check if this dir belongs to root (uid 0)
    dir_owner="$(file_owner "$ssh_dir")"
    if [[ "$dir_owner" == "root" ]]; then
        scan_authorized_keys "$auth_file" "true"
    else
        scan_authorized_keys "$auth_file" "false"
    fi
done

exit 0
