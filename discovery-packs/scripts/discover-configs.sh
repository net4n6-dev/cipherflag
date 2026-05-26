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

# CipherFlag — crypto configuration discovery script for Linux/macOS.
# Scans sshd_config, openssl.cnf, and java.security files.
# Output: NDJSON to stdout. Diagnostics to stderr.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/output-format.sh"

###############################################################################
# Helper: extract a single-key value from a config file
# $1=file $2=key (case-insensitive, first uncommented match)
# Handles "Key value", "Key = value", and "Key=value" styles
###############################################################################

extract_value() {
    local file="$1"
    local key="$2"
    # Match: optional whitespace, key (not preceded by #), optional = , value
    local val
    val="$(grep -i "^[[:space:]]*${key}[[:space:]]*" "$file" 2>/dev/null \
        | grep -v '^[[:space:]]*#' \
        | head -1 \
        | sed "s/^[[:space:]]*${key}[[:space:]]*=\?[[:space:]]*//" \
        | sed 's/[[:space:]]*$//' \
        || true)"
    printf '%s' "$val"
}

###############################################################################
# Build a JSON object string from key=value pairs.
# Reads from two global arrays: CFG_KEYS and CFG_VALS (parallel arrays).
###############################################################################

# CFG_KEYS and CFG_VALS are global, reset before each call to process_*
CFG_KEYS=()
CFG_VALS=()

add_setting() {
    CFG_KEYS+=("$1")
    CFG_VALS+=("$2")
}

build_settings_json() {
    local json="{"
    local first=1
    local i=0
    while [[ $i -lt ${#CFG_KEYS[@]} ]]; do
        local k v
        k="$(json_escape "${CFG_KEYS[$i]}")"
        v="$(json_escape "${CFG_VALS[$i]}")"
        if [[ $first -eq 1 ]]; then
            first=0
        else
            json+=","
        fi
        json+="\"${k}\":\"${v}\""
        i=$((i + 1))
    done
    json+="}"
    printf '%s' "$json"
}

###############################################################################
# Emit JSON for a config file
###############################################################################

emit_config() {
    local config_type="$1"
    local file_path="$2"
    local settings_json="$3"

    local ct_e fp_e
    ct_e="$(json_escape "$config_type")"
    fp_e="$(json_escape "$file_path")"

    emit_json "{\"type\":\"config\",\"config_type\":\"${ct_e}\",\"file_path\":\"${fp_e}\",\"settings\":${settings_json}}"
}

###############################################################################
# 1. sshd_config
###############################################################################

process_sshd_config() {
    local f="$1"
    [[ -f "$f" && -r "$f" ]] || return 0

    emit_error "INFO: scanning sshd_config: $f"

    CFG_KEYS=()
    CFG_VALS=()

    add_setting "Ciphers"              "$(extract_value "$f" "Ciphers")"
    add_setting "MACs"                 "$(extract_value "$f" "MACs")"
    add_setting "KexAlgorithms"        "$(extract_value "$f" "KexAlgorithms")"
    add_setting "HostKeyAlgorithms"    "$(extract_value "$f" "HostKeyAlgorithms")"
    add_setting "PasswordAuthentication" "$(extract_value "$f" "PasswordAuthentication")"

    local settings_json
    settings_json="$(build_settings_json)"
    emit_config "sshd_config" "$f" "$settings_json"
}

# Main sshd_config
process_sshd_config "/etc/ssh/sshd_config"

# Drop-in configs
if [[ -d /etc/ssh/sshd_config.d ]]; then
    while IFS= read -r -d '' f; do
        process_sshd_config "$f"
    done < <(find /etc/ssh/sshd_config.d -name "*.conf" -type f -print0 2>/dev/null)
fi

###############################################################################
# 2. openssl.cnf
###############################################################################

process_openssl_cnf() {
    local f="$1"
    [[ -f "$f" && -r "$f" ]] || return 0

    emit_error "INFO: scanning openssl.cnf: $f"

    CFG_KEYS=()
    CFG_VALS=()

    add_setting "default_md"   "$(extract_value "$f" "default_md")"
    add_setting "default_bits" "$(extract_value "$f" "default_bits")"

    # FIPS mode: look for fips_mode = yes or openssl_conf = fips_provider
    local fips_mode="false"
    if grep -qi 'fips_mode[[:space:]]*=[[:space:]]*yes\|openssl_conf[[:space:]]*=[[:space:]]*fips' "$f" 2>/dev/null; then
        fips_mode="true"
    fi
    add_setting "fips_mode" "$fips_mode"

    local settings_json
    settings_json="$(build_settings_json)"
    emit_config "openssl_cnf" "$f" "$settings_json"
}

OPENSSL_CNF_PATHS=(
    "/etc/ssl/openssl.cnf"
    "/etc/pki/tls/openssl.cnf"
)

# Also scan brew/macOS openssl paths
while IFS= read -r -d '' f; do
    OPENSSL_CNF_PATHS+=("$f")
done < <(find /usr/local/etc -maxdepth 3 -name "openssl.cnf" -print0 2>/dev/null)

for f in "${OPENSSL_CNF_PATHS[@]}"; do
    process_openssl_cnf "$f"
done

###############################################################################
# 3. java.security
###############################################################################

process_java_security() {
    local f="$1"
    [[ -f "$f" && -r "$f" ]] || return 0

    emit_error "INFO: scanning java.security: $f"

    CFG_KEYS=()
    CFG_VALS=()

    # jdk.tls.disabledAlgorithms can span continuation lines; grab the first line only
    local disabled_algos
    disabled_algos="$(grep -i '^[[:space:]]*jdk\.tls\.disabledAlgorithms[[:space:]]*=' "$f" 2>/dev/null \
        | head -1 \
        | sed 's/^[[:space:]]*jdk\.tls\.disabledAlgorithms[[:space:]]*=[[:space:]]*//' \
        | sed 's/[[:space:]]*\\$//' \
        | tr -d '\n' \
        || true)"

    local keystore_type
    keystore_type="$(extract_value "$f" "keystore.type")"

    add_setting "jdk.tls.disabledAlgorithms" "$disabled_algos"
    add_setting "keystore.type" "$keystore_type"

    local settings_json
    settings_json="$(build_settings_json)"
    emit_config "java_security" "$f" "$settings_json"
}

# System JVMs — scan /usr/lib/jvm/*/conf/security/java.security
while IFS= read -r -d '' f; do
    process_java_security "$f"
done < <(find /usr/lib/jvm -maxdepth 5 -name "java.security" -path "*/security/java.security" -print0 2>/dev/null)

# $JAVA_HOME if set
if [[ -n "${JAVA_HOME:-}" && -f "${JAVA_HOME}/conf/security/java.security" ]]; then
    process_java_security "${JAVA_HOME}/conf/security/java.security"
fi

# macOS: /Library/Java/JavaVirtualMachines/*/Contents/Home/conf/security/java.security
while IFS= read -r -d '' f; do
    process_java_security "$f"
done < <(find /Library/Java/JavaVirtualMachines -maxdepth 8 -name "java.security" -path "*/security/java.security" -print0 2>/dev/null)

exit 0
