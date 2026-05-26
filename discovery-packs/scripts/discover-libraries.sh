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

# CipherFlag — crypto library discovery script for Linux/macOS.
# Checks dpkg, rpm, and brew for installed crypto packages.
# Output: NDJSON to stdout. Diagnostics to stderr.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/output-format.sh"

###############################################################################
# Package → canonical library name mapping
###############################################################################

canonical_name() {
    local pkg="$1"
    case "$pkg" in
        openssl|libssl3|libssl1.1|openssl-libs|"openssl@3"|"openssl@1.1") printf 'openssl' ;;
        libgnutls30|gnutls) printf 'gnutls' ;;
        libnss3|nss) printf 'nss' ;;
        libgcrypt20|libgcrypt) printf 'libgcrypt' ;;
        libsodium23|libsodium) printf 'libsodium' ;;
        libwolfssl-dev|wolfssl) printf 'wolfssl' ;;
        *) printf '%s' "$pkg" ;;
    esac
}

###############################################################################
# Emit helpers
###############################################################################

found_something=0

emit_library() {
    local name="$1"
    local version="$2"
    local pkg_name="$3"
    local pkg_mgr="$4"

    found_something=1

    local name_e version_e pkg_name_e pkg_mgr_e
    name_e="$(json_escape "$name")"
    version_e="$(json_escape "$version")"
    pkg_name_e="$(json_escape "$pkg_name")"
    pkg_mgr_e="$(json_escape "$pkg_mgr")"

    emit_json "{\"type\":\"library\",\"name\":\"${name_e}\",\"version\":\"${version_e}\",\"package_name\":\"${pkg_name_e}\",\"package_manager\":\"${pkg_mgr_e}\"}"
}

###############################################################################
# dpkg
###############################################################################

DPKG_PACKAGES=(
    openssl
    libssl3
    libssl1.1
    libgnutls30
    libnss3
    libgcrypt20
    libsodium23
    libwolfssl-dev
)

if command -v dpkg-query >/dev/null 2>&1; then
    emit_error "INFO: checking dpkg packages"
    for pkg in "${DPKG_PACKAGES[@]}"; do
        version="$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)"
        if [[ -n "$version" ]]; then
            canon="$(canonical_name "$pkg")"
            emit_library "$canon" "$version" "$pkg" "dpkg"
        fi
    done
fi

###############################################################################
# rpm
###############################################################################

RPM_PACKAGES=(
    openssl
    openssl-libs
    gnutls
    nss
    libgcrypt
    libsodium
    wolfssl
)

if command -v rpm >/dev/null 2>&1; then
    emit_error "INFO: checking rpm packages"
    for pkg in "${RPM_PACKAGES[@]}"; do
        version="$(rpm -q --qf '%{VERSION}-%{RELEASE}' "$pkg" 2>/dev/null || true)"
        # rpm outputs "package not installed" to stdout when missing; filter that
        if [[ -n "$version" ]] && ! printf '%s' "$version" | grep -qi 'not installed'; then
            canon="$(canonical_name "$pkg")"
            emit_library "$canon" "$version" "$pkg" "rpm"
        fi
    done
fi

###############################################################################
# brew
###############################################################################

BREW_PACKAGES=(
    openssl
    "openssl@3"
    "openssl@1.1"
    gnutls
    nss
    libgcrypt
    libsodium
    wolfssl
)

if command -v brew >/dev/null 2>&1; then
    emit_error "INFO: checking brew packages"
    for pkg in "${BREW_PACKAGES[@]}"; do
        version="$(brew list --versions "$pkg" 2>/dev/null | awk '{print $2}' || true)"
        if [[ -n "$version" ]]; then
            canon="$(canonical_name "$pkg")"
            emit_library "$canon" "$version" "$pkg" "brew"
        fi
    done
fi

###############################################################################
# Binary fallback — openssl version
###############################################################################

if [[ "$found_something" -eq 0 ]]; then
    emit_error "INFO: no package manager found packages; trying binary fallback"
    if command -v openssl >/dev/null 2>&1; then
        version_line="$(openssl version 2>/dev/null || true)"
        # e.g. "OpenSSL 3.0.14 7 Jan 2025 (Library: OpenSSL 3.0.14 7 Jan 2025)"
        version="$(printf '%s' "$version_line" | awk '{print $2}')"
        if [[ -n "$version" ]]; then
            emit_library "openssl" "$version" "openssl" "binary"
        fi
    fi
fi

exit 0
