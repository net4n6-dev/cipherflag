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

#Requires -Version 5.1
# CipherFlag — crypto library discovery script for Windows.
# Detects installed crypto libraries via the registry and binary fallback.
# Output: NDJSON to stdout. Diagnostics to stderr.

. "$PSScriptRoot\lib\output-format.ps1"

###############################################################################
# Canonical name mapping
###############################################################################

function Get-CanonicalName {
    param([string]$DisplayName)
    $lower = $DisplayName.ToLower()
    switch -Wildcard ($lower) {
        "*openssl*"      { return "openssl" }
        "*gnutls*"       { return "gnutls" }
        "*nss*"          { return "nss" }
        "*libsodium*"    { return "libsodium" }
        "*wolfssl*"      { return "wolfssl" }
        "*bouncycastle*" { return "bouncycastle" }
        default          { return $DisplayName }
    }
}

###############################################################################
# Registry scan — Uninstall keys (both 32-bit and 64-bit hives)
###############################################################################

$registryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

# Crypto-related name patterns to match against DisplayName
$cryptoPatterns = @('openssl', 'gnutls', 'nss', 'libsodium', 'wolfssl', 'bouncycastle')

$foundSomething = $false

Emit-Error "INFO: scanning registry for installed crypto libraries"

foreach ($regPath in $registryPaths) {
    $entries = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
    foreach ($entry in $entries) {
        $displayName = $entry.DisplayName
        if ([string]::IsNullOrWhiteSpace($displayName)) { continue }

        $matched = $false
        foreach ($pattern in $cryptoPatterns) {
            if ($displayName -match [regex]::Escape($pattern)) {
                $matched = $true
                break
            }
        }
        if (-not $matched) { continue }

        $version     = if ($entry.DisplayVersion) { $entry.DisplayVersion } else { "" }
        $publisher   = if ($entry.Publisher)      { $entry.Publisher }      else { "" }
        $installLoc  = if ($entry.InstallLocation) { $entry.InstallLocation } else { "" }
        $canonName   = Get-CanonicalName -DisplayName $displayName

        $foundSomething = $true

        Emit-Json @{
            type            = "library"
            name            = $canonName
            version         = $version
            package_name    = $displayName
            package_manager = "windows_registry"
            publisher       = $publisher
            install_path    = $installLoc
        }
    }
}

###############################################################################
# Binary fallback — openssl version
###############################################################################

$opensslCmd = Get-Command openssl -ErrorAction SilentlyContinue

if ($null -ne $opensslCmd) {
    Emit-Error "INFO: checking openssl binary version"

    $versionLine = & $opensslCmd.Source version 2>$null
    if ($versionLine -match '^OpenSSL\s+(\S+)') {
        $version = $Matches[1]

        Emit-Json @{
            type            = "library"
            name            = "openssl"
            version         = $version
            package_name    = "openssl"
            package_manager = "binary"
            publisher       = ""
            install_path    = (Split-Path $opensslCmd.Source -Parent)
        }

        $foundSomething = $true
    }
}

if (-not $foundSomething) {
    Emit-Error "INFO: no crypto libraries detected via registry or binary"
}
