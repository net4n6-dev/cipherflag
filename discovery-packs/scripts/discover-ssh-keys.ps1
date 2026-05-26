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
# CipherFlag — SSH key discovery script for Windows.
# Scans OpenSSH private keys, host keys, and authorized_keys files.
# Output: NDJSON to stdout. Diagnostics to stderr.

. "$PSScriptRoot\lib\output-format.ps1"

###############################################################################
# Helpers
###############################################################################

# Resolve the owner of a file. Returns the SAM-style account name (DOMAIN\user).
function Get-FileOwner {
    param([string]$FilePath)
    try {
        $acl = Get-Acl -Path $FilePath -ErrorAction SilentlyContinue
        if ($acl) { return $acl.Owner }
    }
    catch { }
    return ""
}

# Return $true if the owner looks like a SYSTEM or Administrator account.
function Test-GrantsRoot {
    param([string]$Owner)
    if ([string]::IsNullOrEmpty($Owner)) { return $false }
    $lower = $Owner.ToLower()
    return ($lower -match 'system' -or $lower -match 'administrator' -or $lower -match 'administrators')
}

# Use ssh-keygen to parse a private key file and emit a JSON record.
function Emit-PrivateKey {
    param(
        [string]$FilePath,
        [bool]$IsAuthorized = $false,
        [bool]$GrantsRoot   = $false
    )

    if (-not (Test-Path -Path $FilePath -PathType Leaf)) { return }

    $owner = Get-FileOwner -FilePath $FilePath
    if (-not $GrantsRoot) {
        $GrantsRoot = Test-GrantsRoot -Owner $owner
    }

    if ($null -ne $sshKeygen) {
        $keygen_out = & $sshKeygen.Source -l -f $FilePath 2>$null
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($keygen_out)) {
            Emit-Error "SKIP (cannot parse key): $FilePath"
            return
        }

        # Format: "bits SHA256:xxx comment (type)"
        $parts    = $keygen_out -split '\s+'
        $keySize  = try { [int]$parts[0] } catch { 0 }
        $fp       = ($parts[1] -replace '^SHA256:', '')

        $keyType = "unknown"
        if ($keygen_out -match '\(([^)]+)\)\s*$') {
            $raw = $Matches[1].ToLower()
            $keyType = switch -Wildcard ($raw) {
                "rsa*"     { "rsa" }
                "ecdsa*"   { "ecdsa" }
                "ed25519*" { "ed25519" }
                "dsa*"     { "dsa" }
                default    { $raw }
            }
        }

        # Test for passphrase: ssh-keygen -y -P "" succeeds only on unprotected keys
        $isProtected = $true
        & $sshKeygen.Source -y -P "" -f $FilePath >$null 2>&1
        if ($LASTEXITCODE -eq 0) { $isProtected = $false }
    }
    else {
        # ssh-keygen not available — emit minimal record without fingerprint
        $fp          = ""
        $keyType     = "unknown"
        $keySize     = 0
        $isProtected = $true
    }

    Emit-Json @{
        type               = "ssh_key"
        fingerprint_sha256 = $fp
        key_type           = $keyType
        key_size           = $keySize
        file_path          = $FilePath
        owner              = $owner
        is_protected       = $isProtected
        is_authorized      = $IsAuthorized
        grants_root        = $GrantsRoot
    }
}

# Emit a JSON record for each public key entry in an authorized_keys file.
function Emit-AuthorizedKeysFile {
    param(
        [string]$FilePath,
        [bool]$GrantsRoot = $false
    )

    if (-not (Test-Path -Path $FilePath -PathType Leaf)) { return }

    $lines = Get-Content -Path $FilePath -ErrorAction SilentlyContinue
    if ($null -eq $lines) { return }

    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrEmpty($trimmed) -or $trimmed.StartsWith('#')) { continue }

        if ($null -ne $sshKeygen) {
            $tmp = [System.IO.Path]::GetTempFileName()
            try {
                Set-Content -Path $tmp -Value $trimmed -Encoding UTF8 -ErrorAction SilentlyContinue
                $keygen_out = & $sshKeygen.Source -l -f $tmp 2>$null
                if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($keygen_out)) { continue }

                $parts   = $keygen_out -split '\s+'
                $keySize = try { [int]$parts[0] } catch { 0 }
                $fp      = ($parts[1] -replace '^SHA256:', '')

                $keyType = "unknown"
                if ($keygen_out -match '\(([^)]+)\)\s*$') {
                    $raw = $Matches[1].ToLower()
                    $keyType = switch -Wildcard ($raw) {
                        "rsa*"     { "rsa" }
                        "ecdsa*"   { "ecdsa" }
                        "ed25519*" { "ed25519" }
                        "dsa*"     { "dsa" }
                        default    { $raw }
                    }
                }
            }
            finally {
                Remove-Item -Path $tmp -ErrorAction SilentlyContinue
            }
        }
        else {
            $fp      = ""
            $keyType = "unknown"
            $keySize = 0
        }

        $owner = Get-FileOwner -FilePath $FilePath

        Emit-Json @{
            type               = "ssh_key"
            fingerprint_sha256 = $fp
            key_type           = $keyType
            key_size           = $keySize
            file_path          = $FilePath
            owner              = $owner
            is_protected       = $false
            is_authorized      = $true
            grants_root        = $GrantsRoot
        }
    }
}

###############################################################################
# Check for ssh-keygen availability (ships with Windows 10+ OpenSSH feature)
###############################################################################

$sshKeygen = Get-Command ssh-keygen -ErrorAction SilentlyContinue
if ($null -eq $sshKeygen) {
    Emit-Error "WARNING: ssh-keygen not found; key type/fingerprint fields will be empty"
}

###############################################################################
# Scan current user private keys
###############################################################################

Emit-Error "INFO: scanning current user SSH private keys"

$userSshDir = Join-Path $env:USERPROFILE ".ssh"
if (Test-Path -Path $userSshDir -PathType Container) {
    Get-ChildItem -Path "$userSshDir\id_*" -ErrorAction SilentlyContinue | Where-Object {
        -not $_.Name.EndsWith('.pub')
    } | ForEach-Object {
        Emit-PrivateKey -FilePath $_.FullName
    }
}

###############################################################################
# Scan all user private keys (requires elevated access)
###############################################################################

Emit-Error "INFO: scanning all users' SSH private keys"

Get-ChildItem -Path "C:\Users\*\.ssh\id_*" -ErrorAction SilentlyContinue | Where-Object {
    -not $_.Name.EndsWith('.pub') -and $_.FullName -ne (Join-Path $userSshDir "")
} | ForEach-Object {
    Emit-PrivateKey -FilePath $_.FullName
}

###############################################################################
# Scan SSH host keys
###############################################################################

Emit-Error "INFO: scanning SSH host keys"

$hostKeyDir = "C:\ProgramData\ssh"
if (Test-Path -Path $hostKeyDir -PathType Container) {
    Get-ChildItem -Path "$hostKeyDir\ssh_host_*_key" -ErrorAction SilentlyContinue | Where-Object {
        -not $_.Name.EndsWith('.pub')
    } | ForEach-Object {
        Emit-PrivateKey -FilePath $_.FullName -GrantsRoot $true
    }
}

###############################################################################
# Scan authorized_keys files
###############################################################################

Emit-Error "INFO: scanning authorized_keys files"

# System-wide authorized_keys
$systemAuthKeys = "C:\ProgramData\ssh\administrators_authorized_keys"
if (Test-Path -Path $systemAuthKeys -PathType Leaf) {
    Emit-AuthorizedKeysFile -FilePath $systemAuthKeys -GrantsRoot $true
}

# Per-user authorized_keys
Get-ChildItem -Path "C:\Users\*\.ssh\authorized_keys" -ErrorAction SilentlyContinue | ForEach-Object {
    $owner = Get-FileOwner -FilePath $_.FullName
    $grantsRoot = Test-GrantsRoot -Owner $owner
    Emit-AuthorizedKeysFile -FilePath $_.FullName -GrantsRoot $grantsRoot
}
