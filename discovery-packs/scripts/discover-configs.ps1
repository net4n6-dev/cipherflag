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
# CipherFlag — crypto configuration discovery script for Windows.
# Scans sshd_config, Schannel registry protocols, and openssl.cnf files.
# Output: NDJSON to stdout. Diagnostics to stderr.

. "$PSScriptRoot\lib\output-format.ps1"

###############################################################################
# Helper: extract a directive value from an OpenSSH-style config file.
# Handles "Key value" and "Key = value" syntax; skips comment lines.
###############################################################################

function Get-ConfigValue {
    param(
        [string]$FilePath,
        [string]$Key
    )
    $pattern = "^\s*${Key}\s*=?\s*(.+)$"
    $lines = Get-Content -Path $FilePath -ErrorAction SilentlyContinue
    if ($null -eq $lines) { return "" }
    foreach ($line in $lines) {
        if ($line.TrimStart().StartsWith('#')) { continue }
        if ($line -match $pattern) {
            return $Matches[1].Trim()
        }
    }
    return ""
}

###############################################################################
# 1. sshd_config  (C:\ProgramData\ssh\sshd_config)
###############################################################################

$sshdConfig = "C:\ProgramData\ssh\sshd_config"

if (Test-Path -Path $sshdConfig -PathType Leaf) {
    Emit-Error "INFO: scanning sshd_config: $sshdConfig"

    Emit-Json @{
        type        = "config"
        config_type = "sshd_config"
        file_path   = $sshdConfig
        settings    = @{
            Ciphers                 = (Get-ConfigValue -FilePath $sshdConfig -Key "Ciphers")
            MACs                    = (Get-ConfigValue -FilePath $sshdConfig -Key "MACs")
            KexAlgorithms           = (Get-ConfigValue -FilePath $sshdConfig -Key "KexAlgorithms")
            HostKeyAlgorithms       = (Get-ConfigValue -FilePath $sshdConfig -Key "HostKeyAlgorithms")
            PasswordAuthentication  = (Get-ConfigValue -FilePath $sshdConfig -Key "PasswordAuthentication")
        }
    }
}
else {
    Emit-Error "INFO: sshd_config not found at $sshdConfig"
}

###############################################################################
# 2. Schannel registry — SSL/TLS protocol enable/disable state
#
# Registry tree:
#   HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\<name>\<Client|Server>
#     Enabled    (DWORD)  — 0 = disabled, 1 or absent = enabled
#     DisabledByDefault (DWORD)
###############################################################################

$schannelRoot = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

Emit-Error "INFO: scanning Schannel protocol registry"

if (Test-Path -Path $schannelRoot) {
    $protocols = Get-ChildItem -Path $schannelRoot -ErrorAction SilentlyContinue
    foreach ($proto in $protocols) {
        $protoName = $proto.PSChildName

        $roles = Get-ChildItem -Path $proto.PSPath -ErrorAction SilentlyContinue
        foreach ($role in $roles) {
            $roleName = $role.PSChildName
            $props = Get-ItemProperty -Path $role.PSPath -ErrorAction SilentlyContinue

            $enabled = if ($null -ne $props -and $null -ne $props.Enabled) {
                [bool]($props.Enabled -ne 0)
            }
            else {
                # Key absent means enabled by default
                $true
            }

            $disabledByDefault = if ($null -ne $props -and $null -ne $props.DisabledByDefault) {
                [bool]($props.DisabledByDefault -ne 0)
            }
            else {
                $false
            }

            Emit-Json @{
                type                 = "config"
                config_type          = "schannel_protocol"
                file_path            = $role.PSPath
                settings             = @{
                    protocol             = $protoName
                    role                 = $roleName
                    enabled              = $enabled
                    disabled_by_default  = $disabledByDefault
                }
            }
        }
    }
}
else {
    Emit-Error "INFO: Schannel Protocols registry key not found (may be default/unconfigured)"
}

###############################################################################
# 3. openssl.cnf  (C:\Program Files\OpenSSL*\openssl.cnf)
###############################################################################

Emit-Error "INFO: scanning openssl.cnf files"

$opensslCnfPaths = Get-ChildItem -Path "C:\Program Files\OpenSSL*\openssl.cnf" -ErrorAction SilentlyContinue

foreach ($cnfFile in $opensslCnfPaths) {
    Emit-Error "INFO: scanning openssl.cnf: $($cnfFile.FullName)"

    $defaultMd   = Get-ConfigValue -FilePath $cnfFile.FullName -Key "default_md"
    $defaultBits = Get-ConfigValue -FilePath $cnfFile.FullName -Key "default_bits"

    # Detect FIPS mode: fips_mode = yes  or  openssl_conf = fips_provider
    $fipsMode = $false
    $cnfContent = Get-Content -Path $cnfFile.FullName -ErrorAction SilentlyContinue -Raw
    if ($cnfContent -match 'fips_mode\s*=\s*yes' -or $cnfContent -match 'openssl_conf\s*=\s*fips') {
        $fipsMode = $true
    }

    Emit-Json @{
        type        = "config"
        config_type = "openssl_cnf"
        file_path   = $cnfFile.FullName
        settings    = @{
            default_md   = $defaultMd
            default_bits = $defaultBits
            fips_mode    = $fipsMode
        }
    }
}

if ($null -eq $opensslCnfPaths -or @($opensslCnfPaths).Count -eq 0) {
    Emit-Error "INFO: no openssl.cnf files found under C:\Program Files\OpenSSL*"
}
