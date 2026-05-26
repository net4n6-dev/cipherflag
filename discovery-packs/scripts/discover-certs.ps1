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
# CipherFlag — certificate discovery script for Windows.
# Scans Windows Certificate Store for installed certificates.
# Output: NDJSON to stdout. Diagnostics to stderr.

. "$PSScriptRoot\lib\output-format.ps1"

$certStores = @(
    "Cert:\LocalMachine\My",
    "Cert:\LocalMachine\Root",
    "Cert:\LocalMachine\CA",
    "Cert:\CurrentUser\My"
)

foreach ($storePath in $certStores) {
    Emit-Error "INFO: scanning certificate store: $storePath"

    try {
        $certs = Get-ChildItem -Path $storePath -ErrorAction SilentlyContinue
    }
    catch {
        Emit-Error "Cannot access ${storePath}: $_"
        continue
    }

    foreach ($cert in $certs) {
        try {
            $fp = $cert.GetCertHashString("SHA256").ToLower()
        }
        catch {
            Emit-Error "SKIP (cannot hash): $($cert.Subject)"
            continue
        }

        $subjectCN = if ($cert.Subject -match "CN=([^,]+)") { $Matches[1].Trim() } else { "" }
        $issuerCN  = if ($cert.Issuer  -match "CN=([^,]+)") { $Matches[1].Trim() } else { "" }

        $keyAlg = switch -Wildcard ($cert.PublicKey.Oid.FriendlyName) {
            "RSA"     { "RSA" }
            "ECC"     { "ECDSA" }
            "ECDsa*"  { "ECDSA" }
            "DSA"     { "DSA" }
            default   { $cert.PublicKey.Oid.FriendlyName }
        }

        $keySize = try { $cert.PublicKey.Key.KeySize } catch { 0 }

        Emit-Json @{
            type                = "certificate"
            fingerprint_sha256  = $fp
            subject_cn          = $subjectCN
            issuer_cn           = $issuerCN
            not_before          = $cert.NotBefore.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            not_after           = $cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            key_algorithm       = $keyAlg
            key_size            = $keySize
            signature_algorithm = $cert.SignatureAlgorithm.FriendlyName
            serial_number       = $cert.SerialNumber
            file_path           = $storePath
            store_type          = "windows_store"
        }
    }
}
