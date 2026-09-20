<#
.SYNOPSIS
  Sign the Sopdet collector and regenerate the package manifest.

.DESCRIPTION
  Applies an Authenticode signature to the collector and the launcher, rebuilds
  MANIFEST.sha256 over the packaged files, and reports the resulting signature
  status.

.PARAMETER CertificateThumbprint
  Thumbprint of a code-signing certificate in CurrentUser\My or LocalMachine\My.

.PARAMETER TimestampServer
  RFC 3161 timestamp server. Defaults to DigiCert.

.PARAMETER Path
  Package root. Defaults to the parent of the tools folder.

.EXAMPLE
  .\tools\New-SignedPackage.ps1 -CertificateThumbprint 0123456789ABCDEF...
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CertificateThumbprint,

    [string]$TimestampServer = 'http://timestamp.digicert.com',

    [string]$Path = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'

$certificate = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
    Where-Object { $_.Thumbprint -eq $CertificateThumbprint } |
    Select-Object -First 1

if (-not $certificate) {
    throw "Code-signing certificate $CertificateThumbprint not found in CurrentUser\My or LocalMachine\My."
}

$targets = @(
    (Join-Path $Path 'Invoke-SopdetInventory.ps1'),
    (Join-Path $Path 'Run-Me.cmd')
) | Where-Object { Test-Path $_ }

foreach ($file in $targets) {
    Write-Output "Signing $file"
    $signature = Set-AuthenticodeSignature -FilePath $file -Certificate $certificate -TimestampServer $TimestampServer -HashAlgorithm SHA256
    if ($signature.Status -ne 'Valid') {
        throw "Signing failed for $file : $($signature.Status) $($signature.StatusMessage)"
    }
}

$manifestPath = Join-Path $Path 'MANIFEST.sha256'
$files = Get-ChildItem -Path $Path -Recurse -File |
    Where-Object { $_.Name -ne 'MANIFEST.sha256' -and $_.FullName -notmatch '\\last-run\.' -and $_.DirectoryName -notmatch '\\results$' } |
    Sort-Object FullName

$lines = foreach ($file in $files) {
    $relative = $file.FullName.Substring($Path.Length).TrimStart('\').Replace('\', '/')
    $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash.ToLower()
    "$hash  $relative"
}

Set-Content -Path $manifestPath -Value $lines -Encoding ASCII
Write-Output "Wrote $manifestPath ($($lines.Count) files)"

$verification = Get-AuthenticodeSignature -FilePath (Join-Path $Path 'Invoke-SopdetInventory.ps1')
Write-Output "Collector signature: $($verification.Status)"
