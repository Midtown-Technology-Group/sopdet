<#
.SYNOPSIS
  Deploy the Sopdet Windows agent from the GitHub release channel.

.DESCRIPTION
  Downloads the unsigned Windows build from the rolling GitHub release (or an
  explicit URL), verifies its SHA-256 against the release MANIFEST.sha256,
  removes the mark-of-the-web, and then either reports the version, runs a
  one-shot inventory scan, or starts resident serve mode.

  Designed to run under NinjaOne as SYSTEM. Secrets (-ApiKey, -EnrollToken,
  -DeviceKey) are never written to logs or output.

.PARAMETER Url
  Binary to download. Defaults to the rolling unsigned GitHub release.

.PARAMETER ManifestUrl
  MANIFEST.sha256 used to verify the download. Pass -SkipVerify to disable.

.PARAMETER InstallDir
  Target directory. Defaults to C:\ProgramData\sopdet.

.PARAMETER ExpectedSha256
  Explicit hash to verify against, overriding the manifest.

.PARAMETER Profile
  Inventory profile for a one-shot scan: minimal, quick, or full.

.PARAMETER Endpoint
  Bifrost ingest endpoint for a one-shot scan.

.PARAMETER ApiKey
  Ingest key for a one-shot scan. Secret.

.PARAMETER Compress
  gzip+base64 the one-shot payload.

.PARAMETER DryRun
  Collect only; never post. Writes the envelope next to the binary.

.PARAMETER Serve
  Start resident serve mode instead of a one-shot scan.

.PARAMETER BifrostUrl
  Bifrost base URL for serve mode.

.PARAMETER EnrollToken
  One-time enrollment token for serve mode. Secret.

.PARAMETER DeviceKey
  Device key for serve mode. Secret.

.PARAMETER DownloadOnly
  Verify and stop before running the binary.

.EXAMPLE
  ./scripts/Deploy-Sopdet.ps1 -Profile minimal -DryRun

.EXAMPLE
  ./scripts/Deploy-Sopdet.ps1 -Endpoint https://bifrost.example.com/api/endpoints/<id> -ApiKey <key> -Profile quick -Compress

.EXAMPLE
  ./scripts/Deploy-Sopdet.ps1 -Serve -BifrostUrl https://bifrost.example.com -EnrollToken bfen_<id>_<secret>
#>
#Requires -Version 3.0
[CmdletBinding()]
param(
    [string]$Url = 'https://github.com/Midtown-Technology-Group/sopdet/releases/latest/download/sopdet-windows-amd64.exe',
    [string]$ManifestUrl = 'https://github.com/Midtown-Technology-Group/sopdet/releases/latest/download/MANIFEST.sha256',
    [string]$InstallDir = (Join-Path $env:ProgramData 'sopdet'),
    [string]$ExpectedSha256,
    [ValidateSet('minimal', 'quick', 'full')]
    [Alias('Profile')]
    [string]$CollectionProfile = 'quick',
    [string]$Endpoint,
    [string]$ApiKey = $env:SOPDET_API_KEY,
    [switch]$Compress,
    [switch]$DryRun,
    [switch]$IncludeProcesses,
    [switch]$IncludeAppx,
    [switch]$Serve,
    [string]$BifrostUrl = $env:SOPDET_BIFROST_URL,
    [string]$EnrollToken = $env:SOPDET_ENROLLMENT_TOKEN,
    [string]$DeviceKey = $env:SOPDET_DEVICE_KEY,
    [switch]$SkipVerify,
    [switch]$DownloadOnly
)

$ErrorActionPreference = 'Stop'

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch {
    Write-Verbose "could not set TLS 1.2: $($_.Exception.Message)"
}

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        try {
            $bytes = $sha.ComputeHash($stream)
        } finally {
            $stream.Dispose()
        }
    } finally {
        $sha.Dispose()
    }
    return ([BitConverter]::ToString($bytes) -replace '-', '').ToLowerInvariant()
}

function Get-ManifestHash {
    param([Parameter(Mandatory = $true)][string]$Manifest, [Parameter(Mandatory = $true)][string]$FileName)
    foreach ($line in ($Manifest -split "`n")) {
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }
        $parts = $trimmed -split '\s+', 2
        if ($parts.Count -eq 2 -and $parts[1].Trim() -eq $FileName) {
            return $parts[0].Trim().ToLowerInvariant()
        }
    }
    return $null
}

$asset = Split-Path -Leaf ([Uri]$Url).AbsolutePath
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}
$exe = Join-Path $InstallDir 'sopdet.exe'

Write-Output "downloading $asset"
Invoke-WebRequest -Uri $Url -OutFile $exe -UseBasicParsing -TimeoutSec 120

$actual = Get-Sha256Hex -Path $exe
$expected = $ExpectedSha256
if (-not $expected -and -not $SkipVerify) {
    try {
        $manifestRaw = (Invoke-WebRequest -Uri $ManifestUrl -UseBasicParsing -TimeoutSec 60).Content
        if ($manifestRaw -is [byte[]]) {
            $manifest = [System.Text.Encoding]::UTF8.GetString($manifestRaw)
        } else {
            $manifest = [string]$manifestRaw
        }
        $expected = Get-ManifestHash -Manifest $manifest -FileName $asset
    } catch {
        Write-Output "manifest unavailable: $($_.Exception.Message)"
    }
}
$verified = $false
if ($expected) {
    $verified = ($actual -eq $expected.ToLowerInvariant())
    if (-not $verified) {
        Remove-Item -Path $exe -Force -ErrorAction SilentlyContinue
        throw "checksum mismatch for $asset (expected $expected, got $actual)"
    }
} elseif (-not $SkipVerify) {
    Remove-Item -Path $exe -Force -ErrorAction SilentlyContinue
    throw "could not verify ${asset}: no manifest hash and no -ExpectedSha256 (use -SkipVerify to bypass)"
}

if (Get-Command Unblock-File -ErrorAction SilentlyContinue) {
    Unblock-File -Path $exe -ErrorAction SilentlyContinue
}
$version = (& $exe -version 2>&1 | Out-String).Trim()

$result = [ordered]@{
    status    = 'downloaded'
    asset     = $asset
    path      = $exe
    bytes     = (Get-Item $exe).Length
    sha256    = $actual
    verified  = $verified
    version   = $version
    installed = $true
}

if ($DownloadOnly) {
    [pscustomobject]$result | ConvertTo-Json -Compress
    return
}

if ($Serve) {
    if (-not $BifrostUrl) { throw '-Serve requires -BifrostUrl' }
    $exeArgs = @('-serve', '-bifrost-url', $BifrostUrl)
    if ($EnrollToken) { $exeArgs += @('-enroll-token', $EnrollToken) }
    if ($DeviceKey) { $exeArgs += @('-device-key', $DeviceKey) }
    $result.status = 'serve-started'
} else {
    $exeArgs = @('-profile', $CollectionProfile)
    if ($Endpoint) { $exeArgs += @('-endpoint', $Endpoint) }
    if ($ApiKey) { $exeArgs += @('-api-key', $ApiKey) }
    if ($Compress) { $exeArgs += '-compress' }
    if ($DryRun) { $exeArgs += @('-dry-run', '-out', (Join-Path $InstallDir 'last-scan.json')) }
    if ($IncludeProcesses) { $exeArgs += '-include-processes' }
    if ($IncludeAppx) { $exeArgs += '-include-appx' }
    $result.status = 'scan-complete'
}

$logPath = Join-Path $InstallDir 'deploy-run.log'
$output = (& $exe @exeArgs 2>&1 | Out-String)
$output | Set-Content -Path $logPath -Encoding UTF8
$result.log = $logPath
$result.exit_code = $LASTEXITCODE

[pscustomobject]$result | ConvertTo-Json -Compress
