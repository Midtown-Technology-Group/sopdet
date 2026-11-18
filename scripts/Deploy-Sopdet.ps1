<#
.SYNOPSIS
  Deploy the Sopdet Windows agent from the GitHub release channel.

.DESCRIPTION
  Downloads the Windows build from the rolling GitHub release (or an explicit
  URL), verifies its SHA-256 against an operator-supplied out-of-band pin,
  removes the mark-of-the-web, and then either reports the version, runs a
  one-shot inventory scan, or starts resident serve mode.

  Designed to run under NinjaOne as SYSTEM. Supply secrets through
  SOPDET_API_KEY, SOPDET_ENROLLMENT_TOKEN, and SOPDET_DEVICE_KEY environment
  variables so they are not copied into the collector command line.

.PARAMETER Url
  Binary to download. Defaults to the rolling unsigned GitHub release.

.PARAMETER InstallDir
  Target directory. Defaults to C:\ProgramData\sopdet.

.PARAMETER ExpectedSha256
  Required SHA-256 obtained from a trusted source separate from the download.

.PARAMETER Profile
  Inventory profile for a one-shot scan: minimal, quick, or full.

.PARAMETER Endpoint
  Bifrost ingest endpoint for a one-shot scan.

.PARAMETER Compress
  gzip+base64 the one-shot payload.

.PARAMETER DryRun
  Collect only; never post. Writes the envelope next to the binary.

.PARAMETER Serve
  Start resident serve mode instead of a one-shot scan.

.PARAMETER BifrostUrl
  Bifrost base URL for serve mode.

.PARAMETER DownloadOnly
  Verify and stop before running the binary.

.EXAMPLE
  ./scripts/Deploy-Sopdet.ps1 -ExpectedSha256 <64-character-sha256> -Profile minimal -DryRun

.EXAMPLE
  Set SOPDET_API_KEY in the deployment environment, then run:
  ./scripts/Deploy-Sopdet.ps1 -ExpectedSha256 <64-character-sha256> -Endpoint https://bifrost.example.com/api/endpoints/<id> -Profile quick -Compress

.EXAMPLE
  Set SOPDET_ENROLLMENT_TOKEN in the deployment environment, then run:
  ./scripts/Deploy-Sopdet.ps1 -ExpectedSha256 <64-character-sha256> -Serve -BifrostUrl https://bifrost.example.com
#>
#Requires -Version 3.0
[CmdletBinding()]
param(
    [string]$Url = 'https://github.com/Midtown-Technology-Group/sopdet/releases/latest/download/sopdet-windows-amd64.exe',
    [string]$InstallDir = (Join-Path $env:ProgramData 'sopdet'),
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$ExpectedSha256,
    [ValidateSet('minimal', 'quick', 'full')]
    [Alias('Profile')]
    [string]$CollectionProfile = 'quick',
    [string]$Endpoint,
    [switch]$Compress,
    [switch]$DryRun,
    [switch]$IncludeProcesses,
    [switch]$IncludeAppx,
    [switch]$Serve,
    [string]$BifrostUrl = $env:SOPDET_BIFROST_URL,
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

$asset = Split-Path -Leaf ([Uri]$Url).AbsolutePath
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}
$exe = Join-Path $InstallDir 'sopdet.exe'

Write-Output "downloading $asset"
Invoke-WebRequest -Uri $Url -OutFile $exe -UseBasicParsing -TimeoutSec 120

$actual = Get-Sha256Hex -Path $exe
$expected = $ExpectedSha256.ToLowerInvariant()
if ($actual -ne $expected) {
    Remove-Item -Path $exe -Force -ErrorAction SilentlyContinue
    throw "checksum mismatch for $asset (expected $expected, got $actual)"
}
$verified = $true

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
    $result.status = 'serve-started'
} else {
    $exeArgs = @('-profile', $CollectionProfile)
    if ($Endpoint) { $exeArgs += @('-endpoint', $Endpoint) }
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
