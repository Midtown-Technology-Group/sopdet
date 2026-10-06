<#
.SYNOPSIS
  Sign Sopdet Windows binaries with Azure Artifact Signing (Public or Private Trust).

.DESCRIPTION
  Copies each input file to -OutDir, signs it through Azure Artifact Signing using
  the signtool dlib interface, then verifies the signature. Configuration comes from
  explicit parameters, environment variables, then scripts/artifact-signing.env
  (in that order, independently for each setting).

.PARAMETER Profile
  Public or Private Trust certificate profile.

.PARAMETER File
  One or more files to sign (typically the Windows .exe builds).

.PARAMETER OutDir
  Directory to receive the signed copies. Inputs are left unsigned.

.PARAMETER SignToolPath
  Path to signtool.exe. Auto-detected from the Windows SDK if omitted.

.EXAMPLE
  ./scripts/sign-artifacts.ps1 -Profile Public -File bin/sopdet-windows-amd64.exe -OutDir dist/signed-public

.EXAMPLE
  ./scripts/sign-artifacts.ps1 -Profile Private -File bin/sopdet-windows-amd64.exe,bin/sopdet-windows-arm64.exe -OutDir dist/signed-private
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Public', 'Private')]
    [string]$Profile,

    [Parameter(Mandatory = $true)]
    [string[]]$File,

    [Parameter(Mandatory = $true)]
    [string]$OutDir,

    [string]$Endpoint,
    [string]$AccountName,
    [string]$CertificateProfileName,
    [string]$DlibPath,
    [string]$SignToolPath
)

$ErrorActionPreference = 'Stop'

$envFile = Join-Path $PSScriptRoot 'artifact-signing.env'
$envConfig = @{}
if (Test-Path $envFile) {
    Get-Content $envFile | Where-Object { $_ -match '^[A-Z].*=' } | ForEach-Object {
        $name, $value = $_ -split '=', 2
        $envConfig[$name.Trim()] = $value.Trim()
    }
}

function Resolve-SigningSetting {
    param([string]$Value, [string]$Name)

    if ($Value) { return $Value }
    $environmentValue = [Environment]::GetEnvironmentVariable($Name)
    if ($environmentValue) { return $environmentValue }
    return $envConfig[$Name]
}

$Endpoint = Resolve-SigningSetting -Value $Endpoint -Name 'ARTIFACT_SIGNING_ENDPOINT'
$AccountName = Resolve-SigningSetting -Value $AccountName -Name 'ARTIFACT_SIGNING_ACCOUNT'
$DlibPath = Resolve-SigningSetting -Value $DlibPath -Name 'ARTIFACT_SIGNING_DLIB_PATH'
$profileSetting = if ($Profile -eq 'Public') { 'ARTIFACT_SIGNING_CERT_PROFILE_PUBLIC' } else { 'ARTIFACT_SIGNING_CERT_PROFILE_PRIVATE' }
$CertificateProfileName = Resolve-SigningSetting -Value $CertificateProfileName -Name $profileSetting

if (-not $Endpoint -or -not $AccountName -or -not $CertificateProfileName -or -not $DlibPath) {
    throw 'Missing Artifact Signing configuration (endpoint, account, certificate profile, dlib).'
}
if (-not (Test-Path $DlibPath)) {
    throw "Artifact Signing dlib not found at $DlibPath"
}

if (-not $SignToolPath) {
    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($command) {
        $SignToolPath = $command.Source
    } else {
        $candidate = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | Select-Object -First 1
        if ($candidate) { $SignToolPath = $candidate.FullName }
    }
}
if (-not $SignToolPath -or -not (Test-Path $SignToolPath)) {
    throw 'signtool.exe not found. Pass -SignToolPath or install the Windows SDK.'
}

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }

$metadataPath = Join-Path $env:TEMP "artifact-signing-$Profile.json"
@{
    Endpoint                 = $Endpoint
    CodeSigningAccountName   = $AccountName
    CertificateProfileName   = $CertificateProfileName
} | ConvertTo-Json -Compress | Set-Content -Path $metadataPath -Encoding ascii

foreach ($source in $File) {
    if (-not (Test-Path $source)) { throw "Input file not found: $source" }
    $target = Join-Path $OutDir (Split-Path -Leaf $source)
    Copy-Item -Path $source -Destination $target -Force

    Write-Output "Signing $target ($Profile Trust: $CertificateProfileName)"
    & $SignToolPath sign /v /fd SHA256 /tr http://timestamp.acs.microsoft.com /td SHA256 /dlib $DlibPath /dmdf $metadataPath $target
    if ($LASTEXITCODE -ne 0) { throw "Signing failed for $target (exit $LASTEXITCODE)" }

    & $SignToolPath verify /pa /v $target
    if ($LASTEXITCODE -ne 0) { throw "Verification failed for $target (exit $LASTEXITCODE)" }
    Write-Output "  signed + verified"
}

Write-Output "Signed $($File.Count) file(s) into $OutDir"
