<#
.SYNOPSIS
  Sign Sopdet Windows binaries with Azure Artifact Signing (Public or Private Trust).

.DESCRIPTION
  Copies each input file to -OutDir, signs it through Azure Artifact Signing using
  the signtool dlib interface, then verifies the signature. Configuration comes from
  scripts/artifact-signing.env or explicit parameters.

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

    [string]$Endpoint = $env:ARTIFACT_SIGNING_ENDPOINT,
    [string]$AccountName = $env:ARTIFACT_SIGNING_ACCOUNT,
    [string]$CertificateProfileName,
    [string]$DlibPath = $env:ARTIFACT_SIGNING_DLIB_PATH,
    [string]$SignToolPath
)

$ErrorActionPreference = 'Stop'

$envFile = Join-Path $PSScriptRoot 'artifact-signing.env'
if (Test-Path $envFile) {
    Get-Content $envFile | Where-Object { $_ -match '^[A-Z].*=' } | ForEach-Object {
        $name, $value = $_ -split '=', 2
        Set-Variable -Name $name.Trim() -Value $value.Trim() -Scope Script
    }
}

if (-not $CertificateProfileName) {
    $CertificateProfileName = if ($Profile -eq 'Public') {
        $script:ARTIFACT_SIGNING_CERT_PROFILE_PUBLIC
    } else {
        $script:ARTIFACT_SIGNING_CERT_PROFILE_PRIVATE
    }
}

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
