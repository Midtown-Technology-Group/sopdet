<#
.SYNOPSIS
  Build a supplemental App Control (WDAC) policy that allows Sopdet by publisher.

.DESCRIPTION
  Generates a publisher-scoped supplemental policy from the signed Sopdet
  binaries, bound to an existing base policy, for deployment via Intune. This is
  required in addition to code signing when a fleet enforces application control
  (for example the Intune + Huntress policies seen on hardened endpoints).

  Requires the ConfigCI module (Windows ADK "Application Control" / WDAC
  tooling). Run on a Windows machine where the signed binaries are available.

.PARAMETER SignedPath
  Directory containing the signed sopdet-windows-*.exe files.

.PARAMETER BasePolicyId
  PolicyID (GUID) of the base App Control policy this supplemental extends.

.PARAMETER OutFile
  Output XML path.

.PARAMETER PolicyName
  Friendly policy name.

.EXAMPLE
  ./scripts/New-AppControlPolicy.ps1 -SignedPath dist/signed-private `
      -BasePolicyId {1283AC0F-FFF1-49AE-ADA1-8A933130CAD6} -OutFile sopdet-supplemental.xml
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SignedPath,
    [Parameter(Mandatory = $true)][string]$BasePolicyId,
    [string]$OutFile = 'sopdet-appcontrol-supplemental.xml',
    [string]$PolicyName = 'Sopdet Publisher Allow'
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Command New-CIPolicy -ErrorAction SilentlyContinue)) {
    throw "ConfigCI module not found. Install the Windows ADK 'Windows Defender Application Control' tooling."
}
if (-not (Test-Path $SignedPath)) {
    throw "Signed binaries path not found: $SignedPath"
}

$binaries = Get-ChildItem -Path $SignedPath -Filter 'sopdet-windows-*.exe' -File
if (-not $binaries) {
    throw "No signed sopdet-windows-*.exe found in $SignedPath"
}

Write-Output "Building publisher-scoped supplemental policy from $($binaries.Count) binary(ies)..."
New-CIPolicy -FilePath $OutFile -Level Publisher -Fallback Hash -UserPEs -ScanPath $SignedPath -MultiplePolicyFormat -PolicyName $PolicyName

Set-CIPolicyIdInfo -FilePath $OutFile -PolicyName $PolicyName
Set-CIPolicyIdInfo -FilePath $OutFile -SupplementsBasePolicyID $BasePolicyId
Set-CIPolicyVersion -FilePath $OutFile -Version '1.0.0.0'

Write-Output "Wrote $OutFile"
Write-Output "Deploy via Intune: Devices > Configuration > App Control for Business (supplemental policy),"
Write-Output "or a custom OMA-URI policy at ./Vendor/MSFT/ApplicationControl/CiPolicies/<name>."
Write-Output "See docs/appcontrol.md."
