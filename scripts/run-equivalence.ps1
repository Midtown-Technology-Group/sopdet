#Requires -Version 3.0
<#
.SYNOPSIS
  Collects with the Go agent and the PowerShell agent back-to-back on this
  Windows host, validates both envelopes against the schema, and fails when
  the implementations diverge (cmd/equivcheck). Windows-only; see the
  equivalence-check make target and the CI equivalence job.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    Write-Output 'equivalence: Windows-only; skipping'
    exit 0
}

$root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$work = Join-Path ([IO.Path]::GetTempPath()) 'sopdet-equiv'
New-Item -ItemType Directory -Force -Path $work | Out-Null
$goExe = Join-Path $work 'sopdet-equiv.exe'
$goJson = Join-Path $work 'go.json'
$psJson = Join-Path $work 'ps.json'
$cfgPath = Join-Path $work 'equiv.config.json'

function Invoke-Native([string]$Label, [scriptblock]$Body) {
    Write-Output "equivalence: $Label"
    & $Body
    if ($LASTEXITCODE -ne 0) {
        throw "equivalence: step failed: $Label (exit $LASTEXITCODE)"
    }
}

function Invoke-Collect([string]$Label, [scriptblock]$Body, [string]$Output) {
    Write-Output "equivalence: $Label"
    if (Test-Path $Output) { Remove-Item $Output -Force }
    & $Body
    $produced = Get-Item $Output -ErrorAction SilentlyContinue
    if ($null -eq $produced -or $produced.Length -eq 0) {
        throw "equivalence: step failed: $Label (no output at $Output)"
    }
}

try {
    Push-Location $root
    try {
        # Unbudgeted runs: the size budget would summarize large entities and
        # break record-count parity. Go reads the budget from config only.
        @{ maxPayloadBytes = 20000000 } | ConvertTo-Json -Compress | Out-File -FilePath $cfgPath -Encoding utf8 -Force

        Invoke-Native 'build Go agent' { & go build -o $goExe ./cmd/sopdet }
        Invoke-Collect 'Go collect (full + includes)' {
            & $goExe -config $cfgPath -profile full -include-appx -include-processes -dry-run -quiet -out $goJson
        } $goJson
        Invoke-Collect 'PowerShell collect (full + includes)' {
            & "$root\powershell\Invoke-SopdetInventory.ps1" -CollectionProfile full -IncludeAppx -IncludeProcesses `
                -MaxPayloadBytes 20000000 -DryRun -OutputPath $psJson | Out-Null
        } $psJson
        Invoke-Native 'validate Go envelope' { & go run ./cmd/schemacheck schema/inventory.schema.json $goJson }
        Invoke-Native 'validate PowerShell envelope' { & go run ./cmd/schemacheck schema/inventory.schema.json $psJson }
        Invoke-Native 'compare envelopes' { & go run ./cmd/equivcheck -go $goJson -ps $psJson }
    } finally {
        Pop-Location
    }
    Write-Output "equivalence: envelopes compared (work dir: $work)"
} catch {
    throw
}
