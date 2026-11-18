<#
.SYNOPSIS
  Operator-driven, one-hop deployment of the read-only Sopdet collector.

.DESCRIPTION
  Copies the signed collector (and its config) to each explicitly named target,
  runs it once, optionally collects the JSON result, and writes an audit log.
  It never discovers targets, never scans ranges, and never re-invokes itself
  on a remote host. Use only on assets covered by a signed authorization.

.PARAMETER Target
  One or more explicit hostnames or IP addresses. CIDR ranges are rejected.

.PARAMETER TargetFile
  Path to a newline-delimited list of hosts (# comments and blanks ignored).

.PARAMETER AuthorizationRef
  Mandatory reference to the signed scope/consent. The run refuses without it.

.PARAMETER CollectorPath
  Path to Invoke-SopdetInventory.ps1. Defaults to the packaged collector.

.PARAMETER ExpectedCollectorSha256
  Required SHA-256 obtained from a trusted source separate from CollectorPath.

.PARAMETER ConfigPath
  Optional inventory.config.json copied alongside the collector.

.PARAMETER Credential
  Admin credential for the targets. Use -UseCurrentSession instead to reuse
  the operator's session.

.PARAMETER RemoteDirectory
  Target-side working directory. Default C:\ProgramData\Sopdet.

.PARAMETER CollectionProfile
  Collector profile: minimal, quick, or full.

.PARAMETER KillSwitchPath
  If this file exists, the run aborts before touching any target.

.PARAMETER SkipResultCollection
  Do not copy result JSON files back to the operator.

.PARAMETER RemoveRemoteFiles
  Delete the deployed collector and config from each target afterwards.

.EXAMPLE
  .\Invoke-SopdetFanout.ps1 -TargetFile .\targets.txt -AuthorizationRef ENG-2026-014 `
      -ExpectedCollectorSha256 <64-character-sha256> `
      -Credential (Get-Credential) -CollectionProfile quick -Confirm
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string[]]$Target,
    [string]$TargetFile,
    [Parameter(Mandatory = $true)][string]$AuthorizationRef,
    [string]$CollectorPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'Invoke-SopdetInventory.ps1'),
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$ExpectedCollectorSha256,
    [string]$ConfigPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'inventory.config.json'),
    [System.Management.Automation.PSCredential]$Credential,
    [string]$RemoteDirectory = 'C:\ProgramData\Sopdet',
    [ValidateSet('minimal', 'quick', 'full')][string]$CollectionProfile = 'quick',
    [string]$ResultDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) 'results'),
    [string]$AuditPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'results\fanout-audit.jsonl'),
    [string]$KillSwitchPath,
    [int]$ThrottleMilliseconds = 750,
    [switch]$UseCurrentSession,
    [switch]$SkipResultCollection,
    [switch]$RemoveRemoteFiles
)

$ErrorActionPreference = 'Stop'

function Write-AuditRecord {
    param(
        [Parameter(Mandatory = $true)][string]$AuditFile,
        [Parameter(Mandatory = $true)][string]$Authorization,
        [Parameter(Mandatory = $true)][string]$Computer,
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][string]$Status,
        [string]$Detail,
        [string]$CollectorHash
    )
    $directory = Split-Path -Parent $AuditFile
    if (-not (Test-Path $directory)) {
        New-Item -ItemType Directory -Force -Path $directory | Out-Null
    }
    $entry = [ordered]@{
        ts               = (Get-Date).ToUniversalTime().ToString('o')
        operator         = "$env:USERDOMAIN\$env:USERNAME"
        authorization    = $Authorization
        target           = $Computer
        transport        = $Mode
        status           = $Status
        detail           = $Detail
        collector_sha256 = $CollectorHash
    }
    ($entry | ConvertTo-Json -Compress) | Add-Content -Path $AuditFile -Encoding UTF8
}

function Invoke-TargetViaWinRm {
    param(
        [Parameter(Mandatory = $true)][string]$Computer,
        [Parameter(Mandatory = $true)][string]$Collector,
        [string]$Config,
        [Parameter(Mandatory = $true)][string]$RemoteDir,
        [Parameter(Mandatory = $true)][string]$Profile,
        [Parameter(Mandatory = $true)][string]$Results,
        [System.Management.Automation.PSCredential]$Cred,
        [switch]$CurrentSession,
        [switch]$SkipCollect,
        [switch]$Cleanup
    )
    $sessionArgs = @{ ComputerName = $Computer; ErrorAction = 'Stop' }
    if (-not $CurrentSession) { $sessionArgs['Credential'] = $Cred }
    $session = New-PSSession @sessionArgs
    try {
        Invoke-Command -Session $session -ScriptBlock { New-Item -ItemType Directory -Force -Path $using:RemoteDir | Out-Null }
        Copy-Item -Path $Collector -Destination $RemoteDir -ToSession $session -Force
        if ($Config -and (Test-Path $Config)) { Copy-Item -Path $Config -Destination $RemoteDir -ToSession $session -Force }

        $remoteOut = Join-Path $RemoteDir ("$Computer.json")
        $exitCode = Invoke-Command -Session $session -ArgumentList @($RemoteDir, $Profile, $remoteOut) -ScriptBlock {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $args[0] 'Invoke-SopdetInventory.ps1') -Profile $args[1] -OutputPath $args[2] | Out-Null
            $LASTEXITCODE
        }

        $localCopy = $null
        if (-not $SkipCollect) {
            if (-not (Test-Path $Results)) { New-Item -ItemType Directory -Force -Path $Results | Out-Null }
            $localCopy = Join-Path $Results ("$Computer.json")
            try { Copy-Item -Path $remoteOut -Destination $localCopy -FromSession $session -Force } catch { $localCopy = $null }
        }
        if ($Cleanup) {
            Invoke-Command -Session $session -ScriptBlock { Remove-Item -Path $using:RemoteDir -Recurse -Force -ErrorAction SilentlyContinue }
        }
        return [pscustomobject]@{ ExitCode = $exitCode; ResultPath = $localCopy }
    } finally {
        if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
    }
}

if ($KillSwitchPath -and (Test-Path $KillSwitchPath)) {
    throw "Kill switch present at $KillSwitchPath; aborting."
}
if (-not (Test-Path $CollectorPath)) {
    throw "Collector not found at $CollectorPath."
}
$collectorHash = (Get-FileHash -Path $CollectorPath -Algorithm SHA256).Hash.ToLower()
if ($collectorHash -ne $ExpectedCollectorSha256.ToLowerInvariant()) {
    throw "Collector SHA-256 does not match the trusted pin."
}

$computers = @()
if ($Target) { $computers += $Target }
if ($TargetFile) {
    if (-not (Test-Path $TargetFile)) { throw "Target file not found: $TargetFile" }
    $computers += Get-Content $TargetFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') }
}
$computers = $computers | Select-Object -Unique
foreach ($c in $computers) {
    if ($c -match '[/,\s*]') { throw "Target '$c' looks like a range/pattern. Provide explicit hosts only." }
}
if (-not $computers) { throw 'No targets supplied. Provide -Target or -TargetFile.' }
if (-not $UseCurrentSession -and -not $Credential) { throw 'Provide -Credential or -UseCurrentSession.' }

Write-Output "Authorization : $AuthorizationRef"
Write-Output "Collector     : $CollectorPath ($($collectorHash.Substring(0,12))...)"
Write-Output "Transport     : WinRM"
Write-Output "Targets       : $($computers.Count)"
Write-Output "Audit         : $AuditPath"

$results = New-Object System.Collections.Generic.List[object]
foreach ($computer in $computers) {
    if (-not $PSCmdlet.ShouldProcess($computer, 'Deploy and run read-only inventory via WinRM')) { continue }
    try {
        $common = @{
            Computer   = $computer
            Collector  = $CollectorPath
            Config     = $ConfigPath
            RemoteDir  = $RemoteDirectory
            Profile    = $CollectionProfile
            Results    = $ResultDirectory
            SkipCollect = $SkipResultCollection
            Cleanup    = $RemoveRemoteFiles
        }
        $outcome = Invoke-TargetViaWinRm @common -Cred $Credential -CurrentSession:$UseCurrentSession
        Write-Output "[ok]   $computer  exit=$($outcome.ExitCode)  result=$($outcome.ResultPath)"
        Write-AuditRecord -AuditFile $AuditPath -Authorization $AuthorizationRef -Computer $computer -Mode 'WinRM' -Status 'success' -Detail "exit=$($outcome.ExitCode); result=$($outcome.ResultPath)" -CollectorHash $collectorHash
        $results.Add([pscustomobject]@{ Target = $computer; Status = 'success'; ExitCode = $outcome.ExitCode; ResultPath = $outcome.ResultPath })
    } catch {
        Write-Warning "[fail] $computer  $($_.Exception.Message)"
        Write-AuditRecord -AuditFile $AuditPath -Authorization $AuthorizationRef -Computer $computer -Mode 'WinRM' -Status 'failed' -Detail $_.Exception.Message -CollectorHash $collectorHash
        $results.Add([pscustomobject]@{ Target = $computer; Status = 'failed'; Error = $_.Exception.Message })
    }
    Start-Sleep -Milliseconds ($ThrottleMilliseconds + (Get-Random -Maximum 500))
}

$ok = ($results | Where-Object Status -eq 'success').Count
Write-Output "Completed: $ok/$($results.Count) succeeded."
$results
