<#
.SYNOPSIS
  Exercise signing configuration and invocation without credentials or signing requests.
#>
[CmdletBinding()]
param([string]$CoveragePath, [switch]$CoverageChild, [hashtable]$CoverageState)

$ErrorActionPreference = 'Stop'

function Measure-SigningLine {
    param([string]$ScriptPath, [string]$ReportPath)

    $parseErrors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors) { throw "Cannot measure coverage for $ScriptPath" }
    foreach ($command in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandBaseAst] }, $true)) {
        $extent = $command.Extent
        [pscustomobject]@{
            ReportPath = $ReportPath
            Breakpoint = Set-PSBreakpoint -Script $ScriptPath -Line $extent.StartLineNumber -Column $extent.StartColumnNumber -Action { }
        }
    }
}

# Re-enter with breakpoints already installed so setup and cleanup are measured too.
# Coverage uses real debugger HitCount values, never inferred hits from test success.
if ($CoveragePath -and -not $CoverageChild) {
    $coverage = @{ Entries = @(Measure-SigningLine -ScriptPath $PSCommandPath -ReportPath 'scripts/test-sign-artifacts.ps1') }
    try {
        & $PSCommandPath -CoveragePath $CoveragePath -CoverageChild -CoverageState $coverage
        $writer = [System.Xml.XmlWriter]::Create([IO.Path]::GetFullPath($CoveragePath))
        try {
            $writer.WriteStartElement('coverage')
            $writer.WriteAttributeString('version', '1')
            foreach ($fileGroup in $coverage.Entries | Group-Object ReportPath) {
                $writer.WriteStartElement('file')
                $writer.WriteAttributeString('path', $fileGroup.Name)
                foreach ($lineGroup in $fileGroup.Group | Group-Object { $_.Breakpoint.Line } | Sort-Object { [int]$_.Name }) {
                    $covered = @($lineGroup.Group | Where-Object { $_.Breakpoint.HitCount -gt 0 }).Count -gt 0
                    $writer.WriteStartElement('lineToCover')
                    $writer.WriteAttributeString('lineNumber', $lineGroup.Name)
                    $writer.WriteAttributeString('covered', $covered.ToString().ToLowerInvariant())
                    $writer.WriteEndElement()
                }
                $writer.WriteEndElement()
            }
            $writer.WriteEndElement()
        } finally { $writer.Dispose() }
        Write-Output "Measured signing line coverage: $CoveragePath"
    } finally { $coverage.Entries.Breakpoint | Remove-PSBreakpoint }
    return
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('sopdet signing test ' + [guid]::NewGuid())
$settings = @(
    'ARTIFACT_SIGNING_ENDPOINT', 'ARTIFACT_SIGNING_ACCOUNT',
    'ARTIFACT_SIGNING_CERT_PROFILE_PUBLIC', 'ARTIFACT_SIGNING_CERT_PROFILE_PRIVATE',
    'ARTIFACT_SIGNING_DLIB_PATH', 'SOPDET_SIGNING_TEST_LOG', 'TEMP'
)
$savedEnvironment = @{}
foreach ($name in $settings) { $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name) }

function Test-SigningConfiguration {
    param($Sign, [string]$Label, [hashtable]$Expected)

    foreach ($key in @('Endpoint', 'CodeSigningAccountName', 'CertificateProfileName')) {
        if ($Sign.Metadata.$key -ne $Expected[$key]) { throw "$Label resolved the wrong $key" }
    }
    if ($Sign.Dlib -ne $Expected.Dlib) { throw "$Label resolved the wrong dlib" }
}

function Test-SigningResult {
    param([string]$Label, [hashtable]$Expected)

    $calls = @(Get-Content -LiteralPath $env:SOPDET_SIGNING_TEST_LOG | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
    if ($calls.Count -ne 4) { throw "$Label expected sign + verify for both files, got $($calls.Count) calls" }
    for ($i = 0; $i -lt 2; $i++) {
        $sign = $calls[$i * 2]
        $verify = $calls[$i * 2 + 1]
        if ($sign.Arguments[0] -ne 'sign' -or $verify.Arguments[0] -ne 'verify') {
            throw "$Label did not sign then verify each file"
        }
        Test-SigningConfiguration -Sign $sign -Label $Label -Expected $Expected
        $target = $sign.Arguments[-1]
        if ((Split-Path -Leaf $target) -ne (Split-Path -Leaf $inputFiles[$i]) -or $verify.Arguments[-1] -ne $target) {
            throw "$Label lost or misbound an input file"
        }
        if ((Get-Content -Raw -LiteralPath $target) -ne (Get-Content -Raw -LiteralPath $inputFiles[$i])) {
            throw "$Label did not copy the synthetic input"
        }
    }
    Write-Output "PASS: $Label"
}

try {
    New-Item -ItemType Directory -Path (Join-Path $testRoot 'scripts'), (Join-Path $testRoot 'bin') -Force | Out-Null
    $helperPath = Join-Path $testRoot 'scripts/sign-artifacts.ps1'
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'sign-artifacts.ps1') -Destination $helperPath
    if ($CoverageChild) {
        if ((Get-FileHash $helperPath).Hash -ne (Get-FileHash (Join-Path $PSScriptRoot 'sign-artifacts.ps1')).Hash) { throw 'Coverage helper differs from source' }
        $CoverageState.Entries += @(Measure-SigningLine -ScriptPath $helperPath -ReportPath 'scripts/sign-artifacts.ps1')
    }
    $envFile = Join-Path $testRoot 'scripts/artifact-signing.env'
    $stubPath = Join-Path $testRoot 'fake-signtool.ps1'
    @'
$metadata = $null
$dlib = $null
if ($args[0] -eq 'sign') {
    $metadata = Get-Content -Raw -LiteralPath $args[[array]::IndexOf($args, '/dmdf') + 1] | ConvertFrom-Json
    $dlib = $args[[array]::IndexOf($args, '/dlib') + 1]
}
@{ Arguments = @($args); Metadata = $metadata; Dlib = $dlib } |
    ConvertTo-Json -Depth 5 -Compress | Add-Content -LiteralPath $env:SOPDET_SIGNING_TEST_LOG
exit 0
'@ | Set-Content -LiteralPath $stubPath
    $inputFiles = @('sopdet-windows-amd64.exe', 'sopdet-windows-arm64.exe') | ForEach-Object {
        $path = Join-Path $testRoot "bin/$_"
        'synthetic unsigned input' | Set-Content -LiteralPath $path
        $path
    }
    $fileDlib = Join-Path $testRoot 'file=dlib.dll'
    $envDlib = Join-Path $testRoot 'environment=dlib.dll'
    $explicitDlib = Join-Path $testRoot 'explicit dlib.dll'
    foreach ($path in @($fileDlib, $envDlib, $explicitDlib)) { 'fake dlib' | Set-Content -LiteralPath $path }
    $fileSettings = @{
        ARTIFACT_SIGNING_ENDPOINT = 'https://file.example.invalid/'
        ARTIFACT_SIGNING_ACCOUNT = 'file-account'
        ARTIFACT_SIGNING_CERT_PROFILE_PUBLIC = 'file-public'
        ARTIFACT_SIGNING_CERT_PROFILE_PRIVATE = 'file-private'
        ARTIFACT_SIGNING_DLIB_PATH = $fileDlib
    }
    $environmentSettings = @{
        ARTIFACT_SIGNING_ENDPOINT = 'https://environment.example.invalid/'
        ARTIFACT_SIGNING_ACCOUNT = 'environment-account'
        ARTIFACT_SIGNING_CERT_PROFILE_PUBLIC = 'environment-public'
        ARTIFACT_SIGNING_CERT_PROFILE_PRIVATE = 'environment-private'
        ARTIFACT_SIGNING_DLIB_PATH = $envDlib
    }
    $cases = @(
        @{ Label = 'envfile public'; Profile = 'Public'; FileSettings = $fileSettings; Environment = @{}; Overrides = @{}; Expected = @{
            Endpoint = $fileSettings.ARTIFACT_SIGNING_ENDPOINT; CodeSigningAccountName = 'file-account'; CertificateProfileName = 'file-public'; Dlib = $fileDlib
        } },
        @{ Label = 'envfile private'; Profile = 'Private'; FileSettings = $fileSettings; Environment = @{}; Overrides = @{}; Expected = @{
            Endpoint = $fileSettings.ARTIFACT_SIGNING_ENDPOINT; CodeSigningAccountName = 'file-account'; CertificateProfileName = 'file-private'; Dlib = $fileDlib
        } },
        @{ Label = 'environment public without envfile'; Profile = 'Public'; FileSettings = @{}; Environment = $environmentSettings; Overrides = @{}; Expected = @{
            Endpoint = $environmentSettings.ARTIFACT_SIGNING_ENDPOINT; CodeSigningAccountName = 'environment-account'; CertificateProfileName = 'environment-public'; Dlib = $envDlib
        } },
        @{ Label = 'environment private overrides envfile'; Profile = 'Private'; FileSettings = $fileSettings; Environment = $environmentSettings; Overrides = @{}; Expected = @{
            Endpoint = $environmentSettings.ARTIFACT_SIGNING_ENDPOINT; CodeSigningAccountName = 'environment-account'; CertificateProfileName = 'environment-private'; Dlib = $envDlib
        } },
        @{ Label = 'partial environment falls back per setting'; Profile = 'Public'; FileSettings = $fileSettings; Environment = @{ ARTIFACT_SIGNING_ACCOUNT = 'environment-account' }; Overrides = @{}; Expected = @{
            Endpoint = $fileSettings.ARTIFACT_SIGNING_ENDPOINT; CodeSigningAccountName = 'environment-account'; CertificateProfileName = 'file-public'; Dlib = $fileDlib
        } },
        @{ Label = 'explicit parameters override environment and envfile'; Profile = 'Private'; FileSettings = $fileSettings; Environment = $environmentSettings; Overrides = @{
            Endpoint = 'https://explicit.example.invalid/'; AccountName = 'explicit-account'; CertificateProfileName = 'explicit-profile'; DlibPath = $explicitDlib
        }; Expected = @{
            Endpoint = 'https://explicit.example.invalid/'; CodeSigningAccountName = 'explicit-account'; CertificateProfileName = 'explicit-profile'; Dlib = $explicitDlib
        } }
    )
    [Environment]::SetEnvironmentVariable('TEMP', $testRoot)
    [Environment]::SetEnvironmentVariable('SOPDET_SIGNING_TEST_LOG', (Join-Path $testRoot 'calls.jsonl'))
    foreach ($case in $cases) {
        foreach ($name in $environmentSettings.Keys) { [Environment]::SetEnvironmentVariable($name, $case.Environment[$name]) }
        if ($case.FileSettings.Count) {
            $case.FileSettings.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" } | Set-Content -LiteralPath $envFile
        } else { Remove-Item -LiteralPath $envFile -ErrorAction SilentlyContinue }
        Set-Content -LiteralPath $env:SOPDET_SIGNING_TEST_LOG -Value ''
        $overrides = $case.Overrides
        & $helperPath -Profile $case.Profile -File $inputFiles -OutDir (Join-Path $testRoot 'output') -SignToolPath $stubPath @overrides | Out-Null
        Test-SigningResult -Label $case.Label -Expected $case.Expected
    }

    # Execute the actual checked-in call sites, including the native pwsh -Command boundary in Make.
    foreach ($name in $environmentSettings.Keys) { [Environment]::SetEnvironmentVariable($name, $environmentSettings[$name]) }
    Remove-Item -LiteralPath $envFile
    $releaseCommands = [regex]::Matches((Get-Content -Raw (Join-Path $repoRoot '.github/workflows/release.yml')), 'run: (\./scripts/sign-artifacts\.ps1[^\r\n]+)')
    $makeCommands = [regex]::Matches(((Get-Content -Raw (Join-Path $repoRoot 'Makefile')) -replace '\\\r?\n\s*', ' '), "pwsh -NoProfile -Command '(\./scripts/sign-artifacts\.ps1[^']+)'")
    if ($releaseCommands.Count -ne 2 -or $makeCommands.Count -ne 2) { throw 'Expected both trust tiers in release and Make signing commands' }
    Push-Location $testRoot
    try {
        foreach ($command in @($releaseCommands) + @($makeCommands)) {
            $text = $command.Groups[1].Value.Replace('$(DIST)', 'dist') + ' -SignToolPath ./fake-signtool.ps1'
            Set-Content -LiteralPath $env:SOPDET_SIGNING_TEST_LOG -Value ''
            & pwsh -NoProfile -Command $text | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Signing call site failed: $text" }
            $trustTier = if ($text -match '-Profile Public') { 'public' } else { 'private' }
            Test-SigningResult -Label $command.Value -Expected @{
                Endpoint = $environmentSettings.ARTIFACT_SIGNING_ENDPOINT; CodeSigningAccountName = 'environment-account'; CertificateProfileName = "environment-$trustTier"; Dlib = $envDlib
            }
        }
    } finally { Pop-Location }

    foreach ($name in $environmentSettings.Keys) { [Environment]::SetEnvironmentVariable($name, $null) }
    Set-Content -LiteralPath $env:SOPDET_SIGNING_TEST_LOG -Value ''
    $rejected = $false
    try { & $helperPath -Profile Public -File $inputFiles -OutDir (Join-Path $testRoot 'missing') -SignToolPath $stubPath | Out-Null }
    catch {
        if ($_.Exception.Message -notlike 'Missing Artifact Signing configuration*') { throw }
        $rejected = $true
    }
    if (-not $rejected -or (Get-Content -Raw -LiteralPath $env:SOPDET_SIGNING_TEST_LOG).Trim()) { throw 'Missing configuration must fail before invoking signtool' }
    Write-Output 'PASS: missing configuration fails before signtool'
} finally {
    foreach ($name in $settings) { [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name]) }
    $resolvedTestRoot = [System.IO.Path]::GetFullPath($testRoot)
    $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    if (-not $resolvedTestRoot.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Test cleanup escaped the temp directory' }
    if (Test-Path -LiteralPath $resolvedTestRoot) { Remove-Item -LiteralPath $resolvedTestRoot -Recurse -Force }
}
