#Requires -Version 3.0
[CmdletBinding()]
param(
    [string]$Endpoint,
    [string]$ApiKey,
    [string]$Config,
    [string]$OutputPath,
    [ValidateSet('minimal', 'quick', 'full')]
    [Alias('Profile')]
    [string]$CollectionProfile = 'full',
    [switch]$DryRun,
    [switch]$Compact,
    [switch]$Compress,
    [switch]$Delta,
    [string]$StatePath,
    [long]$MaxPayloadBytes = 1500000,
    [int]$ChunkBytes = 900000,
    [int]$MaxRetries = 4,
    [switch]$IncludeProcesses,
    [switch]$IncludeAppx,
    [int]$MaxListItems = 2000,
    [string]$Proxy
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 } catch { Write-Verbose "ignored: $_" }

$configPath = if ($Config) { $Config } else { Join-Path (Split-Path -Parent $PSCommandPath) 'inventory.config.json' }
if ($configPath -and (Test-Path $configPath)) {
    try {
        $cfg = Get-Content $configPath -Raw | ConvertFrom-Json
        if (-not $PSBoundParameters.ContainsKey('Endpoint') -and $cfg.endpoint) { $Endpoint = [string]$cfg.endpoint }
        if (-not $PSBoundParameters.ContainsKey('ApiKey') -and $cfg.apiKey) { $ApiKey = [string]$cfg.apiKey }
        if (-not $PSBoundParameters.ContainsKey('OutputPath') -and $cfg.outputPath) { $OutputPath = [string]$cfg.outputPath }
        if (-not $PSBoundParameters.ContainsKey('Proxy') -and $cfg.proxy) { $Proxy = [string]$cfg.proxy }
        if (-not $PSBoundParameters.ContainsKey('StatePath') -and $cfg.statePath) { $StatePath = [string]$cfg.statePath }
        if (-not $PSBoundParameters.ContainsKey('CollectionProfile') -and $cfg.profile -and ($cfg.profile -in @('minimal', 'quick', 'full'))) { $CollectionProfile = [string]$cfg.profile }
        if (-not $PSBoundParameters.ContainsKey('MaxListItems') -and $cfg.maxListItems) { $MaxListItems = [int]$cfg.maxListItems }
        if (-not $PSBoundParameters.ContainsKey('MaxPayloadBytes') -and $cfg.maxPayloadBytes) { $MaxPayloadBytes = [long]$cfg.maxPayloadBytes }
        if (-not $PSBoundParameters.ContainsKey('ChunkBytes') -and $cfg.chunkBytes) { $ChunkBytes = [int]$cfg.chunkBytes }
        if (-not $PSBoundParameters.ContainsKey('MaxRetries') -and $cfg.maxRetries) { $MaxRetries = [int]$cfg.maxRetries }
        if (-not $PSBoundParameters.ContainsKey('IncludeAppx') -and $cfg.includeAppx) { $IncludeAppx = $true }
        if (-not $PSBoundParameters.ContainsKey('IncludeProcesses') -and $cfg.includeProcesses) { $IncludeProcesses = $true }
        if (-not $PSBoundParameters.ContainsKey('Compress') -and $cfg.compress) { $Compress = $true }
        if (-not $PSBoundParameters.ContainsKey('Delta') -and $cfg.delta) { $Delta = $true }
        if (-not $PSBoundParameters.ContainsKey('DryRun') -and ($cfg.dryRun -eq $true)) { $DryRun = $true }
    } catch { Write-Verbose "ignored: $_" }
}

$AgentName = 'Sopdet'
$AgentVersion = '0.3.0'
$SchemaVersion = 2
$script:Now = (Get-Date).ToUniversalTime()
$script:NowIso = $script:Now.ToString('o')
$script:Truncated = New-Object System.Collections.Generic.List[string]
$script:Entities = [ordered]@{}
$script:EntityErrors = [ordered]@{}
$script:VolatileFields = @(
    'free_bytes', 'used_percent', 'percent_remaining', 'run_time_minutes',
    'uptime_seconds', 'ram_free_bytes', 'ram_usage_percent', 'estimated_charge_remaining'
)

$ProfileLevel = @{ minimal = 0; quick = 1; full = 2 }

trap {
    $line = $_.InvocationInfo.ScriptLineNumber
    $off = $_.InvocationInfo.OffsetInLine
    $msg = "INV_TRAP: $($_.Exception.GetType().Name): $($_.Exception.Message) @ line $line col $off"
    [Console]::Error.WriteLine($msg)
    [Console]::Error.WriteLine($_.ScriptStackTrace)
    exit 1
}

function Test-IsElevated {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function ConvertTo-Iso($Value) {
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return ([datetime]$Value).ToUniversalTime().ToString('o') }
    return $Value
}

function Convert-EpochToIso($Seconds) {
    if ($null -eq $Seconds) { return $null }
    try { return ([datetimeoffset]::FromUnixTimeSeconds([long]$Seconds)).UtcDateTime.ToString('o') } catch { return $null }
}

function Convert-InstallDate($Value) {
    if ($null -eq $Value) { return $null }
    $s = ([string]$Value).Trim()
    if ($s -match '^\d{8}$') { return ('{0}-{1}-{2}' -f $s.Substring(0, 4), $s.Substring(4, 2), $s.Substring(6, 2)) }
    return $s
}

function Get-CimData {
    param([string]$ClassName, [string]$Namespace = 'root/cimv2', [string]$Filter)
    $params = @{ ClassName = $ClassName; Namespace = $Namespace; ErrorAction = 'Stop' }
    if ($Filter) { $params['Filter'] = $Filter }
    return Get-CimInstance @params
}

function Get-CanonicalFingerprint($Object) {
    $json = $Object | ConvertTo-Json -Depth 16 -Compress
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($json))
    } finally { $sha.Dispose() }
    return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Complete-Record($Record) {
    if ($null -eq $Record) { return $null }
    $forHash = [ordered]@{}
    foreach ($k in $Record.Keys) {
        if ($script:VolatileFields -notcontains $k) { $forHash[$k] = $Record[$k] }
    }
    $Record['fingerprint'] = Get-CanonicalFingerprint $forHash
    $Record['observed_at'] = $script:NowIso
    return $Record
}

function Add-Entity {
    param([string]$Type, [object[]]$Records)
    $recs = @($Records | Where-Object { $null -ne $_ })
    $seen = @{}
    for ($i = 0; $i -lt $recs.Count; $i++) {
        $k = [string]$recs[$i].key
        if ($seen.ContainsKey($k)) { $seen[$k]++; $recs[$i].key = "$k#$($seen[$k])" } else { $seen[$k] = 1 }
    }
    for ($i = 0; $i -lt $recs.Count; $i++) { $recs[$i] = Complete-Record $recs[$i] }
    $fps = @($recs | ForEach-Object { $_.fingerprint } | Sort-Object)
    $rollup = [ordered]@{ count = $recs.Count; fingerprints = $fps }
    $script:Entities[$Type] = [ordered]@{
        count       = $recs.Count
        fingerprint = Get-CanonicalFingerprint $rollup
        records     = $recs
    }
}

function Add-Collected {
    param([string]$Type, [scriptblock]$Body)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $recs = @(& $Body)
        Add-Entity -Type $Type -Records $recs
    } catch {
        $msg = $_.Exception.Message
        $script:EntityErrors[$Type] = [ordered]@{
            error      = $msg
            gated      = [bool]($msg -match 'denied|not authorized|Unauthorized|privilege|0x80070005')
            durationMs = $sw.ElapsedMilliseconds
        }
    }
}

function Limit-Item {
    param([object[]]$Items, [int]$Max, [string]$Label)
    $arr = @($Items | Where-Object { $null -ne $_ })
    if ($arr.Count -gt $Max) {
        if ($Label) { $script:Truncated.Add("$Label ($($arr.Count) > $Max)") }
        return $arr[0..($Max - 1)]
    }
    return $arr
}

function Write-Utf8 {
    param([string]$Path, [string]$Text)
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Text, $enc)
}

function Compress-Base64([string]$Text) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    $ms = New-Object System.IO.MemoryStream
    $level = $null
    try { $level = [System.IO.Compression.CompressionLevel]::Optimal } catch { Write-Verbose "ignored: $_" }
    if ($null -ne $level) {
        $gz = New-Object System.IO.Compression.GZipStream($ms, $level)
    } else {
        $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
    }
    try { $gz.Write($bytes, 0, $bytes.Length) } finally { $gz.Dispose() }
    try { return [Convert]::ToBase64String($ms.ToArray()) } finally { $ms.Dispose() }
}

function Resolve-StatePath([string]$Explicit) {
    if ($Explicit) { return $Explicit }
    return (Join-Path (Join-Path $env:LOCALAPPDATA 'Sopdet') 'state.json')
}

function Read-JsonFile([string]$Path) {
    try { if (Test-Path $Path) { return (Get-Content $Path -Raw | ConvertFrom-Json) } } catch { Write-Verbose "ignored: $_" }
    return $null
}

function Convert-StateToMap($State) {
    $maps = @{}
    if ($null -eq $State) { return $maps }
    $ents = $null
    try { $ents = $State.entities } catch { Write-Verbose "ignored: $_" }
    if ($null -eq $ents) { return $maps }
    foreach ($ep in $ents.PSObject.Properties) {
        $m = @{}
        foreach ($kp in $ep.Value.PSObject.Properties) { $m[$kp.Name] = [string]$kp.Value }
        $maps[$ep.Name] = $m
    }
    return $maps
}

function Get-StateObject([string]$ScanId) {
    $ents = [ordered]@{}
    foreach ($n in $script:Entities.Keys) {
        $m = [ordered]@{}
        foreach ($r in $script:Entities[$n].records) { $m[$r.key] = $r.fingerprint }
        $ents[$n] = $m
    }
    return [ordered]@{ schema_version = $SchemaVersion; scan_id = $ScanId; observed_at = $script:NowIso; entities = $ents }
}

function Get-DeltaEntity($PrevMaps) {
    $delta = New-Object System.Collections.Specialized.OrderedDictionary
    foreach ($n in $script:Entities.Keys) {
        $prev = @{}
        if ($PrevMaps.ContainsKey($n)) { $prev = $PrevMaps[$n] }
        $cur = @{}
        $recs = @{}
        foreach ($r in $script:Entities[$n].records) { $cur[$r.key] = $r.fingerprint; $recs[$r.key] = $r }
        $added = New-Object System.Collections.Generic.List[object]
        $changed = New-Object System.Collections.Generic.List[object]
        $removed = New-Object System.Collections.Generic.List[object]
        $unchanged = 0
        foreach ($k in $cur.Keys) {
            if (-not $prev.ContainsKey($k)) { $added.Add($recs[$k]) }
            elseif ($prev[$k] -ne $cur[$k]) { $changed.Add($recs[$k]) }
            else { $unchanged = $unchanged + 1 }
        }
        foreach ($k in $prev.Keys) {
            if (-not $cur.ContainsKey($k)) {
                $stub = New-Object System.Collections.Specialized.OrderedDictionary
                $stub.Add('key', [string]$k)
                $stub.Add('previous_fingerprint', [string]$prev[$k])
                $removed.Add($stub)
            }
        }
        $ent = New-Object System.Collections.Specialized.OrderedDictionary
        $ent.Add('count', [int]$cur.Count)
        $ent.Add('added', $added.ToArray())
        $ent.Add('changed', $changed.ToArray())
        $ent.Add('removed', $removed.ToArray())
        $ent.Add('unchanged', [int]$unchanged)
        $delta.Add([string]$n, $ent)
    }
    return $delta
}

function Optimize-PayloadBudget([long]$MaxBytes) {
    if ($MaxBytes -le 0) { return }
    $guard = 0
    while ($guard -lt 40) {
        $size = ($script:OutEntities | ConvertTo-Json -Depth 20 -Compress).Length
        if ($size -le $MaxBytes) { break }
        $target = $null; $bestKey = $null; $best = 0
        foreach ($n in $script:OutEntities.Keys) {
            $ent = $script:OutEntities[$n]
            foreach ($arrKey in @('records', 'added', 'changed')) {
                if ($ent.Contains($arrKey)) {
                    $cnt = @($ent[$arrKey]).Count
                    if ($cnt -gt $best) { $best = $cnt; $target = $n; $bestKey = $arrKey }
                }
            }
        }
        if (-not $target -or $best -le 1) { break }
        $ent = $script:OutEntities[$target]
        $arr = @($ent[$bestKey])
        $keep = [math]::Max(1, [math]::Floor($arr.Count / 2))
        $omitted = $arr.Count - $keep
        $ent[$bestKey] = @($arr[0..($keep - 1)])
        $ent['summarized'] = $true
        $ent['omitted'] = ([int]$ent['omitted']) + $omitted
        $script:Truncated.Add("$target.$bestKey summarized (-$omitted)")
        $script:Summarized = $true
        $guard++
    }
}

function Get-ChunkEnvelope($Header, $EntitySubset, [int]$Index, [int]$Count, $Names) {
    $chunkEnv = New-Object System.Collections.Specialized.OrderedDictionary
    foreach ($k in $Header.Keys) { $chunkEnv.Add($k, $Header[$k]) }
    $chunk = New-Object System.Collections.Specialized.OrderedDictionary
    $chunk.Add('index', [int]$Index)
    $chunk.Add('count', [int]$Count)
    $chunk.Add('entities', @($Names))
    $chunkEnv.Add('chunk', $chunk)
    $chunkEnv.Add('entities', $EntitySubset)
    return $chunkEnv
}

function Get-Wire([object]$ChunkEnv, [bool]$UseCompress) {
    $c = $ChunkEnv | ConvertTo-Json -Depth 24 -Compress
    if ($UseCompress) { return (Compress-Base64 $c) }
    return $c
}

function Invoke-IngestPost([string]$Url, [string]$ApiKey, [string]$Body, [string]$Proxy) {
    $headers = @{ 'Content-Type' = 'application/json; charset=utf-8' }
    if ($ApiKey) { $headers['X-Bifrost-Key'] = $ApiKey }
    $req = @{ Method = 'Post'; Uri = $Url; Headers = $headers; Body = [Text.Encoding]::UTF8.GetBytes($Body); TimeoutSec = 90; ErrorAction = 'Stop' }
    if ($Proxy) { $req['Proxy'] = $Proxy }
    Invoke-RestMethod @req | Out-Null
}

function Limit-EntitySize($Ent, $Header, [string]$Name, [bool]$UseCompress, [int]$ChunkBytes) {
    $guard = 0
    while ($guard -lt 40) {
        $single = New-Object System.Collections.Specialized.OrderedDictionary
        $single.Add($Name, $Ent)
        $probe = Get-ChunkEnvelope $Header $single 0 1 @($Name)
        if ((Get-Wire $probe $UseCompress).Length -le $ChunkBytes) { break }
        if (-not $Ent.Contains('records')) { break }
        $recs = @($Ent['records'])
        if ($recs.Count -le 1) { break }
        $keep = [math]::Max(1, [math]::Floor($recs.Count / 2))
        $om = $recs.Count - $keep
        $Ent['records'] = @($recs[0..($keep - 1)])
        $Ent['summarized'] = $true
        $Ent['omitted'] = ([int]$Ent['omitted']) + $om
        $script:Truncated.Add("$Name summarized (-$om) for transport")
        $script:Summarized = $true
        $guard++
    }
}

function Send-Ingest($Header, $Entities, [string]$Url, [string]$ApiKey, [bool]$UseCompress, [int]$ChunkBytes, [int]$MaxRetries, [string]$Proxy, [string]$SpoolDir, [string]$ScanId) {
    $delivered = $true
    if (Test-Path $SpoolDir) {
        foreach ($f in (Get-ChildItem $SpoolDir -Filter '*.json' -ErrorAction SilentlyContinue | Sort-Object Name)) {
            $ok = $false
            for ($a = 1; $a -le $MaxRetries; $a++) {
                try { Invoke-IngestPost $Url $ApiKey (Get-Content $f.FullName -Raw) $Proxy; $ok = $true; break }
                catch { Start-Sleep -Milliseconds ([int]([math]::Pow(2, $a) * 500 + (Get-Random -Maximum 500))) }
            }
            if ($ok) { Remove-Item $f.FullName -Force -ErrorAction SilentlyContinue } else { $delivered = $false }
        }
    }
    $groups = New-Object System.Collections.Generic.List[object]
    $cur = New-Object System.Collections.Specialized.OrderedDictionary
    $curNames = New-Object System.Collections.Generic.List[string]
    foreach ($n in @($Entities.Keys)) {
        $probe = New-Object System.Collections.Specialized.OrderedDictionary
        foreach ($k in $cur.Keys) { $probe.Add($k, $cur[$k]) }
        $probe.Add($n, $Entities[$n])
        $probeNames = @($curNames) + @($n)
        $wire = Get-Wire (Get-ChunkEnvelope $Header $probe 0 1 $probeNames) $UseCompress
        if ($wire.Length -gt $ChunkBytes) {
            if ($curNames.Count -gt 0) {
                $groups.Add(@{ names = @($curNames); entities = $cur })
                $cur = New-Object System.Collections.Specialized.OrderedDictionary
                $curNames = New-Object System.Collections.Generic.List[string]
            }
            Limit-EntitySize $Entities[$n] $Header $n $UseCompress $ChunkBytes
        }
        $cur.Add($n, $Entities[$n])
        $curNames.Add($n)
    }
    if ($curNames.Count -gt 0) { $groups.Add(@{ names = @($curNames); entities = $cur }) }

    $count = $groups.Count
    for ($i = 0; $i -lt $count; $i++) {
        $g = $groups[$i]
        $chunkEnv = Get-ChunkEnvelope $Header $g.entities $i $count $g.names
        $jsonChunk = $chunkEnv | ConvertTo-Json -Depth 24 -Compress
        $bodyObj = New-Object System.Collections.Specialized.OrderedDictionary
        $bodyObj.Add('scan_id', $ScanId)
        $bodyObj.Add('chunk_index', [int]$i)
        $bodyObj.Add('chunk_count', [int]$count)
        if ($UseCompress) {
            $bodyObj.Add('content_encoding', 'gzip+base64')
            $bodyObj.Add('payload', (Compress-Base64 $jsonChunk))
        } else {
            $bodyObj.Add('content_encoding', $null)
            $bodyObj.Add('payload', $jsonChunk)
        }
        $body = $bodyObj | ConvertTo-Json -Depth 24 -Compress
        $ok = $false
        for ($a = 1; $a -le $MaxRetries; $a++) {
            try { Invoke-IngestPost $Url $ApiKey $body $Proxy; $ok = $true; break }
            catch { Start-Sleep -Milliseconds ([int]([math]::Pow(2, $a) * 500 + (Get-Random -Maximum 500))) }
        }
        if (-not $ok) {
            try {
                if (-not (Test-Path $SpoolDir)) { New-Item -ItemType Directory -Force -Path $SpoolDir | Out-Null }
                Write-Utf8 -Path (Join-Path $SpoolDir ("$ScanId-$i.json")) -Text $body
            } catch { Write-Verbose "ignored: $_" }
            $delivered = $false
            $script:Truncated.Add("chunk $i spooled")
        }
    }
    $pending = @(Get-ChildItem $SpoolDir -Filter '*.json' -ErrorAction SilentlyContinue).Count
    return [ordered]@{ delivered = $delivered; chunks = $count; spooled = $pending }
}

function Get-VmSystem($cs) {
    $m = (("$($cs.Manufacturer) $($cs.Model)").ToLower())
    if ($m -match 'vmware') { return 'VMware' }
    if ($m -match 'virtualbox') { return 'VirtualBox' }
    if ($m -match 'hyper-v|virtual machine') { return 'Hyper-V' }
    if ($m -match 'qemu|kvm') { return 'QEMU' }
    if ($m -match 'parallels') { return 'Parallels' }
    if ($m -match 'xen') { return 'Xen' }
    return 'Physical'
}

function Get-PersistedId([string]$FileName) {
    $dir = Join-Path $env:LOCALAPPDATA 'Sopdet'
    $f = Join-Path $dir $FileName
    if (Test-Path $f) {
        $v = (Get-Content $f -Raw).Trim()
        if ($v) { return $v }
    }
    $g = [guid]::NewGuid().ToString()
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    Set-Content -Path $f -Value $g -Encoding ASCII
    return $g
}

function Get-HostIdentity {
    $mg = $null
    try { $mg = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid } catch { Write-Verbose "ignored: $_" }
    $smbios = $null
    try { $smbios = (Get-CimData 'Win32_ComputerSystemProduct').UUID } catch { Write-Verbose "ignored: $_" }
    $instance = Get-PersistedId 'instance-id'
    $deviceId = $null; $source = $null
    if ($mg) { $deviceId = $mg; $source = 'machine_guid' }
    elseif ($smbios -and $smbios -notmatch '^0+$' -and $smbios -notmatch '^F{8}') { $deviceId = $smbios; $source = 'smbios_uuid' }
    else { $deviceId = $instance; $source = 'instance' }
    $fqdn = $env:COMPUTERNAME
    try { $fqdn = [System.Net.Dns]::GetHostEntry('').HostName } catch { Write-Verbose "ignored: $_" }
    return [ordered]@{
        device_id        = $deviceId
        device_id_source = $source
        hardware_uuid    = $smbios
        machine_guid     = $mg
        instance_id      = $instance
        hostname         = $env:COMPUTERNAME
        fqdn             = $fqdn
    }
}

function Get-UptimeSpan {
    try {
        $os = Get-CimData 'Win32_OperatingSystem'
        if ($os.LastBootUpTime) { return [int](((Get-Date).ToUniversalTime() - $os.LastBootUpTime.ToUniversalTime()).TotalSeconds) }
    } catch { Write-Verbose "ignored: $_" }
    return $null
}

function Get-HostRecord {
    $cs = $null; try { $cs = Get-CimData 'Win32_ComputerSystem' } catch { Write-Verbose "ignored: $_" }
    $os = $null; try { $os = Get-CimData 'Win32_OperatingSystem' } catch { Write-Verbose "ignored: $_" }
    $enclosure = $null; try { $enclosure = Get-CimData 'Win32_SystemEnclosure' | Select-Object -First 1 } catch { Write-Verbose "ignored: $_" }
    return [ordered]@{
        key              = 'host'
        hostname         = $env:COMPUTERNAME
        fqdn             = $env:COMPUTERNAME
        domain           = if ($cs) { $cs.Domain } else { $null }
        part_of_domain   = if ($cs) { [bool]$cs.PartOfDomain } else { $null }
        workgroup        = if ($cs -and -not $cs.PartOfDomain) { $cs.Workgroup } else { $null }
        domain_role      = if ($cs) { [int]$cs.DomainRole } else { $null }
        manufacturer     = if ($cs) { $cs.Manufacturer } else { $null }
        model            = if ($cs) { $cs.Model } else { $null }
        system_type      = if ($cs) { $cs.SystemType } else { $null }
        chassis_type     = if ($enclosure) { (@($enclosure.ChassisTypes) -join ',') } else { $null }
        asset_tag        = if ($enclosure) { $enclosure.SMBIOSAssetTag } else { $null }
        virtual_machine  = if ($cs) { ((Get-VmSystem $cs) -ne 'Physical') } else { $null }
        vm_system        = if ($cs) { Get-VmSystem $cs } else { $null }
        current_user     = if ($cs) { $cs.UserName } else { $null }
        last_boot_time   = if ($os) { ConvertTo-Iso $os.LastBootUpTime } else { $null }
        total_memory_bytes = if ($cs -and $cs.TotalPhysicalMemory) { [long]$cs.TotalPhysicalMemory } else { $null }
    }
}

function Get-OsRecord {
    $os = Get-CimData 'Win32_OperatingSystem'
    $tz = $null; try { $tz = Get-CimData 'Win32_TimeZone' } catch { Write-Verbose "ignored: $_" }
    $reg = $null
    try { $reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop } catch { Write-Verbose "ignored: $_" }
    $pending = Test-PendingReboot
    $sb = $null
    try { $sb = [int](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name UEFISecureBootEnabled -ErrorAction Stop).UEFISecureBootEnabled } catch { Write-Verbose "ignored: $_" }
    $verParts = @()
    if ($os.Version) { $verParts = $os.Version.Split('.') }
    $fqdn = $env:COMPUTERNAME
    try { $fqdn = [System.Net.Dns]::GetHostEntry('').HostName } catch { Write-Verbose "ignored: $_" }
    return [ordered]@{
        key                = 'os'
        hostname           = $env:COMPUTERNAME
        fqdn               = $fqdn
        name               = $os.Caption
        full_name          = if ($reg) { $reg.ProductName } else { $os.Caption }
        version            = $os.Version
        major              = if ($verParts.Count -ge 1) { $verParts[0] } else { $null }
        minor              = if ($verParts.Count -ge 2) { $verParts[1] } else { $null }
        build              = $os.BuildNumber
        revision           = if ($reg) { $reg.UBR } else { $null }
        release_id         = if ($reg) { $reg.ReleaseId } else { $null }
        codename           = if ($reg) { $reg.DisplayVersion } else { $null }
        edition_id         = if ($reg) { $reg.EditionID } else { $null }
        edition_sku        = $os.OperatingSystemSKU
        platform           = 'windows'
        platform_like      = 'windows'
        arch               = $os.OSArchitecture
        install_date       = ConvertTo-Iso $os.InstallDate
        boot_time          = ConvertTo-Iso $os.LastBootUpTime
        locale             = $os.Locale
        language           = $os.MUILanguages -join ','
        timezone_name      = if ($tz) { $tz.Caption } else { $null }
        timezone_offset    = if ($tz) { $tz.CurrentTimeZone } else { $null }
        needs_reboot       = $pending.pending
        reboot_indicators  = @($pending.indicators)
        secure_boot        = $sb
        serial_number      = $os.SerialNumber
        hypervisor_present = $os.HypervisorPresent
    }
}

function Test-PendingReboot {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting'
    )
    $indicators = New-Object System.Collections.Generic.List[string]
    foreach ($k in $keys) { if (Test-Path $k) { $indicators.Add($k) } }
    try {
        $pfro = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction Stop).PendingFileRenameOperations
        if ($pfro) { $indicators.Add('PendingFileRenameOperations') }
    } catch { Write-Verbose "ignored: $_" }
    return [ordered]@{ pending = [bool]($indicators.Count -gt 0); indicators = @($indicators) }
}

function Get-HardwareRecord {
    $cs = Get-CimData 'Win32_ComputerSystem'
    $cpu = $null; try { $cpu = Get-CimData 'Win32_Processor' | Select-Object -First 1 } catch { Write-Verbose "ignored: $_" }
    $bb = $null; try { $bb = Get-CimData 'Win32_BaseBoard' | Select-Object -First 1 } catch { Write-Verbose "ignored: $_" }
    return [ordered]@{
        key                  = 'hardware'
        board_serial         = if ($bb) { $bb.SerialNumber } else { $null }
        board_manufacturer   = if ($bb) { $bb.Manufacturer } else { $null }
        board_product        = if ($bb) { $bb.Product } else { $null }
        cpu_name             = if ($cpu) { $cpu.Name } else { $null }
        cpu_cores            = if ($cpu) { $cpu.NumberOfCores } else { $null }
        cpu_logical_cores    = if ($cpu) { $cpu.NumberOfLogicalProcessors } else { $null }
        cpu_mhz              = if ($cpu) { $cpu.CurrentClockSpeed } else { $null }
        cpu_max_mhz          = if ($cpu) { $cpu.MaxClockSpeed } else { $null }
        ram_total_bytes      = if ($cs.TotalPhysicalMemory) { [long]$cs.TotalPhysicalMemory } else { $null }
        manufacturer         = $cs.Manufacturer
        model                = $cs.Model
        system_type          = $cs.SystemType
        virtual_machine      = ((Get-VmSystem $cs) -ne 'Physical')
        vm_system            = Get-VmSystem $cs
    }
}

function Get-ProcessorRecord {
    $out = @()
    try {
        $out = Get-CimData 'Win32_Processor' | ForEach-Object {
            [ordered]@{
                key                 = "cpu:$($_.DeviceID)"
                device_id           = $_.DeviceID
                name                = $_.Name
                manufacturer        = $_.Manufacturer
                architecture        = if ($_.AddressWidth -eq 64) { 'x86_64' } else { 'x86' }
                cores               = $_.NumberOfCores
                logical_cores       = $_.NumberOfLogicalProcessors
                current_mhz         = $_.CurrentClockSpeed
                max_mhz             = $_.MaxClockSpeed
                socket              = $_.SocketDesignation
                processor_id        = $_.ProcessorId
                l2_cache_kb         = $_.L2CacheSize
                l3_cache_kb         = $_.L3CacheSize
            }
        }
    } catch { Write-Verbose "ignored: $_" }
    return @($out)
}

function Get-MemoryModuleRecord {
    $out = @()
    try {
        $out = Get-CimData 'Win32_PhysicalMemory' | Where-Object { $_.Capacity -and [long]$_.Capacity -gt 0 } | ForEach-Object {
            [ordered]@{
                key                  = "dimm:$($_.DeviceLocator):$($_.SerialNumber)"
                bank_label           = $_.BankLabel
                device_locator       = $_.DeviceLocator
                size_bytes           = if ($_.Capacity) { [long]$_.Capacity } else { $null }
                form_factor          = $_.FormFactor
                memory_type          = $_.SMBIOSMemoryType
                speed_mts            = $_.Speed
                configured_speed_mts = $_.ConfiguredClockSpeed
                manufacturer         = $_.Manufacturer
                part_number          = $_.PartNumber
                serial_number        = $_.SerialNumber
            }
        }
    } catch { Write-Verbose "ignored: $_" }
    return @($out)
}

function Get-GraphicsRecord {
    $out = @()
    try {
        $out = Get-CimData 'Win32_VideoController' | ForEach-Object {
            [ordered]@{
                key              = "gpu:$($_.DeviceID)"
                name             = $_.Name
                vendor           = $_.AdapterCompatibility
                memory_bytes     = if ($_.AdapterRAM) { [long]$_.AdapterRAM } else { $null }
                driver_version   = $_.DriverVersion
                driver_date      = ConvertTo-Iso $_.DriverDate
                video_processor  = $_.VideoProcessor
                resolution       = if ($_.CurrentHorizontalResolution) { "$($_.CurrentHorizontalResolution)x$($_.CurrentVerticalResolution)" } else { $null }
            }
        }
    } catch { Write-Verbose "ignored: $_" }
    return @($out)
}

function Get-BiosRecord {
    $b = $null; try { $b = Get-CimData 'Win32_BIOS' | Select-Object -First 1 } catch { Write-Verbose "ignored: $_" }
    $enclosure = $null; try { $enclosure = Get-CimData 'Win32_SystemEnclosure' | Select-Object -First 1 } catch { Write-Verbose "ignored: $_" }
    return @([ordered]@{
        key                  = 'bios'
        manufacturer         = if ($b) { $b.Manufacturer } else { $null }
        name                 = if ($b) { $b.Name } else { $null }
        version              = if ($b) { $b.SMBIOSBIOSVersion } else { $null }
        release_date         = if ($b) { ConvertTo-Iso $b.ReleaseDate } else { $null }
        bios_serial          = if ($b) { $b.SerialNumber } else { $null }
        system_serial        = if ($b) { $b.SerialNumber } else { $null }
        asset_tag            = if ($enclosure) { $enclosure.SMBIOSAssetTag } else { $null }
        enclosure_serial     = if ($enclosure) { $enclosure.SerialNumber } else { $null }
        sku_number           = if ($b) { $b.SystemSKUNumber } else { $null }
        smbios_major         = if ($b) { $b.SMBIOSMajorVersion } else { $null }
        smbios_minor         = if ($b) { $b.SMBIOSMinorVersion } else { $null }
    })
}

function Get-SecureBootRecord {
    $sb = $null
    try { $sb = [int](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name UEFISecureBootEnabled -ErrorAction Stop).UEFISecureBootEnabled } catch { Write-Verbose "ignored: $_" }
    return @([ordered]@{
        key         = 'secureboot'
        secure_boot = $sb
        setup_mode  = $null
        source      = 'registry'
    })
}

function Get-TpmRecord {
    $t = Get-CimData 'Win32_Tpm' 'root/cimv2/security/microsofttpm'
    if ($null -eq $t) {
        return @([ordered]@{
            key           = 'tpm'
            present       = $false
            enabled       = $null
            activated     = $null
            owned         = $null
            manufacturer_id = $null
            manufacturer_version = $null
            spec_version  = $null
            physical_presence_version = $null
        })
    }
    return @([ordered]@{
        key                     = 'tpm'
        present                 = $true
        enabled                 = [bool]$t.IsEnabled_InitialValue
        activated               = [bool]$t.IsActivated_InitialValue
        owned                   = [bool]$t.IsOwned_InitialValue
        manufacturer_id         = $t.ManufacturerId
        manufacturer_version    = $t.ManufacturerVersion
        spec_version            = $t.SpecVersion
        physical_presence_version = $t.PhysicalPresenceVersionInfo
    })
}

function Get-VirtualizationRecord {
    $cs = Get-CimData 'Win32_ComputerSystem'
    return @([ordered]@{
        key                = 'virtualization'
        vm_system          = Get-VmSystem $cs
        hypervisor_present = [bool]$cs.HypervisorPresent
        manufacturer       = $cs.Manufacturer
        model              = $cs.Model
        physical           = ((Get-VmSystem $cs) -eq 'Physical')
    })
}

function Get-VolumeRecord {
    $out = @()
    try {
        $out = Get-CimData 'Win32_LogicalDisk' | ForEach-Object {
            $used = $null
            if ($_.Size -and $_.FreeSpace) { $used = [math]::Round(100 * ([double]($_.Size - $_.FreeSpace)) / [double]$_.Size, 1) }
            [ordered]@{
                key                = "volume:$($_.DeviceID)"
                drive_letter       = $_.DeviceID
                label              = $_.VolumeName
                device_type        = [int]$_.DriveType
                file_system        = $_.FileSystem
                capacity_bytes     = if ($_.Size) { [long]$_.Size } else { $null }
                free_bytes         = if ($_.FreeSpace) { [long]$_.FreeSpace } else { $null }
                used_percent       = $used
                serial_number      = $_.VolumeSerialNumber
                system_drive       = ([string]$_.DeviceID).TrimEnd(':') -eq (([string]$env:SystemDrive).TrimEnd(':'))
                encrypt_name       = $null
                encrypt_algo       = $null
                encrypt_status     = $null
                encrypt_type       = $null
            }
        }
    } catch { Write-Verbose "ignored: $_" }
    if ($env:SystemDrive) {
        try {
            $bl = Get-CimInstance -Namespace 'root/cimv2/security/microsoftvolumeencryption' -ClassName 'Win32_EncryptableVolume' -ErrorAction Stop
            foreach ($v in $bl) {
                $letter = ([string]$v.DriveLetter).TrimEnd(':')
                foreach ($r in $out) { if (([string]$r.drive_letter).TrimEnd(':') -eq $letter) {
                    $r.encrypt_name = 'BitLocker'
                    $r.encrypt_status = switch ([int]$v.ProtectionStatus) { 0 { 'off' } 1 { 'on' } 2 { 'unknown' } default { "$($v.ProtectionStatus)" } }
                    $r.encrypt_algo = switch ([int]$v.EncryptionMethod) { 1 { 'AES_128_WITH_DIFFUSER' } 2 { 'AES_256_WITH_DIFFUSER' } 3 { 'AES_128' } 4 { 'AES_256' } 5 { 'HARDWARE_ENCRYPTION' } 6 { 'XTS_AES_128' } 7 { 'XTS_AES_256' } default { "$($v.EncryptionMethod)" } }
                    $r.encrypt_type = 'software'
                } }
            }
        } catch { Write-Verbose "ignored: $_" }
    }
    return @($out)
}

function Get-PhysicalDiskRecord {
    $out = @()
    try {
        $out = Get-CimData 'Win32_DiskDrive' | ForEach-Object {
            [ordered]@{
                key             = "disk:$($_.Index)"
                index           = $_.Index
                model           = $_.Model
                manufacturer    = $_.Manufacturer
                serial_number   = $_.SerialNumber
                size_bytes      = if ($_.Size) { [long]$_.Size } else { $null }
                interface_type  = $_.InterfaceType
                media_type      = $_.MediaType
                firmware        = $_.FirmwareRevision
                partition_count = $_.Partitions
                bytes_per_sector = $_.BytesPerSector
                status          = $_.Status
                smart_capable   = $_.Capabilities
            }
        }
    } catch { Write-Verbose "ignored: $_" }
    return @($out)
}

function Get-NetworkRecord {
    $out = @()
    try {
        $out = Get-CimData 'Win32_NetworkAdapterConfiguration' -Filter 'IPEnabled=True' | ForEach-Object {
            $speed = $null
            try { $speed = (Get-CimData 'Win32_NetworkAdapter' -Filter "Index=$($_.Index)" -ErrorAction Stop).Speed } catch { Write-Verbose "ignored: $_" }
            [ordered]@{
                key              = "nic:$($_.Index):$($_.MACAddress)"
                interface_index  = $_.Index
                adapter_name     = $_.Description
                description      = $_.Description
                interface_type   = $null
                mac_address      = $_.MACAddress
                ip_addresses     = @($_.IPAddress)
                subnet_masks     = @($_.IPSubnet)
                default_gateway  = @($_.DefaultIPGateway)
                dns_servers      = @($_.DNSServerSearchOrder)
                dns_domain       = $_.DNSDomain
                dns_host_name    = $_.DNSHostName
                dhcp_enabled     = [bool]$_.DHCPEnabled
                dhcp_server      = $_.DHCPServer
                link_speed_bps   = $speed
                mtu              = $null
                status           = $_.NetConnectionStatus
                service_name     = $_.ServiceName
            }
        }
    } catch { Write-Verbose "ignored: $_" }
    return @($out)
}

function Get-ListeningPortRecord {
    $out = @()
    $ephemeralMin = 49152
    $add = {
        param($proto, $addr, $port, $pidv)
        if ($null -eq $port) { return }
        $p = [int]$port
        if ($p -lt 1 -or $p -ge $ephemeralMin) { return }
        $fam = if (([string]$addr).Contains(':')) { 'ipv6' } else { 'ipv4' }
        return [ordered]@{ key = "$proto|$fam|$addr|$p|$pidv"; protocol = $proto; address = $addr; port = $p; family = $fam; pid = $pidv; process = $null }
    }
    try {
        foreach ($c in (Get-NetTCPConnection -State Listen -ErrorAction Stop)) {
            $r = & $add 'tcp' $c.LocalAddress $c.LocalPort ([int]$c.OwningProcess)
            if ($r) { $out += $r }
        }
    } catch { Write-Verbose "ignored: $_" }
    try {
        foreach ($c in (Get-NetUDPEndpoint -ErrorAction Stop)) {
            $r = & $add 'udp' $c.LocalAddress $c.LocalPort ([int]$c.OwningProcess)
            if ($r) { $out += $r }
        }
    } catch { Write-Verbose "ignored: $_" }
    if ($out.Count -eq 0) {
        try {
            foreach ($line in (netstat -ano | Select-String 'LISTENING|UDP')) {
                $parts = ($line.ToString().Trim() -split '\s+')
                if ($parts.Length -ge 4 -and $parts[0] -match '^(TCP|UDP)$') {
                    $proto = $parts[0].ToLower(); $local = $parts[1]
                    $li = $local.LastIndexOf(':'); if ($li -lt 0) { continue }
                    $addr = $local.Substring(0, $li); $port = [int]$local.Substring($li + 1)
                    $r = & $add $proto $addr $port ([int]$parts[-1])
                    if ($r) { $out += $r }
                }
            }
        } catch { Write-Verbose "ignored: $_" }
    }
    $names = @{}
    foreach ($r in $out) {
        if ($null -eq $r.process -and $null -ne $r.pid) {
            if (-not $names.ContainsKey($r.pid)) {
                $n = $null
                try { $n = (Get-Process -Id $r.pid -ErrorAction Stop).ProcessName } catch { Write-Verbose "ignored: $_" }
                $names[$r.pid] = $n
            }
            $r.process = $names[$r.pid]
        }
    }
    return @($out)
}

function Get-SoftwareRecord {
    $paths = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'machine'; Arch = 'x64' },
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'machine'; Arch = 'x86' },
        @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'user'; Arch = 'auto' }
    )
    $seen = @{}
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($p in $paths) {
        if (-not (Test-Path $p.Path)) { continue }
        foreach ($key in (Get-ChildItem $p.Path -ErrorAction SilentlyContinue)) {
            $k = $null
            try { $k = Get-ItemProperty $key.PSPath -ErrorAction Stop } catch { continue }
            if (-not $k.DisplayName) { continue }
            $id = "$($p.Scope)|$($k.DisplayName)|$($k.DisplayVersion)"
            if ($seen.ContainsKey($id)) { continue }
            $seen[$id] = $true
            $size = $null
            if ($k.EstimatedSize) { $size = [long]([double]$k.EstimatedSize * 1024) }
            $fmt = 'exe'
            if ($key.PSChildName -match '^\{[0-9A-Fa-f-]{36}\}$') { $fmt = 'msi' }
            $out.Add([ordered]@{
                key             = $id
                name            = $k.DisplayName
                version         = $k.DisplayVersion
                vendor          = $k.Publisher
                install_date    = Convert-InstallDate $k.InstallDate
                install_location = $k.InstallLocation
                install_source  = $k.InstallSource
                size_bytes      = $size
                architecture    = $p.Arch
                scope           = $p.Scope
                format          = $fmt
                source          = 'registry'
                product_code    = $key.PSChildName
                uninstall_string = $k.UninstallString
            })
        }
    }
    return @($out | Sort-Object name, version)
}

function Get-AppxRecord {
    $out = @()
    try {
        $out = Get-AppxPackage -ErrorAction Stop | ForEach-Object {
            [ordered]@{
                key              = "appx:$($_.PackageFullName)"
                name             = $_.Name
                version          = "$($_.Version)"
                vendor           = $_.Publisher
                install_date     = $null
                install_location = $_.InstallLocation
                install_source   = $null
                size_bytes       = $null
                architecture     = "$($_.Architecture)"
                scope            = 'user'
                format           = 'appx'
                source           = 'appx'
                product_code     = $_.PackageFullName
                uninstall_string = $null
            }
        }
    } catch { Write-Verbose "ignored: $_" }
    return @($out)
}

function Get-OsPatchRecord {
    $out = @()
    try {
        $out = Get-CimData 'Win32_QuickFixEngineering' | ForEach-Object {
            [ordered]@{
                key           = "patch:$($_.HotFixID)"
                hotfix_id     = $_.HotFixID
                caption       = $_.Caption
                description   = $_.Description
                installed_by  = $_.InstalledBy
                installed_on  = ConvertTo-Iso $_.InstalledOn
                severity      = $null
                status        = 'installed'
                type          = 'os'
            }
        }
    } catch { Write-Verbose "ignored: $_" }
    return @($out)
}

function Get-ServiceRecord {
    $out = @()
    try {
        $out = Get-CimData 'Win32_Service' | ForEach-Object {
            [ordered]@{
                key          = "service:$($_.Name)"
                name         = $_.Name
                display_name = $_.DisplayName
                description  = $_.Description
                service_type = $_.ServiceType
                status       = $_.State
                start_type   = $_.StartMode
                user_account = $_.StartName
                path         = $_.PathName
            }
        }
    } catch { Write-Verbose "ignored: $_" }
    return @($out)
}

function Get-StartupRecord {
    $out = @()
    try {
        $out = Get-CimData 'Win32_StartupCommand' | ForEach-Object {
            [ordered]@{
                key      = "startup:$($_.Name):$($_.Location):$($_.User)"
                name     = $_.Name
                command  = $_.Command
                location = $_.Location
                user     = $_.User
            }
        }
    } catch { Write-Verbose "ignored: $_" }
    return @($out)
}

function Get-DriverRecord {
    $out = @()
    try {
        $out = Get-CimData 'Win32_PnPSignedDriver' | ForEach-Object {
            [ordered]@{
                key           = "driver:$($_.DeviceName):$($_.InfName)"
                device_name   = $_.DeviceName
                device_class  = $_.DeviceClass
                manufacturer  = $_.Manufacturer
                provider      = $_.DriverProviderName
                version       = $_.DriverVersion
                driver_date   = ConvertTo-Iso $_.DriverDate
                is_signed     = $_.IsSigned
                inf_name      = $_.InfName
            }
        }
    } catch { Write-Verbose "ignored: $_" }
    return @($out)
}

function Get-LocalUserRecord {
    $out = @()
    try {
        $out = Get-LocalUser -ErrorAction Stop | ForEach-Object {
            [ordered]@{
                key                = "user:$($_.SID)"
                name               = $_.Name
                full_name          = $_.FullName
                description        = $_.Description
                enabled            = [bool]$_.Enabled
                password_required  = [bool]$_.PasswordRequired
                password_last_set  = ConvertTo-Iso $_.PasswordLastSet
                last_logon         = ConvertTo-Iso $_.LastLogon
                account_expires    = ConvertTo-Iso $_.AccountExpires
                user_may_change_password = [bool]$_.UserMayChangePassword
                sid                = "$($_.SID)"
                account_type       = "$($_.PrincipalSource)"
                disabled           = -not [bool]$_.Enabled
            }
        }
    } catch { Write-Verbose "ignored: $_" }
    if ($out.Count -eq 0) {
        try {
            $out = Get-CimData 'Win32_UserAccount' -Filter 'LocalAccount=True' | ForEach-Object {
                [ordered]@{
                    key               = "user:$($_.SID)"
                    name              = $_.Name
                    full_name         = $_.FullName
                    description       = $_.Description
                    enabled           = -not [bool]$_.Disabled
                    password_required = [bool]$_.PasswordRequired
                    password_last_set = $null
                    last_logon        = $null
                    account_expires   = $null
                    user_may_change_password = $null
                    sid               = $_.SID
                    account_type      = 'local'
                    disabled          = [bool]$_.Disabled
                }
            }
        } catch { Write-Verbose "ignored: $_" }
    }
    return @($out)
}

function Get-LoggedOnUserRecord {
    $out = @()
    $seen = @{}
    try {
        $cs = Get-CimData 'Win32_ComputerSystem'
        if ($cs.UserName) {
            $short = ($cs.UserName -split '\\')[-1]
            $seen[$short.ToLower()] = $true
            $out += [ordered]@{ key = "session:$($cs.UserName)"; user_name = $cs.UserName; session_type = 'console'; logon_time = $null; sid = $null }
        }
    } catch { Write-Verbose "ignored: $_" }
    try {
        foreach ($line in (quser 2>$null)) {
            $t = $line.Trim()
            if ($t -match '^\s*>?\s*USERNAME') { continue }
            if ($t -match '^\s*>?\s*(\S+)\s+(console|rdp-tcp#?\d*)\s+(\d+)\s+(\S+)\s+(\S+)\s*(.*)$') {
                $user = $Matches[1]; $sess = $Matches[2]
                $state = $Matches[4]
                if ($state -match '^(none|disc)$') { continue }
                if ($seen.ContainsKey($user.ToLower())) { continue }
                $seen[$user.ToLower()] = $true
                $tval = ("$($Matches[4]) $($Matches[5]) $($Matches[6])").Trim()
                $out += [ordered]@{ key = "session:$($user):$($sess)"; user_name = $user; session_type = $sess; logon_time = $tval; sid = $null }
            }
        }
    } catch { Write-Verbose "ignored: $_" }
    return @($out)
}

function Get-PrinterRecord {
    $out = @()
    try {
        $out = Get-CimData 'Win32_Printer' | ForEach-Object {
            [ordered]@{
                key         = "printer:$($_.Name)"
                name        = $_.Name
                default     = [bool]$_.Default
                network     = [bool]$_.Network
                shared      = [bool]$_.Shared
                port_name   = $_.PortName
                driver_name = $_.DriverName
                status      = $_.PrinterStatus
                location    = $_.Location
            }
        }
    } catch { Write-Verbose "ignored: $_" }
    return @($out)
}

function Get-MonitorRecord {
    $out = @()
    try {
        $ids = Get-CimInstance -Namespace 'root/wmi' -ClassName 'WmiMonitorID' -ErrorAction Stop
        foreach ($m in $ids) {
            $name = -join (@($m.UserFriendlyName) | Where-Object { $_ -gt 0 } | ForEach-Object { [char]$_ })
            $serial = -join (@($m.SerialNumberID) | Where-Object { $_ -gt 0 } | ForEach-Object { [char]$_ })
            $mfg = -join (@($m.ManufacturerName) | Where-Object { $_ -gt 0 } | ForEach-Object { [char]$_ })
            $out += [ordered]@{ key = "monitor:$serial"; manufacturer = $mfg; name = $name; serial_number = $serial; product_code = $null; size_inches = $null; year_of_manufacture = $m.YearOfManufacture; source = 'edid' }
        }
    } catch { Write-Verbose "ignored: $_" }
    if ($out.Count -eq 0) {
        try {
            $out = Get-CimData 'Win32_DesktopMonitor' | ForEach-Object {
                [ordered]@{ key = "monitor:$($_.DeviceID)"; manufacturer = $_.MonitorManufacturer; name = $_.Name; serial_number = $null; product_code = $_.MonitorType; size_inches = $null; year_of_manufacture = $null; source = 'cim' }
            }
        } catch { Write-Verbose "ignored: $_" }
    }
    return @($out)
}

function Get-UsbRecord {
    $out = @()
    try {
        $out = Get-CimData 'Win32_PnPEntity' -Filter "PNPClass='USB'" | ForEach-Object {
            [ordered]@{
                key         = "usb:$($_.DeviceID)"
                name        = $_.Name
                device_id   = $_.DeviceID
                manufacturer = $_.Manufacturer
                status      = $_.Status
                service     = $_.Service
                class       = $_.PNPClass
            }
        }
    } catch { Write-Verbose "ignored: $_" }
    return @($out)
}

function Get-BatteryRecord {
    $out = @()
    try {
        $bats = Get-CimData 'Win32_Battery'
        $static = @()
        try { $static = Get-CimInstance -Namespace 'root/wmi' -ClassName 'BatteryStaticData' -ErrorAction Stop } catch { Write-Verbose "ignored: $_" }
        $full = @()
        try { $full = Get-CimInstance -Namespace 'root/wmi' -ClassName 'BatteryFullChargedCapacity' -ErrorAction Stop } catch { Write-Verbose "ignored: $_" }
        $cycle = @()
        try { $cycle = Get-CimInstance -Namespace 'root/wmi' -ClassName 'BatteryCycleCount' -ErrorAction Stop } catch { Write-Verbose "ignored: $_" }
        $i = 0
        foreach ($b in $bats) {
            $design = $null; $real = $null; $cycles = $null
            if ($static.Count -gt $i) { $design = [int]$static[$i].DesignedCapacity }
            if ($full.Count -gt $i) { $real = [int]$full[$i].FullChargedCapacity }
            if ($cycle.Count -gt $i) { $cycles = [int]$cycle[$i].CycleCount }
            $runTime = $b.EstimatedRunTime
            if ($null -ne $runTime -and ([long]$runTime -ge 4294967295 -or [long]$runTime -eq 71582788)) { $runTime = $null }
            $out += [ordered]@{
                key               = "battery:$($b.DeviceID)"
                name              = $b.Name
                device_id         = $b.DeviceID
                chemistry         = $b.Chemistry
                status            = $b.BatteryStatus
                percent_remaining = $b.EstimatedChargeRemaining
                run_time_minutes  = $runTime
                design_capacity_mwh = $design
                real_capacity_mwh   = $real
                cycle_count         = $cycles
                voltage_mv          = $b.DesignVoltage
            }
            $i++
        }
    } catch { Write-Verbose "ignored: $_" }
    return @($out)
}

function Get-AntivirusRecord {
    $out = @()
    try {
        $out = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName 'AntiVirusProduct' -ErrorAction Stop | ForEach-Object {
            $state = $null
            try { $state = [int]$_.productState } catch { Write-Verbose "ignored: $_" }
            $enabled = $null
            if ($null -ne $state) { $enabled = [bool](((($state -shr 12) -band 0xF) -in @(0x1, 0x2, 0x3))) }
            [ordered]@{
                key             = "av:$($_.instanceGuid)"
                name            = $_.displayName
                product_state   = if ($null -ne $state) { ('{0:X}' -f $state) } else { $null }
                enabled         = $enabled
                up_to_date      = $null
                version         = $null
                definition_version = $null
                expiration      = $null
                instance_guid   = $_.instanceGuid
                product_exe     = $_.pathToSignedProductExe
            }
        }
    } catch { Write-Verbose "ignored: $_" }
    try {
        $d = Get-MpComputerStatus -ErrorAction Stop
        $found = $false
        foreach ($r in $out) { if ($r.name -match 'Defender') { $found = $true; $r.version = "$($d.AMProductVersion)"; $r.definition_version = "$($d.AntivirusSignatureVersion)"; $r.enabled = [bool]$d.AntivirusEnabled; $r.up_to_date = ([int]$d.AntivirusSignatureAge -le 1) } }
        if (-not $found) {
            $out += [ordered]@{ key = 'av:windows-defender'; name = 'Windows Defender'; product_state = $null; enabled = [bool]$d.AntivirusEnabled; up_to_date = ([int]$d.AntivirusSignatureAge -le 1); version = "$($d.AMProductVersion)"; definition_version = "$($d.AntivirusSignatureVersion)"; expiration = $null; instance_guid = $null; product_exe = $null }
        }
    } catch { Write-Verbose "ignored: $_" }
    return @($out)
}

function Get-FirewallRecord {
    $out = @()
    if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
        try {
            $out = Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
                [ordered]@{
                    key              = "firewall:$($_.Name)"
                    profile          = "$($_.Name)"
                    enabled          = [bool]$_.Enabled
                    default_inbound  = "$($_.DefaultInboundAction)"
                    default_outbound = "$($_.DefaultOutboundAction)"
                }
            }
        } catch { Write-Verbose "ignored: $_" }
    }
    if (@($out).Count -eq 0) {
        $profiles = @(
            @{ Key = 'DomainProfile'; Name = 'domain' },
            @{ Key = 'StandardProfile'; Name = 'private' },
            @{ Key = 'PublicProfile'; Name = 'public' }
        )
        foreach ($p in $profiles) {
            $path = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\$($p.Key)"
            try {
                $k = Get-ItemProperty $path -ErrorAction Stop
                $rec = [ordered]@{ key = "firewall:$($p.Name)"; profile = $p.Name }
                if ($null -ne $k.EnableFirewall) { $rec['enabled'] = ([int]$k.EnableFirewall -eq 1) }
                if ($null -ne $k.DefaultInboundAction) {
                    if ([int]$k.DefaultInboundAction -eq 1) { $rec['default_inbound'] = 'allow' } else { $rec['default_inbound'] = 'block' }
                }
                if ($null -ne $k.DefaultOutboundAction) {
                    if ([int]$k.DefaultOutboundAction -eq 1) { $rec['default_outbound'] = 'block' } else { $rec['default_outbound'] = 'allow' }
                }
                $out += $rec
            } catch { Write-Verbose "ignored: $_" }
        }
    }
    return @($out)
}

function Get-UacRecord {
    $u = $null
    try { $u = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop } catch { Write-Verbose "ignored: $_" }
    if ($null -eq $u) {
        return @([ordered]@{ key = 'uac'; enable_lua = $null; consent_prompt_behavior_admin = $null; prompt_on_secure_desktop = $null })
    }
    return @([ordered]@{
        key                            = 'uac'
        enable_lua                     = [int]$u.EnableLUA
        consent_prompt_behavior_admin  = [int]$u.ConsentPromptBehaviorAdmin
        prompt_on_secure_desktop       = [int]$u.PromptOnSecureDesktop
    })
}

function Get-ProcessRecord {
    $out = @()
    try {
        $out = Get-CimData 'Win32_Process' | ForEach-Object {
            [ordered]@{
                key             = "process:$($_.ProcessId):$($_.CreationDate)"
                name            = $_.Name
                pid             = $_.ProcessId
                parent_pid      = $_.ParentProcessId
                working_set_bytes = $_.WorkingSetSize
                executable_path = $_.ExecutablePath
                command_line    = $_.CommandLine
                start_time      = ConvertTo-Iso $_.CreationDate
            }
        }
    } catch { Write-Verbose "ignored: $_" }
    return @($out)
}

$Identity = Get-HostIdentity
$Elevated = Test-IsElevated
$Level = $ProfileLevel[$CollectionProfile]

$hostRecord = $null; try { $hostRecord = Get-HostRecord } catch { Write-Verbose "ignored: $_" }

$plan = [ordered]@{
    host                = @{ level = 0; body = { Get-HostRecord } }
    os                  = @{ level = 0; body = { Get-OsRecord } }
    hardware            = @{ level = 0; body = { Get-HardwareRecord } }
    virtualization      = @{ level = 0; body = { Get-VirtualizationRecord } }
    secureboot          = @{ level = 0; body = { Get-SecureBootRecord } }
    uac                 = @{ level = 0; body = { Get-UacRecord } }
    antivirus           = @{ level = 0; body = { Get-AntivirusRecord } }
    firewall_profiles   = @{ level = 0; body = { Get-FirewallRecord } }
    volumes             = @{ level = 0; body = { Get-VolumeRecord } }
    network_interfaces  = @{ level = 0; body = { Get-NetworkRecord } }
    bios                = @{ level = 1; body = { Get-BiosRecord } }
    processors          = @{ level = 1; body = { Get-ProcessorRecord } }
    memory_modules      = @{ level = 1; body = { Get-MemoryModuleRecord } }
    graphics            = @{ level = 1; body = { Get-GraphicsRecord } }
    tpm                 = @{ level = 1; body = { Get-TpmRecord } }
    software            = @{ level = 1; body = { Limit-Item (Get-SoftwareRecord) $MaxListItems 'software' } }
    os_patches          = @{ level = 1; body = { Get-OsPatchRecord } }
    local_users         = @{ level = 1; body = { Get-LocalUserRecord } }
    logged_on_users     = @{ level = 1; body = { Get-LoggedOnUserRecord } }
    batteries           = @{ level = 1; body = { Get-BatteryRecord } }
    printers            = @{ level = 1; body = { Get-PrinterRecord } }
    services            = @{ level = 2; body = { Limit-Item (Get-ServiceRecord) $MaxListItems 'services' } }
    startup_items       = @{ level = 2; body = { Limit-Item (Get-StartupRecord) $MaxListItems 'startup_items' } }
    drivers             = @{ level = 2; body = { Limit-Item (Get-DriverRecord) $MaxListItems 'drivers' } }
    physical_disks      = @{ level = 2; body = { Get-PhysicalDiskRecord } }
    listening_ports     = @{ level = 2; body = { Limit-Item (Get-ListeningPortRecord) $MaxListItems 'listening_ports' } }
    monitors            = @{ level = 2; body = { Get-MonitorRecord } }
    usb_devices         = @{ level = 2; body = { Limit-Item (Get-UsbRecord) $MaxListItems 'usb_devices' } }
}
if ($IncludeAppx) { $plan['appx_packages'] = @{ level = 2; body = { Limit-Item (Get-AppxRecord) $MaxListItems 'appx_packages' } } }
if ($IncludeProcesses) { $plan['processes'] = @{ level = 2; body = { Limit-Item (Get-ProcessRecord) $MaxListItems 'processes' } } }

foreach ($name in $plan.Keys) {
    if ($plan[$name].level -le $Level) { Add-Collected -Type $name -Body $plan[$name].body }
}

$decorators = [ordered]@{
    username       = if ($hostRecord) { $hostRecord.current_user } else { "$env:USERDOMAIN\$env:USERNAME" }
    upn            = "$env:USERDOMAIN\$env:USERNAME"
    uptime_seconds = Get-UptimeSpan
    os_platform    = 'windows'
    is_elevated    = $Elevated
}

$script:Summarized = $false
$action = 'snapshot'
$baseScanId = $null
$statePath = Resolve-StatePath $StatePath
if ($Delta) {
    $prevState = Read-JsonFile $statePath
    $prevMaps = Convert-StateToMap $prevState
    if ($prevMaps.Count -gt 0) {
        if ($prevState -and $prevState.scan_id) { $baseScanId = [string]$prevState.scan_id }
        $script:OutEntities = Get-DeltaEntity $prevMaps
        $action = 'delta'
    } else {
        $script:OutEntities = $script:Entities
        $action = 'snapshot'
    }
} else {
    $script:OutEntities = $script:Entities
}
Optimize-PayloadBudget $MaxPayloadBytes

$envelope = [ordered]@{
    schema_version  = $SchemaVersion
    scan_id         = [guid]::NewGuid().ToString()
    action          = $action
    base_scan_id    = $baseScanId
    partial         = [bool]($CollectionProfile -ne 'full')
    host_identifier = $Identity
    calendar_time   = $script:NowIso
    unix_time       = [long][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    received_at     = $null
    decorators      = $decorators
    agent           = [ordered]@{
        name         = $AgentName
        version      = $AgentVersion
        os           = 'windows'
        arch         = $env:PROCESSOR_ARCHITECTURE
        elevated     = $Elevated
        powershell   = $PSVersionTable.PSVersion.ToString()
        profile      = $CollectionProfile
        user         = "$env:USERDOMAIN\$env:USERNAME"
    }
    truncated       = @($script:Truncated)
    entity_errors   = $script:EntityErrors
    entities        = $script:OutEntities
}

$jsonCompact = $envelope | ConvertTo-Json -Depth 24 -Compress
$jsonPretty = $jsonCompact
try { $jsonPretty = $envelope | ConvertTo-Json -Depth 24 } catch { Write-Verbose "ignored: $_" }
$jsonWire = $jsonCompact
if ($Compress) {
    $b64 = Compress-Base64 $jsonCompact
    $wrapper = [ordered]@{
        content_encoding   = 'gzip+base64'
        schema_version     = $SchemaVersion
        action             = $action
        scan_id            = $envelope.scan_id
        uncompressed_bytes = $jsonCompact.Length
        compressed_bytes   = $b64.Length
        data               = $b64
    }
    $jsonWire = $wrapper | ConvertTo-Json -Depth 6 -Compress
}

if ($OutputPath) { Write-Utf8 -Path $OutputPath -Text $jsonPretty }

$header = New-Object System.Collections.Specialized.OrderedDictionary
foreach ($k in $envelope.Keys) { if ($k -ne 'entities') { $header.Add($k, $envelope[$k]) } }

$delivered = $false
if ($DryRun -or -not $Endpoint) {
    if ($Compress -or $Compact) { Write-Output $jsonWire } else { Write-Output $jsonPretty }
    $delivered = $true
} else {
    $spoolDir = Join-Path $env:LOCALAPPDATA 'Sopdet\spool'
    $ingestResult = Send-Ingest $header $script:OutEntities $Endpoint $ApiKey $Compress.IsPresent $ChunkBytes $MaxRetries $Proxy $spoolDir $envelope.scan_id
    $delivered = [bool]$ingestResult.delivered
    [ordered]@{
        posted    = $delivered
        endpoint  = $Endpoint
        scan_id   = $envelope.scan_id
        device_id = $Identity.device_id
        chunks    = $ingestResult.chunks
        spooled   = $ingestResult.spooled
    } | ConvertTo-Json -Depth 6 -Compress
}

if ($delivered -and -not $script:Summarized) {
    try {
        $stateObj = Get-StateObject $envelope.scan_id
        Write-Utf8 -Path $statePath -Text ($stateObj | ConvertTo-Json -Depth 24 -Compress)
    } catch { Write-Verbose "ignored: $_" }
}
