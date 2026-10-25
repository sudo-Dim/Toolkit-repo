<#
.SYNOPSIS
    System Security Dashboard - Collects security-relevant system data
    and generates a minimalist, Apple-inspired HTML report.
.DESCRIPTION
    Gathers: System Info, CPU/RAM/Disk, Top Processes, Event Logs
    (Failed Logins, Service Installs, Process Creation), Network Connections,
    Local Users, Firewall Status, Autostart Entries, Scheduled Tasks.
.NOTES
    Run as Administrator for full Event Log access.
    Native GUI consumes the returned snapshot. HTML export and browser opening are optional.
#>

[CmdletBinding()]
param(
    [string]$OutputPath,
    [ValidateRange(1,1000)][int]$TopNProcs = 15,
    [ValidateRange(1,8760)][int]$EventHours = 24,
    [ValidateRange(1,10000)][int]$MaxEvents = 50,
    [switch]$OpenReport,
    [switch]$NoReport
)

$collectionErrors = [System.Collections.Generic.List[object]]::new()
function Invoke-SafeCollect {
    param([string]$Name, [scriptblock]$Block)
    $ErrorActionPreference = 'Stop'
    try { & $Block }
    catch {
        $collectionErrors.Add([PSCustomObject]@{ Section=$Name; Error=$_.Exception.Message })
    }
}

# Reuse one snapshot: no repeated CIM queries or process lookup per socket.
$osSnapshot = Invoke-SafeCollect 'Operating System' { Get-CimInstance Win32_OperatingSystem }
$cpuSnapshot = @(Invoke-SafeCollect 'Processor' { Get-CimInstance Win32_Processor })
$processSnapshot = @(Invoke-SafeCollect 'Processes' { Get-Process })
$processNames = @{}
foreach ($process in $processSnapshot) { $processNames[$process.Id] = $process.ProcessName }

# --- 1. System Information ---
$SysInfo = Invoke-SafeCollect 'System Info' {
    $os  = $osSnapshot
    if (-not $os) { throw "Operating system data unavailable" }
    $cs  = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $span = New-TimeSpan -Start $os.LastBootUpTime
    $uptimeStr = '{0}d {1}h {2}m' -f $span.Days, $span.Hours, $span.Minutes
    [PSCustomObject]@{
        Hostname      = $env:COMPUTERNAME
        Domain        = $cs.Domain
        OS            = $os.Caption
        Build         = $os.BuildNumber
        Architecture  = $os.OSArchitecture
        InstallDate   = $os.InstallDate.ToString('dd.MM.yyyy')
        LastBoot      = $os.LastBootUpTime.ToString('dd.MM.yyyy HH:mm')
        Uptime        = $uptimeStr
        Manufacturer  = $cs.Manufacturer
        Model         = $cs.Model
        SerialNumber  = $bios.SerialNumber
        CurrentUser   = ($env:USERDOMAIN + '\' + $env:USERNAME)
        TimeZone      = (Get-TimeZone).DisplayName
    }
}

# --- 2. Hardware Metrics ---
$HwMetrics = Invoke-SafeCollect 'Hardware Metrics' {
    $os   = $osSnapshot
    $cpu  = $cpuSnapshot
    if (-not $os -or -not $cpu.Count) { throw "Hardware data unavailable" }
    $disks = Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3'

    $cpuLoad = ($cpu | Measure-Object -Property LoadPercentage -Average).Average

    $totalRAM = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
    $freeRAM  = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
    $usedRAM  = [math]::Round($totalRAM - $freeRAM, 1)
    $ramPct   = if ($totalRAM -gt 0) { [math]::Round(($usedRAM / $totalRAM) * 100, 0) } else { 0 }

    $diskInfo = foreach ($d in $disks) {
        $totalGB = [math]::Round($d.Size / 1GB, 1)
        $freeGB  = [math]::Round($d.FreeSpace / 1GB, 1)
        $usedGB  = [math]::Round($totalGB - $freeGB, 1)
        $pct     = if ($totalGB -gt 0) { [math]::Round(($usedGB / $totalGB) * 100, 0) } else { 0 }
        [PSCustomObject]@{
            Drive   = $d.DeviceID
            Label   = $d.VolumeName
            TotalGB = $totalGB
            UsedGB  = $usedGB
            FreeGB  = $freeGB
            Percent = $pct
        }
    }

    [PSCustomObject]@{
        CPUName    = ($cpu | Select-Object -First 1).Name.Trim()
        CPUCores   = ($cpu | Select-Object -First 1).NumberOfCores
        CPUThreads = ($cpu | Select-Object -First 1).NumberOfLogicalProcessors
        CPULoad    = $cpuLoad
        RAMTotalGB = $totalRAM
        RAMUsedGB  = $usedRAM
        RAMFreeGB  = $freeRAM
        RAMPercent = $ramPct
        Disks      = $diskInfo
    }
}

# --- 3. Top Processes ---
$TopProcesses = Invoke-SafeCollect 'Top Processes' {
    $processSnapshot | Where-Object { $_.ProcessName -ne 'Idle' } |
        Sort-Object CPU -Descending |
        Select-Object -First $TopNProcs |
        ForEach-Object {
            $memMB = [math]::Round($_.WorkingSet64 / 1MB, 1)
            $cpuSec = [math]::Round($_.CPU, 1)
            $procPath = '--'
            try { $procPath = $_.Path } catch {}
            [PSCustomObject]@{
                PID     = $_.Id
                Name    = $_.ProcessName
                CPU_s   = $cpuSec
                MemMB   = $memMB
                Threads = $_.Threads.Count
                Handles = $_.HandleCount
                Path    = $procPath
            }
        }
}

# --- 4. Windows Event Logs ---
$EventCutoff = (Get-Date).AddHours(-$EventHours)

$FailedLogins = Invoke-SafeCollect 'Failed Logins (4625)' {
    try {
        Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4625
            StartTime = $EventCutoff
        } -MaxEvents $MaxEvents -ErrorAction Stop |
        ForEach-Object {
            $xml = [xml]$_.ToXml()
            $data = $xml.Event.EventData.Data
            [PSCustomObject]@{
                Time      = $_.TimeCreated.ToString('dd.MM. HH:mm:ss')
                Account   = ($data | Where-Object Name -eq 'TargetUserName').'#text'
                Domain    = ($data | Where-Object Name -eq 'TargetDomainName').'#text'
                Source    = ($data | Where-Object Name -eq 'IpAddress').'#text'
                Reason    = ($data | Where-Object Name -eq 'FailureReason').'#text'
                LogonType = ($data | Where-Object Name -eq 'LogonType').'#text'
            }
        }
    } catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
    }
}

$ServiceInstalls = Invoke-SafeCollect 'Service Installs (7045)' {
    try {
        Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 7045
            StartTime = $EventCutoff
        } -MaxEvents $MaxEvents -ErrorAction Stop |
        ForEach-Object {
            $xml = [xml]$_.ToXml()
            $data = $xml.Event.EventData.Data
            [PSCustomObject]@{
                Time        = $_.TimeCreated.ToString('dd.MM. HH:mm:ss')
                ServiceName = ($data | Where-Object Name -eq 'ServiceName').'#text'
                ImagePath   = ($data | Where-Object Name -eq 'ImagePath').'#text'
                AccountName = ($data | Where-Object Name -eq 'AccountName').'#text'
                StartType   = ($data | Where-Object Name -eq 'StartType').'#text'
            }
        }
    } catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
    }
}

$WarningsErrors = Invoke-SafeCollect 'System Warnings and Errors' {
    try {
        Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Level     = 1,2,3
            StartTime = $EventCutoff
        } -MaxEvents $MaxEvents -ErrorAction Stop |
        ForEach-Object {
            $msg = if ($null -ne $_.Message) { [string]$_.Message } else { '' }
            [PSCustomObject]@{
                Time     = $_.TimeCreated.ToString('dd.MM.yyyy HH:mm:ss')
                Level    = switch ($_.Level) { 1 {'Critical'} 2 {'Error'} 3 {'Warning'} }
                Source   = $_.ProviderName
                ID       = $_.Id
                RecordID = $_.RecordId
                Message  = $msg
            }
        }
    } catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
    }
}

# --- 5. Network Connections ---
$NetConnections = Invoke-SafeCollect 'Network Connections' {
    Get-NetTCPConnection -State Established,Listen -ErrorAction Stop |
        ForEach-Object {
            $procName = '--'
            if ($processNames.ContainsKey([int]$_.OwningProcess)) { $procName = $processNames[[int]$_.OwningProcess] }
            $localAddress = if ($_.LocalAddress.Contains(':')) { '[' + $_.LocalAddress + ']' } else { $_.LocalAddress }
            $remoteAddress = if ($_.RemoteAddress.Contains(':')) { '[' + $_.RemoteAddress + ']' } else { $_.RemoteAddress }
            $localStr  = $localAddress  + ':' + $_.LocalPort
            $remoteStr = $remoteAddress + ':' + $_.RemotePort
            [PSCustomObject]@{
                LocalAddr  = $localStr
                RemoteAddr = $remoteStr
                State      = $_.State.ToString()
                PID        = $_.OwningProcess
                Process    = $procName
            }
        } | Sort-Object State, Process
}

# --- 6. Local Users and Admins ---
$LocalUsers = Invoke-SafeCollect 'Local Users' {
    Get-LocalUser | ForEach-Object {
        $lastLogon = 'Never'
        if ($_.LastLogon) { $lastLogon = $_.LastLogon.ToString('dd.MM.yyyy HH:mm') }
        $pwdSet = '--'
        if ($_.PasswordLastSet) { $pwdSet = $_.PasswordLastSet.ToString('dd.MM.yyyy') }
        [PSCustomObject]@{
            Name        = $_.Name
            Enabled     = $_.Enabled
            LastLogon   = $lastLogon
            PwdLastSet  = $pwdSet
            PwdExpires  = $_.PasswordExpires
            Description = $_.Description
        }
    }
}

$LocalAdmins = Invoke-SafeCollect 'Local Admins' {
    (Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop).Name
}

# --- 7. Firewall Status ---
$FirewallStatus = Invoke-SafeCollect 'Firewall' {
    Get-NetFirewallProfile | ForEach-Object {
        [PSCustomObject]@{
            Profile = $_.Name
            Enabled = $_.Enabled
            DefaultInboundAction  = $_.DefaultInboundAction.ToString()
            DefaultOutboundAction = $_.DefaultOutboundAction.ToString()
        }
    }
}

# --- 8. Autostart Entries ---
$AutoStarts = Invoke-SafeCollect 'Autostart Entries' {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($p in $paths) {
        if (Test-Path $p) {
            $key = Get-Item $p
            foreach ($vname in $key.GetValueNames()) {
                $shortLoc = $p.Replace('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\','HKLM\..\').Replace('HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\','HKCU\..\')
                [PSCustomObject]@{
                    Location = $shortLoc
                    Name     = $vname
                    Command  = $key.GetValue($vname)
                }
            }
        }
    }
}

# --- 9. Scheduled Tasks (non-Microsoft) ---
$SchedTasks = Invoke-SafeCollect 'Scheduled Tasks' {
    Get-ScheduledTask | Where-Object {
        $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled'
    } | Select-Object -First 30 | ForEach-Object {
        $task = $_
        $info = Invoke-SafeCollect ('Task: ' + $task.TaskName) { $task | Get-ScheduledTaskInfo -ErrorAction Stop }
        $lastRun = '--'
        $nextRun = '--'
        if ($info.LastRunTime -and $info.LastRunTime.Year -gt 1999) {
            $lastRun = $info.LastRunTime.ToString('dd.MM.yyyy HH:mm')
        }
        if ($info.NextRunTime -and $info.NextRunTime.Year -gt 1999) {
            $nextRun = $info.NextRunTime.ToString('dd.MM.yyyy HH:mm')
        }
        [PSCustomObject]@{
            Name     = $_.TaskName
            Path     = $_.TaskPath
            State    = $_.State.ToString()
            LastRun  = $lastRun
            NextRun  = $nextRun
            Author   = $_.Author
        }
    }
}

# --- 10. Security Config Quick Checks ---
$SecurityChecks = Invoke-SafeCollect 'Security Checks' {
    $checks = @()

    $smb1 = $null
    try { $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch {}
    if ($smb1 -eq $false) {
        $checks += [PSCustomObject]@{ Check='SMBv1 Disabled'; Status='Pass'; Detail='SMBv1 is disabled' }
    } elseif ($null -eq $smb1) {
        $checks += [PSCustomObject]@{ Check='SMBv1 Disabled'; Status='Unknown'; Detail='Could not read SMB configuration' }
    } else {
        $checks += [PSCustomObject]@{ Check='SMBv1 Disabled'; Status='Fail'; Detail='SMBv1 is ENABLED - security risk' }
    }

    $rdp = $null
    try { $rdp = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop).fDenyTSConnections } catch {}
    if ($rdp -eq 1) {
        $checks += [PSCustomObject]@{ Check='RDP Status'; Status='Info'; Detail='RDP is disabled' }
    } elseif ($null -eq $rdp) {
        $checks += [PSCustomObject]@{ Check='RDP Status'; Status='Unknown'; Detail='Could not read RDP configuration' }
    } else {
        $checks += [PSCustomObject]@{ Check='RDP Status'; Status='Warn'; Detail='RDP is enabled' }
    }

    $defender = $null
    try { $defender = Get-MpComputerStatus -ErrorAction Stop } catch {}
    if ($defender) {
        if ($defender.RealTimeProtectionEnabled) {
            $checks += [PSCustomObject]@{ Check='Real-Time Protection'; Status='Pass'; Detail='Active' }
        } else {
            $checks += [PSCustomObject]@{ Check='Real-Time Protection'; Status='Fail'; Detail='DISABLED' }
        }
        $sigDate = if ($defender.AntivirusSignatureLastUpdated) { $defender.AntivirusSignatureLastUpdated.ToString('dd.MM.yyyy HH:mm') } else { 'Unknown' }
        $checks += [PSCustomObject]@{ Check='Antivirus Signatures'; Status='Info'; Detail=('Updated: ' + $sigDate) }
    }

    if (-not $defender) {
        $checks += [PSCustomObject]@{ Check='Microsoft Defender'; Status='Unknown'; Detail='Status unavailable; another antivirus may be installed' }
    }

    $sbl = $null
    try { $sbl = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction Stop).EnableScriptBlockLogging } catch {}
    if ($sbl -eq 1) {
        $checks += [PSCustomObject]@{ Check='PS ScriptBlock Logging'; Status='Pass'; Detail='Enabled' }
    } else {
        $checks += [PSCustomObject]@{ Check='PS ScriptBlock Logging'; Status='Warn'; Detail='Not configured' }
    }

    $uac = $null
    try { $uac = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop).EnableLUA } catch {}
    if ($uac -eq 1) {
        $checks += [PSCustomObject]@{ Check='UAC Enabled'; Status='Pass'; Detail='UAC is active' }
    } elseif ($null -eq $uac) {
        $checks += [PSCustomObject]@{ Check='UAC Enabled'; Status='Unknown'; Detail='Could not read UAC configuration' }
    } else {
        $checks += [PSCustomObject]@{ Check='UAC Enabled'; Status='Fail'; Detail='UAC is DISABLED' }
    }

    $checks
}

# =============================================
# HTML REPORT GENERATION
# =============================================
$result = [PSCustomObject]@{
    CollectedAt = (Get-Date).ToString('o')
    System = $SysInfo
    Hardware = $HwMetrics
    Processes = @($TopProcesses | Where-Object { $null -ne $_ })
    FailedLogins = @($FailedLogins | Where-Object { $null -ne $_ })
    ServiceInstalls = @($ServiceInstalls | Where-Object { $null -ne $_ })
    SystemEvents = @($WarningsErrors | Where-Object { $null -ne $_ })
    Network = @($NetConnections | Where-Object { $null -ne $_ })
    Users = @($LocalUsers | Where-Object { $null -ne $_ })
    Administrators = @($LocalAdmins | Where-Object { $null -ne $_ })
    Firewall = @($FirewallStatus | Where-Object { $null -ne $_ })
    Autostart = @($AutoStarts | Where-Object { $null -ne $_ })
    Tasks = @($SchedTasks | Where-Object { $null -ne $_ })
    Security = @($SecurityChecks | Where-Object { $null -ne $_ })
    Errors = $collectionErrors.ToArray()
    ProcessCount = $processSnapshot.Count
    Html = $null
}
if ($NoReport) { return $result }

# Fallbacks, falls eine Sammlung fehlgeschlagen ist (sonst null.ToString()-Crash beim HTML-Aufbau)
if (-not $SysInfo) {
    $SysInfo = [PSCustomObject]@{
        Hostname = $env:COMPUTERNAME; Domain = '--'; OS = '--'; Build = '--'; Architecture = '--'
        InstallDate = '--'; LastBoot = '--'; Uptime = '--'; Manufacturer = '--'; Model = '--'
        SerialNumber = '--'; CurrentUser = ($env:USERDOMAIN + '\' + $env:USERNAME); TimeZone = '--'
    }
}
if (-not $HwMetrics) {
    $HwMetrics = [PSCustomObject]@{
        CPUName = '--'; CPUCores = 0; CPUThreads = 0; CPULoad = 0
        RAMTotalGB = 0; RAMUsedGB = 0; RAMFreeGB = 0; RAMPercent = 0; Disks = @()
    }
}

$reportTime = Get-Date -Format 'dd. MMMM yyyy, HH:mm:ss'

# --- Helper: Build table rows ---
function ConvertTo-HtmlTableRows {
    param($Data, [string[]]$Properties)
    if (-not $Data) {
        $colCount = $Properties.Count
        return "<tr><td colspan='$colCount' class='empty'>No data collected</td></tr>"
    }
    $rows = [System.Text.StringBuilder]::new()
    foreach ($item in $Data) {
        [void]$rows.Append('<tr>')
        foreach ($prop in $Properties) {
            $val = $item.$prop
            if ($null -eq $val) { $val = '--' }
            $valStr = $val.ToString()
            $class = ''
            if ($valStr -eq 'Fail' -or $valStr -eq 'Critical' -or $valStr -eq 'Error') { $class = ' class="tag-red"' }
            elseif ($valStr -eq 'Pass') { $class = ' class="tag-green"' }
            elseif ($valStr -eq 'Warn' -or $valStr -eq 'Warning') { $class = ' class="tag-yellow"' }
            elseif ($valStr -eq 'Info') { $class = ' class="tag-blue"' }
            elseif ($valStr -eq 'True')  { $class = ' class="tag-green"'; $valStr = 'Yes' }
            elseif ($valStr -eq 'False') { $class = ' class="tag-red"'; $valStr = 'No' }
            if ($valStr -eq 'Established') { $class = ' class="tag-green"' }
            if ($valStr -eq 'Listen') { $class = ' class="tag-blue"' }
            $escaped = [System.Net.WebUtility]::HtmlEncode($valStr)
            if ($prop -eq 'Message') {
                $preview = ($valStr -replace '[\r\n]+', ' ')
                if ($preview.Length -gt 120) { $preview = $preview.Substring(0,120) + '...' }
                [void]$rows.Append('<td class="message-cell"><details><summary>' + [System.Net.WebUtility]::HtmlEncode($preview) + ' (Volltext)</summary><div class="event-message">' + $escaped + '</div></details></td>')
            } elseif ($class) {
                [void]$rows.Append('<td><span' + $class + '>' + $escaped + '</span></td>')
            } else {
                [void]$rows.Append('<td>' + $escaped + '</td>')
            }
        }
        [void]$rows.Append('</tr>')
    }
    return $rows.ToString()
}

function New-HeaderRow {
    param([string[]]$Headers)
    $h = '<tr>'
    foreach ($header in $Headers) { $h += '<th>' + $header + '</th>' }
    return ($h + '</tr>')
}

# --- Ring gauge SVG helper ---
function New-RingGauge {
    param([int]$Percent, [string]$Label, [string]$SubLabel)
    $Percent = [math]::Max(0, [math]::Min(100, $Percent))
    $Label = [System.Net.WebUtility]::HtmlEncode($Label)
    $SubLabel = [System.Net.WebUtility]::HtmlEncode($SubLabel)
    $color = '#34c759'
    if ($Percent -ge 90) { $color = '#ff3b30' }
    elseif ($Percent -ge 70) { $color = '#ff9500' }
    $dashArray = ([math]::Round(251.2 * $Percent / 100, 1)).ToString([Globalization.CultureInfo]::InvariantCulture)
    $svg = '<div class="gauge">'
    $svg += '<svg viewBox="0 0 100 100">'
    $svg += '<circle cx="50" cy="50" r="40" fill="none" stroke="rgba(142,142,147,0.15)" stroke-width="7"/>'
    $svg += '<circle cx="50" cy="50" r="40" fill="none" stroke="' + $color + '" stroke-width="7" '
    $svg += 'stroke-dasharray="' + $dashArray + ' 251.2" stroke-linecap="round" '
    $svg += 'transform="rotate(-90 50 50)" class="gauge-ring"/>'
    $svg += '</svg>'
    $svg += '<div class="gauge-text"><span class="gauge-value">' + $Percent + '<small>%</small></span></div>'
    $svg += '<div class="gauge-label">' + $Label + '</div>'
    $svg += '<div class="gauge-sub">' + $SubLabel + '</div>'
    $svg += '</div>'
    return $svg
}

# --- Disk bars ---
$diskBarsHtml = ''
if ($HwMetrics -and $HwMetrics.Disks) {
    foreach ($d in $HwMetrics.Disks) {
        $color = '#34c759'
        if ($d.Percent -ge 90) { $color = '#ff3b30' }
        elseif ($d.Percent -ge 70) { $color = '#ff9500' }
        $dlabel = $d.Drive
        if ($d.Label) { $dlabel = $d.Drive + ' ' + $d.Label }
        $diskBarsHtml += '<div class="disk-item">'
        $diskBarsHtml += '<div class="disk-header">'
        $diskBarsHtml += '<span class="disk-name">' + [System.Net.WebUtility]::HtmlEncode($dlabel) + '</span>'
        $diskBarsHtml += '<span class="disk-stats">' + $d.UsedGB + ' / ' + $d.TotalGB + ' GB (' + $d.Percent + '%)</span>'
        $diskBarsHtml += '</div>'
        $diskBarsHtml += '<div class="bar-track"><div class="bar-fill" style="width:' + $d.Percent + '%;background:' + $color + '"></div></div>'
        $diskBarsHtml += '</div>'
    }
}

# --- Security checks cards ---
$securityCardsHtml = ''
if ($SecurityChecks) {
    foreach ($c in $SecurityChecks) {
        $icon = 'i'
        $statusClass = 'check-info'
        if ($c.Status -eq 'Pass')  { $icon = '&#10003;'; $statusClass = 'check-pass' }
        if ($c.Status -eq 'Fail')  { $icon = '&#10007;'; $statusClass = 'check-fail' }
        if ($c.Status -eq 'Warn')  { $icon = '!'; $statusClass = 'check-warn' }
        $escapedDetail = [System.Net.WebUtility]::HtmlEncode($c.Detail)
        $securityCardsHtml += '<div class="check-card ' + $statusClass + '">'
        $securityCardsHtml += '<div class="check-icon">' + $icon + '</div>'
        $securityCardsHtml += '<div class="check-body">'
        $securityCardsHtml += '<div class="check-title">' + $c.Check + '</div>'
        $securityCardsHtml += '<div class="check-detail">' + $escapedDetail + '</div>'
        $securityCardsHtml += '</div></div>'
    }
}

# --- Admins list ---
$adminsHtml = ''
if ($LocalAdmins) {
    foreach ($a in $LocalAdmins) {
        $escapedA = [System.Net.WebUtility]::HtmlEncode($a)
        $adminsHtml += '<span class="admin-badge">' + $escapedA + '</span>'
    }
}

# --- Build table rows ---
$fwRows          = ConvertTo-HtmlTableRows -Data $FirewallStatus -Properties @('Profile','Enabled','DefaultInboundAction','DefaultOutboundAction')
$procRows        = ConvertTo-HtmlTableRows -Data $TopProcesses -Properties @('PID','Name','CPU_s','MemMB','Threads','Handles')
$failedLoginRows = ConvertTo-HtmlTableRows -Data $FailedLogins -Properties @('Time','Account','Domain','Source','LogonType')
$serviceRows     = ConvertTo-HtmlTableRows -Data $ServiceInstalls -Properties @('Time','ServiceName','ImagePath','AccountName','StartType')
$warnErrorRows   = ConvertTo-HtmlTableRows -Data $WarningsErrors -Properties @('Time','Level','Source','ID','RecordID','Message')
$netRows         = ConvertTo-HtmlTableRows -Data $NetConnections -Properties @('Process','PID','LocalAddr','RemoteAddr','State')
$userRows        = ConvertTo-HtmlTableRows -Data $LocalUsers -Properties @('Name','Enabled','LastLogon','PwdLastSet','Description')
$autostartRows   = ConvertTo-HtmlTableRows -Data $AutoStarts -Properties @('Location','Name','Command')
$taskRows        = ConvertTo-HtmlTableRows -Data $SchedTasks -Properties @('Name','State','LastRun','NextRun','Author')

# --- Build gauges ---
$cpuSub = $HwMetrics.CPUCores.ToString() + 'C / ' + $HwMetrics.CPUThreads.ToString() + 'T'
$ramSub = $HwMetrics.RAMUsedGB.ToString() + ' / ' + $HwMetrics.RAMTotalGB.ToString() + ' GB'
$cpuGauge = New-RingGauge -Percent ([int]$HwMetrics.CPULoad) -Label 'CPU' -SubLabel $cpuSub
$ramGauge = New-RingGauge -Percent ([int]$HwMetrics.RAMPercent) -Label 'Memory' -SubLabel $ramSub

# --- Counts ---
$nProcs   = $processSnapshot.Count
$nConns   = 0
if ($NetConnections) { $nConns = @($NetConnections | Where-Object { $null -ne $_ }).Count }
$nEvents  = @($FailedLogins | Where-Object { $null -ne $_ }).Count + @($ServiceInstalls | Where-Object { $null -ne $_ }).Count + @($WarningsErrors | Where-Object { $null -ne $_ }).Count
$nChecks  = 0
if ($SecurityChecks) { $nChecks = @($SecurityChecks | Where-Object { $_.Status -eq 'Fail' }).Count }

$failColor = 'var(--green)'
if ($nChecks -gt 0) { $failColor = 'var(--red)' }

$secCount = 0
if ($SecurityChecks) { $secCount = @($SecurityChecks | Where-Object { $null -ne $_ }).Count }

# --- Header rows ---
$fwHdr   = New-HeaderRow @('Profile','Enabled','Inbound','Outbound')
$procHdr = New-HeaderRow @('PID','Name','CPU (s)','Mem (MB)','Threads','Handles')
$flHdr   = New-HeaderRow @('Time','Account','Domain','Source IP','Logon Type')
$siHdr   = New-HeaderRow @('Time','Service','Image Path','Account','Start Type')
$weHdr   = New-HeaderRow @('Time','Level','Source','ID','RecordID','Message')
$netHdr  = New-HeaderRow @('Process','PID','Local','Remote','State')
$uHdr    = New-HeaderRow @('Name','Enabled','Last Logon','PW Set','Description')
$asHdr   = New-HeaderRow @('Location','Name','Command')
$stHdr   = New-HeaderRow @('Name','State','Last Run','Next Run','Author')

# --- Escaped values for HTML ---
$escOS     = [System.Net.WebUtility]::HtmlEncode($SysInfo.OS)
$escUser   = [System.Net.WebUtility]::HtmlEncode($SysInfo.CurrentUser)
$escMfr    = [System.Net.WebUtility]::HtmlEncode($SysInfo.Manufacturer)
$escMdl    = [System.Net.WebUtility]::HtmlEncode($SysInfo.Model)
$escTZ     = [System.Net.WebUtility]::HtmlEncode($SysInfo.TimeZone)
$escCPU    = [System.Net.WebUtility]::HtmlEncode($HwMetrics.CPUName)
$escHost   = [System.Net.WebUtility]::HtmlEncode($SysInfo.Hostname)
$escDomain = [System.Net.WebUtility]::HtmlEncode($SysInfo.Domain)
$escSerial = [System.Net.WebUtility]::HtmlEncode($SysInfo.SerialNumber)

# =============================================
# ASSEMBLE HTML with StringBuilder
# =============================================
$sb = [System.Text.StringBuilder]::new(65536)

[void]$sb.AppendLine('<!DOCTYPE html>')
[void]$sb.AppendLine('<html lang="de"><head><meta charset="UTF-8">')
[void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1.0">')
[void]$sb.AppendLine('<title>Security Dashboard</title>')
[void]$sb.AppendLine('<style>')
[void]$sb.AppendLine(':root{--bg:#f5f5f7;--surface:#fff;--text:#1d1d1f;--text-sec:#6e6e73;--text-tert:#aeaeb2;--border:rgba(0,0,0,0.06);--accent:#0071e3;--green:#34c759;--red:#ff3b30;--yellow:#ff9500;--blue:#007aff;--radius:16px;--radius-sm:10px;--shadow:0 1px 3px rgba(0,0,0,0.04),0 4px 24px rgba(0,0,0,0.06);--shadow-lg:0 2px 8px rgba(0,0,0,0.04),0 12px 48px rgba(0,0,0,0.08);--font:-apple-system,BlinkMacSystemFont,"Helvetica Neue","Segoe UI",sans-serif}')
[void]$sb.AppendLine('*{margin:0;padding:0;box-sizing:border-box}')
[void]$sb.AppendLine('body{font-family:var(--font);background:var(--bg);color:var(--text);-webkit-font-smoothing:antialiased;line-height:1.5}')
[void]$sb.AppendLine('.container{max-width:1200px;margin:0 auto;padding:0 24px}')
[void]$sb.AppendLine('.hero{padding:72px 0 48px;text-align:center}')
[void]$sb.AppendLine('.hero-badge{display:inline-flex;align-items:center;gap:6px;background:var(--surface);border:1px solid var(--border);border-radius:100px;padding:6px 16px;font-size:12px;font-weight:500;color:var(--text-sec);letter-spacing:.5px;text-transform:uppercase;margin-bottom:20px;box-shadow:0 1px 2px rgba(0,0,0,0.04)}')
[void]$sb.AppendLine('.hero-badge .dot{width:6px;height:6px;border-radius:50%;background:var(--green);animation:pulse 2s ease infinite}')
[void]$sb.AppendLine('@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(.85)}}')
[void]$sb.AppendLine('.hero h1{font-size:52px;font-weight:700;letter-spacing:-0.03em;line-height:1.08;margin-bottom:12px;background:linear-gradient(135deg,var(--text) 0%,#48484a 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent}')
[void]$sb.AppendLine('.hero .subtitle{font-size:20px;font-weight:400;color:var(--text-sec)}')
[void]$sb.AppendLine('.hero-meta{display:flex;justify-content:center;gap:32px;margin-top:32px;font-size:13px;color:var(--text-tert)}')
[void]$sb.AppendLine('.hero-meta span{display:flex;align-items:center;gap:6px}')
[void]$sb.AppendLine('.stats-strip{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:48px}')
[void]$sb.AppendLine('.stat-card{background:var(--surface);border-radius:var(--radius);padding:24px;text-align:center;box-shadow:var(--shadow);border:1px solid var(--border);transition:transform .25s ease,box-shadow .25s ease}')
[void]$sb.AppendLine('.stat-card:hover{transform:translateY(-2px);box-shadow:var(--shadow-lg)}')
[void]$sb.AppendLine('.stat-value{font-size:40px;font-weight:700;letter-spacing:-0.02em;line-height:1;margin-bottom:4px}')
[void]$sb.AppendLine('.stat-label{font-size:13px;font-weight:500;color:var(--text-sec)}')
[void]$sb.AppendLine('.section{margin-bottom:48px}')
[void]$sb.AppendLine('.section-header{display:flex;align-items:baseline;gap:12px;margin-bottom:20px;padding-bottom:12px;border-bottom:1px solid var(--border)}')
[void]$sb.AppendLine('.section-header h2{font-size:26px;font-weight:600;letter-spacing:-0.02em}')
[void]$sb.AppendLine('.section-header .section-count{font-size:13px;font-weight:500;color:var(--text-tert);background:var(--bg);padding:2px 10px;border-radius:100px}')
[void]$sb.AppendLine('.card{background:var(--surface);border-radius:var(--radius);box-shadow:var(--shadow);border:1px solid var(--border);overflow:hidden}')
[void]$sb.AppendLine('.card-inner{padding:28px}')
[void]$sb.AppendLine('.card+.card{margin-top:16px}')
[void]$sb.AppendLine('.gauges-row{display:flex;gap:48px;justify-content:center;flex-wrap:wrap}')
[void]$sb.AppendLine('.gauge{display:flex;flex-direction:column;align-items:center;min-width:140px}')
[void]$sb.AppendLine('.gauge svg{width:120px;height:120px}')
[void]$sb.AppendLine('.gauge-ring{transition:stroke-dasharray 1.5s cubic-bezier(.4,0,.2,1)}')
[void]$sb.AppendLine('.gauge-text{margin-top:-82px;margin-bottom:42px;text-align:center}')
[void]$sb.AppendLine('.gauge-value{font-size:28px;font-weight:600;letter-spacing:-0.02em}')
[void]$sb.AppendLine('.gauge-value small{font-size:16px;font-weight:400;color:var(--text-sec)}')
[void]$sb.AppendLine('.gauge-label{font-size:15px;font-weight:600;margin-top:4px}')
[void]$sb.AppendLine('.gauge-sub{font-size:12px;color:var(--text-tert);margin-top:2px}')
[void]$sb.AppendLine('.disk-item{margin-bottom:14px}.disk-item:last-child{margin-bottom:0}')
[void]$sb.AppendLine('.disk-header{display:flex;justify-content:space-between;margin-bottom:6px}')
[void]$sb.AppendLine('.disk-name{font-size:14px;font-weight:500}.disk-stats{font-size:13px;color:var(--text-sec)}')
[void]$sb.AppendLine('.bar-track{height:6px;background:rgba(142,142,147,0.12);border-radius:3px;overflow:hidden}')
[void]$sb.AppendLine('.bar-fill{height:100%;border-radius:3px;transition:width 1.5s cubic-bezier(.4,0,.2,1)}')
[void]$sb.AppendLine('table{width:100%;border-collapse:collapse;font-size:13px}')
[void]$sb.AppendLine('th{text-align:left;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--text-tert);padding:10px 14px;border-bottom:1px solid var(--border);background:rgba(0,0,0,0.015);position:sticky;top:0}')
[void]$sb.AppendLine('td{padding:9px 14px;border-bottom:1px solid var(--border);color:var(--text);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-variant-numeric:tabular-nums}')
[void]$sb.AppendLine('td.message-cell{min-width:280px;max-width:none;white-space:normal;overflow:visible}td.message-cell summary{cursor:pointer;color:var(--accent)}.event-message{white-space:pre-wrap;overflow-wrap:anywhere;margin-top:10px;max-height:420px;overflow:auto} @media print{td.message-cell details>.event-message{display:block!important;max-height:none}}')
[void]$sb.AppendLine('tr:last-child td{border-bottom:none}tr:hover td{background:rgba(0,122,255,0.03)}')
[void]$sb.AppendLine('td.empty{text-align:center;color:var(--text-tert);padding:32px;font-style:italic}')
[void]$sb.AppendLine('.table-scroll{max-height:420px;overflow-y:auto}')
[void]$sb.AppendLine('.table-scroll::-webkit-scrollbar{width:6px}.table-scroll::-webkit-scrollbar-track{background:transparent}.table-scroll::-webkit-scrollbar-thumb{background:rgba(0,0,0,0.15);border-radius:3px}')
[void]$sb.AppendLine('.tag-red,.tag-green,.tag-yellow,.tag-blue{display:inline-block;padding:2px 10px;border-radius:6px;font-size:12px;font-weight:600}')
[void]$sb.AppendLine('.tag-red{background:rgba(255,59,48,0.1);color:var(--red)}.tag-green{background:rgba(52,199,89,0.1);color:var(--green)}.tag-yellow{background:rgba(255,149,0,0.1);color:var(--yellow)}.tag-blue{background:rgba(0,122,255,0.1);color:var(--blue)}')
[void]$sb.AppendLine('.checks-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}')
[void]$sb.AppendLine('.check-card{display:flex;align-items:flex-start;gap:14px;padding:18px;border-radius:var(--radius-sm);border:1px solid var(--border);background:var(--surface);transition:transform .2s ease}')
[void]$sb.AppendLine('.check-card:hover{transform:translateY(-1px)}')
[void]$sb.AppendLine('.check-icon{width:32px;height:32px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:15px;font-weight:700;flex-shrink:0}')
[void]$sb.AppendLine('.check-pass .check-icon{background:rgba(52,199,89,0.12);color:var(--green)}.check-fail .check-icon{background:rgba(255,59,48,0.12);color:var(--red)}.check-warn .check-icon{background:rgba(255,149,0,0.12);color:var(--yellow)}.check-info .check-icon{background:rgba(0,122,255,0.12);color:var(--blue)}')
[void]$sb.AppendLine('.check-title{font-size:14px;font-weight:600;margin-bottom:2px}.check-detail{font-size:12px;color:var(--text-sec)}')
[void]$sb.AppendLine('.admin-badge{display:inline-block;padding:6px 14px;background:rgba(0,0,0,0.04);border:1px solid var(--border);border-radius:8px;font-size:13px;font-weight:500;margin:4px}')
[void]$sb.AppendLine('.info-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:2px}')
[void]$sb.AppendLine('.info-item{padding:14px 18px;background:rgba(0,0,0,0.015);border-radius:8px;margin:2px}')
[void]$sb.AppendLine('.info-label{font-size:11px;font-weight:500;text-transform:uppercase;letter-spacing:.05em;color:var(--text-tert);margin-bottom:2px}.info-value{font-size:15px;font-weight:500}')
[void]$sb.AppendLine('.two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px}')
[void]$sb.AppendLine('.footer{text-align:center;padding:48px 0 40px;font-size:12px;color:var(--text-tert)}')
[void]$sb.AppendLine('@media(max-width:768px){.hero h1{font-size:34px}.stats-strip{grid-template-columns:repeat(2,1fr)}.two-col{grid-template-columns:1fr}.hero-meta{flex-direction:column;gap:8px}}')
[void]$sb.AppendLine('@media print{body{background:#fff}.card{box-shadow:none;border:1px solid #ddd}.stat-card:hover{transform:none}}')
[void]$sb.AppendLine('</style></head><body><div class="container">')

# HERO
[void]$sb.AppendLine('<div class="hero">')
[void]$sb.AppendLine('<div class="hero-badge"><span class="dot"></span> System Scan Complete</div>')
[void]$sb.Append('<h1>Security Dashboard</h1>')
[void]$sb.Append('<p class="subtitle">' + $escHost + ' &mdash; ' + $escOS + '</p>')
[void]$sb.Append('<div class="hero-meta">')
[void]$sb.Append('<span>Report: ' + $reportTime + '</span>')
[void]$sb.Append('<span>Uptime: ' + $SysInfo.Uptime + '</span>')
[void]$sb.Append('<span>User: ' + $escUser + '</span>')
[void]$sb.AppendLine('</div></div>')

# STATS
[void]$sb.AppendLine('<div class="stats-strip">')
[void]$sb.Append('<div class="stat-card"><div class="stat-value" style="color:var(--accent)">' + $nProcs + '</div><div class="stat-label">Processes</div></div>')
[void]$sb.Append('<div class="stat-card"><div class="stat-value" style="color:var(--green)">' + $nConns + '</div><div class="stat-label">Connections</div></div>')
[void]$sb.Append('<div class="stat-card"><div class="stat-value" style="color:var(--yellow)">' + $nEvents + '</div><div class="stat-label">Events (' + $EventHours + 'h)</div></div>')
[void]$sb.Append('<div class="stat-card"><div class="stat-value" style="color:' + $failColor + '">' + $nChecks + '</div><div class="stat-label">Failed Checks</div></div>')
[void]$sb.AppendLine('</div>')

# HARDWARE
[void]$sb.AppendLine('<div class="section"><div class="section-header"><h2>Hardware</h2><span class="section-count">' + $escCPU + '</span></div>')
[void]$sb.AppendLine('<div class="two-col">')
[void]$sb.Append('<div class="card"><div class="card-inner"><div class="gauges-row">' + $cpuGauge + $ramGauge + '</div></div></div>')
[void]$sb.Append('<div class="card"><div class="card-inner"><h3 style="font-size:15px;font-weight:600;margin-bottom:18px">Storage</h3>' + $diskBarsHtml + '</div></div>')
[void]$sb.AppendLine('</div></div>')

# SECURITY CHECKS
[void]$sb.AppendLine('<div class="section"><div class="section-header"><h2>Security Checks</h2><span class="section-count">' + $secCount + ' checks</span></div>')
[void]$sb.AppendLine('<p>Unavailable checks: ' + @($SecurityChecks | Where-Object Status -eq 'Unknown').Count + '</p>')
[void]$sb.AppendLine('<div class="checks-grid">' + $securityCardsHtml + '</div></div>')

# FIREWALL
[void]$sb.AppendLine('<div class="section"><div class="section-header"><h2>Firewall</h2></div>')
[void]$sb.AppendLine('<div class="card"><table>' + $fwHdr + $fwRows + '</table></div></div>')

# PROCESSES
[void]$sb.AppendLine('<div class="section"><div class="section-header"><h2>Top Processes</h2><span class="section-count">by CPU time</span></div>')
[void]$sb.AppendLine('<div class="card"><div class="table-scroll"><table>' + $procHdr + $procRows + '</table></div></div></div>')

# EVENTS
[void]$sb.AppendLine('<div class="section"><div class="section-header"><h2>Event Logs</h2><span class="section-count">Last ' + $EventHours + ' hours</span></div>')
[void]$sb.AppendLine('<div class="card" style="margin-bottom:16px"><div class="card-inner" style="padding-bottom:12px"><h3 style="font-size:15px;font-weight:600;margin-bottom:4px">Failed Logins</h3><p style="font-size:12px;color:var(--text-tert)">Event ID 4625</p></div>')
[void]$sb.AppendLine('<div class="table-scroll"><table>' + $flHdr + $failedLoginRows + '</table></div></div>')
[void]$sb.AppendLine('<div class="card" style="margin-bottom:16px"><div class="card-inner" style="padding-bottom:12px"><h3 style="font-size:15px;font-weight:600;margin-bottom:4px">New Service Installs</h3><p style="font-size:12px;color:var(--text-tert)">Event ID 7045</p></div>')
[void]$sb.AppendLine('<div class="table-scroll"><table>' + $siHdr + $serviceRows + '</table></div></div>')
[void]$sb.AppendLine('<div class="card"><div class="card-inner" style="padding-bottom:12px"><h3 style="font-size:15px;font-weight:600;margin-bottom:4px">Windows-Systemereignisse</h3><p style="font-size:12px;color:var(--text-sec)">Historische Eintraege aus dem Windows-Systemprotokoll (Critical, Error, Warning). Die Windows-Stufe allein nennt keine Ursache und belegt keinen Fehler des Dashboards. Meldung anklicken, um den vollstaendigen Text zu lesen. Fehler bei der Datenerfassung stehen separat unter Collection issues.</p></div>')
[void]$sb.AppendLine('<div class="table-scroll"><table>' + $weHdr + $warnErrorRows + '</table></div></div></div>')

# NETWORK
[void]$sb.AppendLine('<div class="section"><div class="section-header"><h2>Network Connections</h2><span class="section-count">' + $nConns + ' active</span></div>')
[void]$sb.AppendLine('<div class="card"><div class="table-scroll"><table>' + $netHdr + $netRows + '</table></div></div></div>')

# USERS
[void]$sb.AppendLine('<div class="section"><div class="section-header"><h2>Local Users &amp; Admins</h2></div><div class="two-col">')
[void]$sb.AppendLine('<div class="card"><div class="card-inner" style="padding-bottom:12px"><h3 style="font-size:15px;font-weight:600;margin-bottom:12px">User Accounts</h3></div>')
[void]$sb.AppendLine('<div class="table-scroll"><table>' + $uHdr + $userRows + '</table></div></div>')
[void]$sb.AppendLine('<div class="card"><div class="card-inner"><h3 style="font-size:15px;font-weight:600;margin-bottom:16px">Administrators</h3><div>' + $adminsHtml + '</div></div></div>')
[void]$sb.AppendLine('</div></div>')

# AUTOSTART
[void]$sb.AppendLine('<div class="section"><div class="section-header"><h2>Autostart Entries</h2></div>')
[void]$sb.AppendLine('<div class="card"><div class="table-scroll"><table>' + $asHdr + $autostartRows + '</table></div></div></div>')

# TASKS
[void]$sb.AppendLine('<div class="section"><div class="section-header"><h2>Scheduled Tasks</h2><span class="section-count">non-Microsoft, active</span></div>')
[void]$sb.AppendLine('<div class="card"><div class="table-scroll"><table>' + $stHdr + $taskRows + '</table></div></div></div>')

# SYSTEM INFO
[void]$sb.AppendLine('<div class="section"><div class="section-header"><h2>System Information</h2></div>')
[void]$sb.AppendLine('<div class="card"><div class="card-inner"><div class="info-grid">')
[void]$sb.Append('<div class="info-item"><div class="info-label">Hostname</div><div class="info-value">' + $escHost + '</div></div>')
[void]$sb.Append('<div class="info-item"><div class="info-label">Domain</div><div class="info-value">' + $escDomain + '</div></div>')
[void]$sb.Append('<div class="info-item"><div class="info-label">OS</div><div class="info-value">' + $escOS + '</div></div>')
[void]$sb.Append('<div class="info-item"><div class="info-label">Build</div><div class="info-value">' + $SysInfo.Build + '</div></div>')
[void]$sb.Append('<div class="info-item"><div class="info-label">Architecture</div><div class="info-value">' + $SysInfo.Architecture + '</div></div>')
[void]$sb.Append('<div class="info-item"><div class="info-label">Install Date</div><div class="info-value">' + $SysInfo.InstallDate + '</div></div>')
[void]$sb.Append('<div class="info-item"><div class="info-label">Last Boot</div><div class="info-value">' + $SysInfo.LastBoot + '</div></div>')
[void]$sb.Append('<div class="info-item"><div class="info-label">Uptime</div><div class="info-value">' + $SysInfo.Uptime + '</div></div>')
[void]$sb.Append('<div class="info-item"><div class="info-label">Manufacturer</div><div class="info-value">' + $escMfr + '</div></div>')
[void]$sb.Append('<div class="info-item"><div class="info-label">Model</div><div class="info-value">' + $escMdl + '</div></div>')
[void]$sb.Append('<div class="info-item"><div class="info-label">Serial</div><div class="info-value">' + $escSerial + '</div></div>')
[void]$sb.Append('<div class="info-item"><div class="info-label">User</div><div class="info-value">' + $escUser + '</div></div>')
[void]$sb.Append('<div class="info-item"><div class="info-label">Time Zone</div><div class="info-value">' + $escTZ + '</div></div>')
[void]$sb.AppendLine('</div></div></div></div>')

# FOOTER
$psVer = $PSVersionTable.PSVersion.ToString()
[void]$sb.Append('<div class="footer">Security Dashboard &mdash; Generated ' + $reportTime + '<br>')
[void]$sb.Append('PowerShell ' + $psVer + ' &middot; Windows Security Audit Tool</div>')
[void]$sb.AppendLine('</div></body></html>')

# Collection failures remain visible instead of appearing as successful empty scans.
$errorRows = ConvertTo-HtmlTableRows -Data $result.Errors -Properties @('Section','Error')
$errorSection = '<section class="container"><h2>Collection errors</h2><table>' + $errorRows + '</table></section>'
$result.Html = $sb.ToString().Replace('</body>', $errorSection + '</body>')
if ($OutputPath) {
    [IO.File]::WriteAllText($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath), $result.Html, [Text.UTF8Encoding]::new($false))
    if ($OpenReport) { Start-Process -FilePath $OutputPath }
}
return $result
