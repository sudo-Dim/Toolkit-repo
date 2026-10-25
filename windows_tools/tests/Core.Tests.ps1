$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$passed = 0
function Assert($Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:passed++
}
foreach ($file in Get-ChildItem $root -Recurse -Filter '*.ps1') {
    $tokens = $null; $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
    Assert (-not $errors) ("Syntax: " + $file.Name + ': ' + ($errors | Out-String))
}

. (Join-Path $root 'debloat/Debloat.Core.ps1')
$calls = @{ App=0; Provisioned=0; Registry=0; Remove=0; RemoveProvisioned=0 }
function Test-Path {
    param($LiteralPath,$Path,$ErrorAction)
    $value = if ($LiteralPath) { $LiteralPath } else { $Path }
    if ($value -like '*CurrentVersion\Uninstall') { return $true }
    Microsoft.PowerShell.Management\Test-Path -LiteralPath $value
}
function Get-AppxPackage {
    param([switch]$AllUsers, $ErrorAction)
    $script:calls.App++
    [pscustomobject]@{ Name='McAfeeWPS'; PackageFullName='McAfeeWPS_1.0_x64' }
    [pscustomobject]@{ Name='Microsoft.WindowsCalculator'; PackageFullName='Calculator_1.0_x64' }
}
function Get-AppxProvisionedPackage {
    param([switch]$Online, $ErrorAction)
    $script:calls.Provisioned++
    [pscustomobject]@{ DisplayName='McAfeeWPS'; PackageName='McAfeeWPS_provisioned' }
}
function Get-ItemProperty {
    param($Path,$LiteralPath,$ErrorAction)
    $script:calls.Registry++
    if ($Path -like '*Uninstall*') { [pscustomobject]@{ DisplayName='McAfee'; PSPath='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\McAfee' } }
    elseif ($LiteralPath -eq 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\McAfee') { $script:fixtureUninstall }
    else { throw 'Access denied' }
}
function Remove-AppxPackage {
    param($Package,[switch]$AllUsers,$ErrorAction)
    $script:calls.Remove++
    if ($Package -eq 'fail') { throw 'Simulated removal failure' }
}
function Remove-AppxProvisionedPackage {
    param($PackageName,[switch]$Online,$ErrorAction)
    $script:calls.RemoveProvisioned++
}
$inventory = @(Get-DebloatInventory -AllUsers)
Assert ($calls.App -eq 1 -and $calls.Provisioned -eq 1) 'Inventory must enumerate packages once'
Assert ($calls.Registry -eq 2) 'Each uninstall registry view must be read once'
Assert ($inventory.Count -eq 3) 'Overlapping patterns/registry entries must not duplicate candidates'
Assert (@($inventory | Where-Object Name -like '*Calculator*').Count -eq 0) 'Unrelated package must remain excluded'
$calls.Provisioned = 0
$userInventory = @(Get-DebloatInventory)
Assert ($calls.Provisioned -eq 0) 'Current-user scope must not enumerate provisioning'

$temp = Join-Path ([IO.Path]::GetTempPath()) ('ToolkitTests-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    if ($env:OS -eq 'Windows_NT') {
        $protected = Join-Path $temp 'protected'
        New-DebloatDirectory $protected
        $acl = Get-Acl -LiteralPath $protected
        Assert $acl.AreAccessRulesProtected 'Elevated working directories must not inherit user-write access'
        Assert ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-544') 'Elevated directory owner must be Administrators'
    }
    $selection = @(
        [pscustomobject]@{ Kind='App'; Name='Success'; Id='ok' },
        [pscustomobject]@{ Kind='App'; Name='Failure'; Id='fail' },
        [pscustomobject]@{ Kind='Provisioned'; Name='Template'; Id='template' }
    )
    $log = Join-Path $temp 'result.json'
    $result = @(Invoke-DebloatPlan -Selection $selection -AllUsers -NoRestorePoint -LogPath $log -Confirm:$false)
    Assert ($calls.Remove -eq 2 -and $calls.RemoveProvisioned -eq 1) 'Execute each exact selection once'
    Assert ($result[0].Status -eq 'Success' -and $result[1].Status -eq 'Error' -and $result[2].Status -eq 'Success') 'Failure must not report success or stop unrelated actions'
    $saved = Get-Content -LiteralPath $log -Raw | ConvertFrom-Json
    Assert ($saved.Results[1].Detail -eq 'Simulated removal failure') 'Run log must retain real error'
    $calls.Remove = 0
    $duplicate = @(Invoke-DebloatPlan -Selection @($selection[0],$selection[0]) -NoRestorePoint -LogPath $log -Confirm:$false)
    Assert ($calls.Remove -eq 1 -and $duplicate.Count -eq 1) 'Duplicate explicit selections must run once'
    $calls.Remove = 0
    $dryLog = Join-Path $temp 'dry.json'
    Invoke-DebloatPlan -Selection $selection -AllUsers -NoRestorePoint -LogPath $dryLog -WhatIf | Out-Null
    Assert ($calls.Remove -eq 0 -and -not (Test-Path -LiteralPath $dryLog)) 'WhatIf must not modify Windows or write logs'
    $calls.RemoveProvisioned = 0
    $result = @(Invoke-DebloatPlan -Selection @($selection[2]) -NoRestorePoint -LogPath $log -Confirm:$false)
    Assert ($result[0].Status -eq 'Error' -and $calls.RemoveProvisioned -eq 0) 'Provisioning must require all-user scope'
    # Real harmless child processes verify stream handling, exit codes and hidden
    # Windows startup. No installer is executed by these tests.
    $childHost = (Get-Process -Id $PID).Path
    function Invoke-FixtureProcess([string]$Code) {
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Code))
        Invoke-CheckedProcess $script:childHost ('-NoProfile -NonInteractive -EncodedCommand ' + $encoded)
    }
    $failure = ''
    try { Invoke-FixtureProcess "[Console]::Out.Write(('x' * 131072)); [Console]::Error.Write(('y' * 131072) + 'failure-detail'); exit 5" }
    catch { $failure = $_.Exception.Message }
    Assert ($failure -like '*Exit code 5:*' -and $failure -like '*failure-detail*' -and $failure.Length -lt 2500) 'Verbose failures must not deadlock; retain exit code and bounded diagnostics'
    Invoke-FixtureProcess 'if ([Console]::In.ReadToEnd().Trim().Length) { throw "Unexpected keyboard input" }; exit 0'
    Assert $true 'Background processes must finish without keyboard input'
    if ($env:OS -eq 'Windows_NT') {
        $script:RestartNeeded = $false
        Invoke-FixtureProcess 'exit 3010'
        Assert $script:RestartNeeded 'Installer reboot result must be retained'
        Invoke-FixtureProcess @'
Add-Type 'using System; using System.Runtime.InteropServices; public static class ConsoleProbe { [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow(); [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr window); }'
if ([ConsoleProbe]::IsWindowVisible([ConsoleProbe]::GetConsoleWindow())) { throw 'Visible helper console' }
'@
        Assert $true 'Windows helper console must not be visible'
        $childScript = Join-Path $temp 'child.ps1'
        $marker = Join-Path $temp 'child-finished'
        [IO.File]::WriteAllText($childScript, ('Start-Sleep -Milliseconds 800; [IO.File]::WriteAllText("' + $marker + '","done")'))
        Invoke-FixtureProcess ('Start-Process -FilePath "' + $childHost + '" -ArgumentList ''-NoProfile -NonInteractive -File "' + $childScript + '"'' -WindowStyle Hidden')
        Assert ([IO.File]::Exists($marker)) 'Installer descendants must finish before reporting completion'
    }
    function Invoke-CheckedProcess {
        param($FilePath,$Arguments)
        $script:executed = @($FilePath,$Arguments)
        $script:calls.Exec++
    }
    function Start-Process { throw 'Unexpected external UI launch' }
    $fixtureExe = if ($env:OS -eq 'Windows_NT') { 'C:\Program Files\Vendor\uninstall.exe' } else { '/trusted/uninstall.exe' }
    $fixtureUninstall = [pscustomobject]@{ UninstallString=('"' + $fixtureExe + '" /remove'); QuietUninstallString=('"' + $fixtureExe + '" /remove /quiet') }
    $fixtureSignature = 'Valid'
    function Get-AuthenticodeSignature { param($LiteralPath) [pscustomobject]@{Status=$script:fixtureSignature} }
    Invoke-ClassicUninstall 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\McAfee'
    Assert ($executed[0] -eq $fixtureExe -and $executed[1] -eq '/remove /quiet') 'Registered quiet command must retain exact path and arguments'

    $classic = [pscustomobject]@{Kind='Classic';Name='Interactive vendor';Id='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\McAfee'}
    $fixtureUninstall.QuietUninstallString = ' '; $calls.Exec = 0; $calls.Remove = 0
    $result = @(Invoke-DebloatPlan -Selection @($classic,$selection[0]) -NoRestorePoint -LogPath $log -Confirm:$false)
    Assert ($calls.Exec -eq 0 -and $result[0].Status -eq 'Skipped' -and $result[0].Detail -like '*Deinstallationsmodus*') 'Interactive-only uninstallers must be skipped with an explanation'
    Assert ($calls.Remove -eq 1 -and $result[1].Status -eq 'Success') 'Skipped interactive actions must not block unrelated selected actions'
    $saved = Get-Content -LiteralPath $log -Raw | ConvertFrom-Json
    Assert ($saved.Results[0].Status -eq 'Skipped') 'Skipped actions must remain visible in the run log'
    $result = @(Invoke-DebloatPlan -Options @('DefaultBrowser') -NoRestorePoint -LogPath $log -Confirm:$false)
    Assert ($result[0].Status -eq 'Skipped' -and $result[0].Detail -like '*Standardbrowser*') 'Legacy browser options must not open Settings'
    $fixtureUninstall.UninstallString = 'MsiExec.exe /I{12345678-1234-1234-1234-123456789ABC}'
    $previousRoot = $env:SystemRoot
    try {
        if (-not $env:SystemRoot) { $env:SystemRoot = $temp }
        Invoke-ClassicUninstall $classic.Id
        Assert ($executed[0] -eq (Join-Path $env:SystemRoot 'System32\msiexec.exe') -and $executed[1] -eq '/x {12345678-1234-1234-1234-123456789ABC} /qn /norestart') 'MSI fallback must use the system installer without UI or restart'
        $fixtureUninstall.UninstallString = 'MsiExec.exe /I{------------------------------------}'; $calls.Exec = 0; $caught = $false
        try { Invoke-ClassicUninstall $classic.Id } catch { $caught = $true }
        Assert ($caught -and $calls.Exec -eq 0) 'Invalid MSI product codes must never execute'
    } finally { $env:SystemRoot = $previousRoot }
    foreach ($launcher in @('explorer.exe','control.exe','SystemSettings.exe')) {
        $fixtureUninstall.QuietUninstallString = '"' + (Join-Path $temp $launcher) + '"'
        $caught = $false; $calls.Exec = 0
        try { Invoke-ClassicUninstall $classic.Id } catch { $caught = $true }
        Assert ($caught -and $calls.Exec -eq 0) 'Shell and Settings launchers must never be used as uninstallers'
    }
    $fixtureUninstall.QuietUninstallString = '"' + $fixtureExe + '" /remove /quiet'

    $caught = $false
    try { Invoke-ClassicUninstall 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\McAfee' } catch { $caught = $true }
    Assert $caught 'User-writable uninstall entries must never execute elevated'
    $fixtureSignature = 'NotSigned'; $caught = $false; $calls.Exec = 0
    try { Invoke-ClassicUninstall 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\McAfee' } catch { $caught = $true }
    Assert ($caught -and $calls.Exec -eq 0) 'Unsigned uninstallers must not execute'

    # Synthetic Windows providers: no host diagnosis or system changes in this suite.
    $global:ToolkitDiagnosticTestState = @{ Cim=@{}; Processes=0; NoEvents=$false; SystemEvents=@() }
    function Get-CimInstance {
        param($ClassName,$Filter)
        $global:ToolkitDiagnosticTestState.Cim[$ClassName]++
        switch ($ClassName) {
            Win32_OperatingSystem { [pscustomobject]@{ LastBootUpTime=(Get-Date).AddHours(-3); InstallDate=(Get-Date).AddDays(-30); Caption='Test OS'; BuildNumber='1'; OSArchitecture='x64'; TotalVisibleMemorySize=16777216; FreePhysicalMemory=8388608 } }
            Win32_ComputerSystem { [pscustomobject]@{ Domain='Test'; Manufacturer='Vendor'; Model='Model' } }
            Win32_BIOS { [pscustomobject]@{ SerialNumber='123' } }
            Win32_Processor { [pscustomobject]@{ Name='Test CPU'; NumberOfCores=4; NumberOfLogicalProcessors=8; LoadPercentage=25 } }
            Win32_LogicalDisk { [pscustomobject]@{ DeviceID='C:'; VolumeName='<script>alert(1)</script>'; Size=100GB; FreeSpace=50GB } }
        }
    }
    function Get-Process {
        param($Id,$ErrorAction)
        $global:ToolkitDiagnosticTestState.Processes++
        [pscustomobject]@{ Id=12; ProcessName='Sample'; WorkingSet64=10MB; CPU=1; Path='sample.exe'; Threads=@(1); HandleCount=2 }
    }
    function Get-WinEvent {
        param($FilterHashtable,$MaxEvents,$ErrorAction)
        if ($global:ToolkitDiagnosticTestState.NoEvents) {
            Write-Error 'No matching events' -ErrorId 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand' -ErrorAction Stop
        }
        if ($FilterHashtable.LogName -eq 'Security') { throw 'Security log access denied' }
        if ($FilterHashtable.Level) { $global:ToolkitDiagnosticTestState.SystemEvents }
    }
    function Get-NetTCPConnection {
        param($State,$ErrorAction)
        1..20 | ForEach-Object { [pscustomobject]@{ OwningProcess=12; LocalAddress='::1'; LocalPort=$_; RemoteAddress='127.0.0.1'; RemotePort=443; State='Established' } }
    }
    function Get-LocalUser { }
    function Get-LocalGroupMember { param($SID,$ErrorAction) [pscustomobject]@{ Name='LocalAdmin' } }
    function Get-NetFirewallProfile { }
    function Get-ScheduledTask { }
    function Get-SmbServerConfiguration { param($ErrorAction) throw 'Access denied' }
    function Get-MpComputerStatus { param($ErrorAction) throw 'Unavailable' }
    $culture = [Threading.Thread]::CurrentThread.CurrentCulture
    try {
        [Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo('de-AT')
        $data = & (Join-Path $root 'diagnostic/Collect-Diagnostics.ps1')
    } finally { [Threading.Thread]::CurrentThread.CurrentCulture = $culture }
    Assert ($global:ToolkitDiagnosticTestState.Cim.Win32_OperatingSystem -eq 1 -and $global:ToolkitDiagnosticTestState.Cim.Win32_Processor -eq 1) 'Reuse CIM snapshots'
    Assert ($global:ToolkitDiagnosticTestState.Processes -eq 1) 'Reuse process snapshot across all network connections'
    Assert ($data.Network.Count -eq 20 -and $data.Network[0].Process -eq 'Sample') 'Cached process names must retain every connection'
    Assert (@($data.Network.LocalAddr | Where-Object { $_ -eq '[::1]:1' }).Count -eq 1) 'IPv6 address and port must remain unambiguous'
    Assert (@($data.Errors | Where-Object Error -like '*Security log access denied*').Count -eq 1) 'Access denied must appear as a collection error'
    Assert (@($data.Security | Where-Object Status -eq 'Fail').Count -eq 0) 'Unknown readings must not become failed security checks'
    Assert (@($data.Security | Where-Object Status -eq 'Unknown').Count -ge 4) 'Unreadable security checks must be marked unknown'
    Assert ($data.Html.Contains('&lt;script&gt;alert(1)&lt;/script&gt;') -and -not $data.Html.Contains('<script>alert(1)</script>')) 'Disk labels must be HTML escaped'
    Assert ($data.Html.Contains('stroke-dasharray="62.8 251.2"')) 'SVG numbers must use invariant culture'
    Assert ($data.Html.Contains('Security log access denied')) 'HTML report must include collection failures'
    Assert ($data.SystemEvents.Count -eq 0 -and $data.FailedLogins.Count -eq 0) 'Empty event results must not count a null record'
    $message = ('Windows event detail ' * 20) + "`r`n<script>untrusted</script> END-OF-EVENT"
    $global:ToolkitDiagnosticTestState.SystemEvents = @([pscustomobject]@{
        TimeCreated=[datetime]'2026-10-25T11:07:50'; Level=2; ProviderName='Microsoft-Windows-DNS-Client'; Id=1012; RecordId=987; Message=$message
    })
    $withEvents = & (Join-Path $root 'diagnostic/Collect-Diagnostics.ps1')
    Assert ($withEvents.SystemEvents[0].Message -eq $message) 'Event collection must retain complete multiline messages'
    Assert ($withEvents.SystemEvents[0].RecordID -eq 987 -and $withEvents.SystemEvents[0].Time -eq '25.10.2026 11:07:50') 'Event records must preserve year and record identity'
    Assert ($withEvents.Html.Contains('<details><summary>') -and $withEvents.Html.Contains('END-OF-EVENT')) 'HTML event text must be expandable without truncation'
    Assert ($withEvents.Html.Contains('&lt;script&gt;untrusted&lt;/script&gt;') -and -not $withEvents.Html.Contains('<script>untrusted</script>')) 'Event messages must remain escaped in expandable details'
    Assert ($withEvents.Html.Contains('Windows-Systemereignisse') -and $withEvents.Errors.Count -eq 1) 'Windows events must remain separate from collection failures'
    $global:ToolkitDiagnosticTestState.NoEvents = $true
    $empty = & (Join-Path $root 'diagnostic/Collect-Diagnostics.ps1') -NoReport
    Assert (@($empty.Errors | Where-Object Section -like '*Logins*').Count -eq 0) 'NoMatchingEventsFound is an empty result, not an access failure'
    Assert ($null -eq $empty.Html) 'NoReport must skip HTML rendering'
} finally { Remove-Item -LiteralPath $temp -Recurse -Force; Remove-Variable ToolkitDiagnosticTestState -Scope Global -ErrorAction SilentlyContinue }
Write-Output "$passed checks passed. Windows providers were mocked; no system changes were made."
