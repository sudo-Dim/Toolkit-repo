# Windows PowerShell 5.1; dot-sourcing only defines functions, never changes Windows.
function New-DebloatDirectory {
    param([Parameter(Mandatory)][string]$Path)
    if (Test-Path -LiteralPath $Path) { throw 'Private directory already exists' }
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    $admin = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $acl.SetOwner($admin)
    foreach ($sid in @($admin,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.WindowsIdentity]::GetCurrent().User,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
    [void][IO.Directory]::CreateDirectory($Path,$acl)
}

function Get-DebloatInventory {
    param([switch]$AllUsers)
    $catalog = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'catalog.json') -Raw | ConvertFrom-Json
    $regexOptions = [Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [Text.RegularExpressions.RegexOptions]::CultureInvariant
    $appMatch = [regex]::new((@($catalog.apps | ForEach-Object { [regex]::Escape($_) }) -join '|'), $regexOptions)
    $classicMatch = [regex]::new((@($catalog.classic | ForEach-Object { [regex]::Escape($_) }) -join '|'), $regexOptions)
    $installed = @(Get-AppxPackage -AllUsers:$AllUsers -ErrorAction Stop)
    $provisioned = if ($AllUsers) { @(Get-AppxProvisionedPackage -Online -ErrorAction Stop) } else { @() }
    $registryPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $classic = @(foreach ($path in $registryPaths) {
        if (Test-Path -LiteralPath $path.Substring(0,$path.Length - 2) -ErrorAction Stop) {
            Get-ItemProperty -Path $path -ErrorAction Stop | Where-Object DisplayName
        }
    })
    $candidates = [Collections.Generic.List[object]]::new()
    foreach ($package in $installed) {
        if ($appMatch.IsMatch($package.Name)) {
            $candidates.Add([pscustomobject]@{ Kind='App'; Name=$package.Name; Id=$package.PackageFullName })
        }
    }
    foreach ($package in $provisioned) {
        if ($appMatch.IsMatch($package.DisplayName)) {
            $candidates.Add([pscustomobject]@{ Kind='Provisioned'; Name=$package.DisplayName; Id=$package.PackageName })
        }
    }
    foreach ($entry in $classic) {
        if ($classicMatch.IsMatch($entry.DisplayName)) {
            $candidates.Add([pscustomobject]@{
                Kind='Classic'; Name=$entry.DisplayName; Id=$entry.PSPath
            })
        }
    }
    # Deduplicate overlapping patterns (e.g. McAfee and McAfeeWPS).
    @($candidates | Sort-Object Kind,Id -Unique)
}

function Invoke-CheckedProcess {
    param([string]$FilePath, [string]$Arguments)
    $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -Wait -PassThru -ErrorAction Stop
    if ($process.ExitCode -notin @(0,1641,3010)) { throw "Exit code $($process.ExitCode): $FilePath" }
    if ($process.ExitCode -in @(1641,3010)) { $script:RestartNeeded = $true }
}

function Invoke-ClassicUninstall {
    param([string]$RegistryPath)
    if ($RegistryPath -notmatch '^(?:Microsoft\.PowerShell\.Core\\Registry::HKEY_LOCAL_MACHINE\\|HKLM:\\)SOFTWARE\\(?:WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Uninstall\\[^\\]+$') {
        throw 'Only machine-wide uninstall entries are allowed'
    }
    # Re-read the exact selected entry. Never execute a command through cmd /c.
    $entry = Get-ItemProperty -LiteralPath $RegistryPath -ErrorAction Stop
    $command = if ($entry.QuietUninstallString) { $entry.QuietUninstallString } else { $entry.UninstallString }
    if (-not $command) { throw 'No uninstall command registered' }
    if ($command -match '^\s*"([^"]+)"\s*(.*)$') {
        $exe = $Matches[1]; $arguments = $Matches[2]
    } elseif ($command -match '^\s*(.+?\.exe)\s*(.*)$') {
        $exe = $Matches[1]; $arguments = $Matches[2]
    } else { throw 'Uninstall command could not be parsed' }
    $exe = [Environment]::ExpandEnvironmentVariables($exe)
    if ([IO.Path]::GetFileName($exe) -in @('cmd.exe','powershell.exe','pwsh.exe','wscript.exe','cscript.exe','mshta.exe','rundll32.exe','regsvr32.exe')) {
        throw 'Script interpreters are not allowed as elevated uninstallers'
    }
    if ([IO.Path]::GetFileName($exe) -ieq 'msiexec.exe') {
        $guid = [regex]::Match($arguments, '\{[0-9a-fA-F-]{36}\}').Value
        if (-not $guid) { throw 'MSI product code missing' }
        $exe = Join-Path $env:SystemRoot 'System32\msiexec.exe'
        $arguments = "/x $guid /qn /norestart"
    }
    if (-not [IO.Path]::IsPathRooted($exe) -or $exe.StartsWith('\\')) { throw 'Uninstaller needs an absolute local path' }
    $signature = Get-AuthenticodeSignature -LiteralPath $exe
    if ($signature.Status -ne 'Valid') { throw 'Uninstaller is not validly signed; use Windows Installed Apps instead' }
    Invoke-CheckedProcess $exe $arguments
}

function Set-DebloatRegistry {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord')
    $exists = Test-Path -LiteralPath $Path
    $old = if ($exists) { Get-Item -LiteralPath $Path -ErrorAction Stop } else { $null }
    $hadValue = $old -and $old.GetValueNames() -contains $Name
    $script:Backups.Add([pscustomobject]@{
        Path=$Path; Name=$Name; Exists=[bool]$hadValue
        Value=$(if ($hadValue) { $old.GetValue($Name, $null, 'DoNotExpandEnvironmentNames') })
        Type=$(if ($hadValue) { $old.GetValueKind($Name).ToString() })
    })
    if ($old) { $old.Close() }
    # Save before mutation, so a failed action still has its previous value recorded.
    Save-DebloatLog
    if (-not $exists) { New-Item -Path $Path -Force -ErrorAction Stop | Out-Null }
    $propertyName = if ($Name -eq '') { '(default)' } else { $Name }
    New-ItemProperty -LiteralPath $Path -Name $propertyName -Value $Value -PropertyType $Type -Force -ErrorAction Stop | Out-Null
}

function Save-DebloatLog {
    $report = [pscustomobject]@{
        StartedAt=$script:StartedAt; Results=$script:Results.ToArray()
        RegistryBackup=$script:Backups.ToArray(); RestartNeeded=$script:RestartNeeded
    }
    $json = $report | ConvertTo-Json -Depth 12
    [IO.File]::WriteAllText($script:LogPath, $json, [Text.UTF8Encoding]::new($false))
}

function Install-DebloatBrave {
    $paths = @(
        "$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe",
        "${env:ProgramFiles(x86)}\BraveSoftware\Brave-Browser\Application\brave.exe",
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\Application\brave.exe"
    )
    if (@($paths | Where-Object { Test-Path -LiteralPath $_ }).Count) { return }
    $folder = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('BraveInstall-' + [guid]::NewGuid().ToString('N'))
    New-DebloatDirectory $folder
    $installer = Join-Path $folder 'BraveSetup.exe'
    try {
        Invoke-WebRequest -Uri 'https://laptop-updates.brave.com/latest/winx64' -OutFile $installer -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
        $signature = Get-AuthenticodeSignature -LiteralPath $installer
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '(?:^|,\s*)O=(?:"Brave Software,? Inc\.?"|Brave Software,? Inc\.?)(?:,|$)') {
            throw 'Brave installer signature or publisher is invalid'
        }
        Invoke-CheckedProcess $installer '--install --silent --system-level'
        if (-not @($paths | Where-Object { Test-Path -LiteralPath $_ }).Count) { throw 'Brave executable not found after installation' }
    } finally { Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction SilentlyContinue }
}

function Invoke-DebloatOption {
    param([string]$Id)
    switch ($Id) {
        'Brave' { Install-DebloatBrave }
        'DefaultBrowser' { Start-Process 'ms-settings:defaultapps' -ErrorAction Stop }
        'Telemetry' {
            foreach ($path in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection')) {
                Set-DebloatRegistry $path 'AllowTelemetry' 0
            }
            foreach ($name in @('SilentInstalledAppsEnabled','SystemPaneSuggestionsEnabled','SoftLandingEnabled','SubscribedContent-338388Enabled','SubscribedContent-310093Enabled')) {
                Set-DebloatRegistry 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' $name 0
            }
        }
        { $_ -in @('DiagTrack','dmwappushservice','SysMain','WSearch') } {
            Stop-Service -Name $Id -Force -ErrorAction Stop
            Set-Service -Name $Id -StartupType Disabled -ErrorAction Stop
        }
        { $_ -in @('Internet-Explorer-Optional-amd64','WindowsMediaPlayer') } {
            $state = Get-WindowsOptionalFeature -Online -FeatureName $Id -ErrorAction Stop
            if ($state.State -ne 'Disabled') {
                $change = Disable-WindowsOptionalFeature -Online -FeatureName $Id -NoRestart -ErrorAction Stop
                if ($change.RestartNeeded) { $script:RestartNeeded = $true }
            }
        }
        'OneDrive' {
            $setups = @("$env:SystemRoot\System32\OneDriveSetup.exe", "$env:SystemRoot\SysWOW64\OneDriveSetup.exe")
            $setup = $setups | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
            if (-not $setup) { throw 'OneDrive uninstaller not found; nothing changed' }
            Invoke-CheckedProcess $setup '/uninstall'
            Set-DebloatRegistry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' 'DisableFileSyncNGSC' 1
            foreach ($path in @('HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}','HKCU:\Software\Classes\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}')) {
                Set-DebloatRegistry $path 'System.IsPinnedToNameSpaceTree' 0
            }
            Get-ScheduledTask -ErrorAction Stop | Where-Object TaskName -like '*OneDrive*' | ForEach-Object {
                Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -Confirm:$false -ErrorAction Stop
            }
            # Keep user data and program folders; let the official uninstaller handle files.
        }
        'McAfeeRemnants' {
            Get-Service -ErrorAction Stop | Where-Object { $_.Name -like '*McAfee*' -or $_.DisplayName -like '*McAfee*' } | ForEach-Object {
                Stop-Service -Name $_.Name -Force -ErrorAction Stop
                Set-Service -Name $_.Name -StartupType Disabled -ErrorAction Stop
            }
            Get-ScheduledTask -ErrorAction Stop | Where-Object TaskName -like '*McAfee*' | ForEach-Object {
                Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -Confirm:$false -ErrorAction Stop
            }
        }
        'GameBar' {
            foreach ($protocol in @('ms-gamebar','ms-gamebarservices','ms-gamingoverlay')) {
                $base = "HKCU:\Software\Classes\$protocol"
                Set-DebloatRegistry $base '' "URL:$protocol" 'String'
                Set-DebloatRegistry $base 'URL Protocol' '' 'String'
                Set-DebloatRegistry "$base\shell\open\command" '' "`"$env:SystemRoot\System32\systray.exe`"" 'String'
            }
            Set-DebloatRegistry 'HKCU:\System\GameConfigStore' 'GameDVR_Enabled' 0
            Set-DebloatRegistry 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR' 'AppCaptureEnabled' 0
            Set-DebloatRegistry 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR' 'AllowGameDVR' 0
        }
        'Taskbar' {
            foreach ($name in @('ShowTaskViewButton','TaskbarMn','TaskbarDa')) {
                Set-DebloatRegistry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' $name 0
            }
            Set-DebloatRegistry 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search' 'SearchboxTaskbarMode' 0
            $script:RestartNeeded = $true
        }
        'TaskbarPins' {
            $folder = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
            if (-not (Test-Path -LiteralPath $folder)) { return }
            $shell = New-Object -ComObject WScript.Shell
            try {
                foreach ($link in Get-ChildItem -LiteralPath $folder -Filter '*.lnk') {
                    $shortcut = $shell.CreateShortcut($link.FullName)
                    if ([IO.Path]::GetFileName($shortcut.TargetPath) -ine 'explorer.exe') {
                        # Keep a copy next to the run log before removing a pin.
                        $backup = Join-Path ([IO.Path]::GetDirectoryName($script:LogPath)) 'TaskbarPins'
                        New-Item -ItemType Directory -Path $backup -Force -ErrorAction Stop | Out-Null
                        Copy-Item -LiteralPath $link.FullName -Destination $backup -ErrorAction Stop
                        Remove-Item -LiteralPath $link.FullName -Force -ErrorAction Stop
                    }
                }
            } finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell) }
            $script:RestartNeeded = $true
        }
        default { throw "Unknown option: $Id" }
    }
}

function Invoke-DebloatPlan {
    [CmdletBinding(SupportsShouldProcess)]
    param([object[]]$Selection, [string[]]$Options = @(), [switch]$AllUsers,
          [switch]$NoRestorePoint, [Parameter(Mandatory)][string]$LogPath)
    $script:LogPath = $LogPath
    $script:StartedAt = (Get-Date).ToString('o')
    $script:Results = [Collections.Generic.List[object]]::new()
    $script:Backups = [Collections.Generic.List[object]]::new()
    $script:RestartNeeded = $false
    $actions = [Collections.Generic.List[object]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $Selection) {
        if ($seen.Add($item.Kind + ':' + $item.Id)) { $actions.Add($item) }
    }
    foreach ($id in $Options | Select-Object -Unique) { $actions.Add([pscustomobject]@{ Kind='Option'; Name=$id; Id=$id }) }
    if (-not $actions.Count) { return @() }
    if (-not $WhatIfPreference) {
        $folder = Split-Path -Parent $LogPath
        if ($folder) { New-Item -ItemType Directory -Path $folder -Force -ErrorAction Stop | Out-Null }
        Save-DebloatLog
        if (-not $NoRestorePoint) {
            try {
                Checkpoint-Computer -Description 'Before Windows Debloat' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
                $script:Results.Add([pscustomobject]@{ Name='Restore point'; Status='Success'; Detail='' })
            } catch {
                $script:Results.Add([pscustomobject]@{ Name='Restore point'; Status='Warning'; Detail=$_.Exception.Message })
            }
            Save-DebloatLog
        }
    }
    foreach ($item in $actions) {
        if (-not $PSCmdlet.ShouldProcess($item.Name, $item.Kind)) { continue }
        $status = 'Success'; $detail = ''
        try {
            switch ($item.Kind) {
                'App' { Remove-AppxPackage -Package $item.Id -AllUsers:$AllUsers -ErrorAction Stop }
                'Provisioned' {
                    if (-not $AllUsers) { throw 'Provisioned packages require AllUsers' }
                    Remove-AppxProvisionedPackage -Online -PackageName $item.Id -ErrorAction Stop | Out-Null
                }
                'Classic' { Invoke-ClassicUninstall $item.Id }
                'Option' { Invoke-DebloatOption $item.Id }
                default { throw "Unknown action kind: $($item.Kind)" }
            }
        } catch { $status = 'Error'; $detail = $_.Exception.Message }
        $entry = [pscustomobject]@{ Name=$item.Name; Status=$status; Detail=$detail }
        $script:Results.Add($entry)
        Save-DebloatLog
    }
    $script:Results.ToArray()
}
