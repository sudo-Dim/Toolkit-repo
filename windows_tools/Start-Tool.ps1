[CmdletBinding()]
param([ValidateSet('Diagnostic','Debloat')][string]$Tool = 'Diagnostic', [switch]$SmokeTest)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
$root = $PSScriptRoot
$state = @{ Worker=$null; Pending=$null; Stop=$null; CloseAfterStop=$false; Mode=''; Data=$null; SmokeDone=$false }

function New-Button([string]$Text) {
    $button = [Windows.Forms.Button]::new()
    $button.Text = $Text; $button.AutoSize = $true; $button.Height = 32
    $button.Margin = [Windows.Forms.Padding]::new(4)
    return $button
}
function New-Grid {
    $grid = [Windows.Forms.DataGridView]::new()
    $grid.Dock = 'Fill'; $grid.ReadOnly = $true
    $grid.AllowUserToAddRows = $false; $grid.AllowUserToDeleteRows = $false
    $grid.AutoSizeColumnsMode = 'DisplayedCells'; $grid.RowHeadersVisible = $false
    $grid.BackgroundColor = [Drawing.Color]::White; $grid.SelectionMode = 'FullRowSelect'
    return ,$grid
}
function Set-Grid($Grid, $Rows) {
    $table = [Data.DataTable]::new()
    $items = @($Rows | Where-Object { $null -ne $_ })
    if ($items.Count) {
        $properties = @($items[0].PSObject.Properties.Name)
        foreach ($property in $properties) { [void]$table.Columns.Add($property) }
        foreach ($item in $items) {
            $row = $table.NewRow()
            foreach ($property in $properties) { $row[$property] = [string]$item.$property }
            $table.Rows.Add($row)
        }
    }
    $Grid.DataSource = $table
}
function Confirm-Selection([string[]]$Lines) {
    $review = [Windows.Forms.Form]::new()
    $review.Text = 'Auswahl pruefen'; $review.StartPosition = 'CenterParent'
    $review.ClientSize = [Drawing.Size]::new(760,520); $review.MinimumSize = [Drawing.Size]::new(600,400)
    $review.Font = $form.Font
    $text = [Windows.Forms.TextBox]::new(); $text.Multiline = $true; $text.ReadOnly = $true
    $text.Dock = 'Fill'; $text.ScrollBars = 'Both'; $text.WordWrap = $false
    $text.Text = ($Lines -join "`r`n") + "`r`n`r`nEin Wiederherstellungspunkt wird versucht.`r`nDeinstallationen koennen App-Daten entfernen."
    $buttons = [Windows.Forms.FlowLayoutPanel]::new(); $buttons.Dock = 'Bottom'; $buttons.AutoSize = $true
    $no = New-Button 'Abbrechen'; $no.DialogResult = 'Cancel'
    $yes = New-Button 'Diese Auswahl anwenden'; $yes.DialogResult = 'OK'
    $buttons.Controls.Add($no); $buttons.Controls.Add($yes)
    $review.Controls.Add($text); $review.Controls.Add($buttons)
    $review.CancelButton = $no; $review.AcceptButton = $no
    try { return $review.ShowDialog($form) -eq 'OK' }
    finally { $review.Dispose() }
}
function Start-Worker([string]$Mode, [string]$Code, [object[]]$Arguments) {
    if ($state.Worker) { return }
    $state.Mode = $Mode
    $worker = [PowerShell]::Create()
    $runspace = [RunspaceFactory]::CreateRunspace()
    $runspace.ApartmentState = 'STA'; $runspace.ThreadOptions = 'ReuseThread'; $runspace.Open()
    $worker.Runspace = $runspace
    $runspace.SessionStateProxy.SetVariable('ErrorActionPreference','Stop')
    [void]$worker.AddScript($Code)
    foreach ($argument in $Arguments) { [void]$worker.AddArgument($argument) }
    try {
        $state.Pending = $worker.BeginInvoke(); $state.Worker = $worker
    } catch { $worker.Dispose(); $runspace.Dispose(); throw }
    $scan.Enabled = $false; $apply.Enabled = $false; $export.Enabled = $false
    $cancel.Enabled = $Mode -ne 'Apply'
    $status.Text = if ($Mode -eq 'Apply') { 'Auswahl wird angewendet ...' } else { 'Daten werden erfasst ...' }
    $progress.Visible = $true
}
function Show-Diagnostic($Data) {
    $tabs.TabPages.Clear()
    $sections = [ordered]@{
        'System'=@($Data.System.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Name=$_.Name; Wert=$_.Value } })
        'Hardware'=@($Data.Hardware.PSObject.Properties | Where-Object Name -ne 'Disks' | ForEach-Object { [pscustomobject]@{ Name=$_.Name; Wert=$_.Value } })
        'Laufwerke'=$Data.Hardware.Disks; 'Sicherheit'=$Data.Security; 'Firewall'=$Data.Firewall
        'Prozesse'=$Data.Processes; 'Netzwerk'=$Data.Network; 'Anmeldefehler'=$Data.FailedLogins
        'Neue Dienste'=$Data.ServiceInstalls; 'Systemereignisse'=$Data.SystemEvents
        'Benutzer'=$Data.Users; 'Administratoren'=@($Data.Administrators | ForEach-Object { [pscustomobject]@{ Name=$_ } })
        'Autostart'=$Data.Autostart; 'Aufgaben'=$Data.Tasks; 'Erfassungsfehler'=$Data.Errors
    }
    foreach ($name in $sections.Keys) {
        $page = [Windows.Forms.TabPage]::new($name)
        $grid = New-Grid; Set-Grid $grid $sections[$name]; $page.Controls.Add($grid)
        $tabs.TabPages.Add($page)
    }
    $status.Text = 'Erfasst: ' + $Data.ProcessCount + ' Prozesse; ' + @($Data.Errors).Count + ' Erfassungsfehler. Nicht lesbare Werte sind unbekannt.'
}

$form = [Windows.Forms.Form]::new()
$form.Text = if ($Tool -eq 'Diagnostic') { 'Security Dashboard' } else { 'Windows Debloat' }
$form.ClientSize = [Drawing.Size]::new(1050,700); $form.MinimumSize = [Drawing.Size]::new(820,560)
$form.StartPosition = 'CenterScreen'; $form.Font = [Drawing.Font]::new('Segoe UI',10)
$layout = [Windows.Forms.TableLayoutPanel]::new()
$layout.Dock = 'Fill'; $layout.ColumnCount = 1; $layout.RowCount = 4
[void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new('AutoSize'))
[void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new('AutoSize'))
[void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new('Percent',100))
[void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new('AutoSize'))
$form.Controls.Add($layout)
$intro = [Windows.Forms.Label]::new(); $intro.AutoSize = $true; $intro.MaximumSize = [Drawing.Size]::new(1000,0)
$intro.Padding = [Windows.Forms.Padding]::new(12)
$intro.Text = if ($Tool -eq 'Diagnostic') {
    'Systemdiagnose ohne Installation. Sicherheitsprotokolle brauchen Administratorrechte. Ergebnisse bleiben lokal; HTML ist ein optionaler Export.'
} else {
    'Zuerst erfassen, dann gezielt auswaehlen. App = installiertes Paket; Provisioned = Vorlage fuer neue Benutzer. Es ist nichts vorausgewaehlt. Vor dem Anwenden erscheint die genaue Auswahl.'
}
$layout.Controls.Add($intro,0,0)
$toolbar = [Windows.Forms.FlowLayoutPanel]::new(); $toolbar.AutoSize = $true; $toolbar.Dock = 'Fill'
$scan = New-Button 'Erfassen'; $apply = New-Button 'Auswahl anwenden'; $apply.Enabled = $false
$cancel = New-Button 'Abbrechen'; $cancel.Enabled = $false
$export = New-Button 'Exportieren'; $export.Enabled = $false
$toolbar.Controls.Add($scan); $toolbar.Controls.Add($cancel); $toolbar.Controls.Add($export)
$allUsers = [Windows.Forms.CheckBox]::new(); $allUsers.Text = 'Alle Benutzer'; $allUsers.AutoSize = $true; $allUsers.Checked = $true
if ($Tool -eq 'Debloat') { $toolbar.Controls.Add($apply); $toolbar.Controls.Add($allUsers) }
$layout.Controls.Add($toolbar,0,1)
$tabs = [Windows.Forms.TabControl]::new(); $tabs.Dock = 'Fill'; $tabs.Multiline = $true
$layout.Controls.Add($tabs,0,2)
$footer = [Windows.Forms.FlowLayoutPanel]::new(); $footer.AutoSize = $true; $footer.Dock = 'Fill'
$progress = [Windows.Forms.ProgressBar]::new(); $progress.Style = 'Marquee'; $progress.Visible = $false
$status = [Windows.Forms.Label]::new(); $status.Text = 'Bereit'; $status.AutoSize = $true; $status.Padding = [Windows.Forms.Padding]::new(6)
$footer.Controls.Add($progress); $footer.Controls.Add($status); $layout.Controls.Add($footer,0,3)

$packages = [Windows.Forms.CheckedListBox]::new(); $packages.Dock = 'Fill'; $packages.CheckOnClick = $true
$packages.DisplayMember = 'Label'; $packages.HorizontalScrollbar = $true
$options = [Windows.Forms.CheckedListBox]::new(); $options.Dock = 'Fill'; $options.CheckOnClick = $true; $options.DisplayMember = 'Label'
$optionLabels = [ordered]@{
    Brave='Brave installieren'; DefaultBrowser='Standardbrowser-Einstellungen oeffnen'
    Telemetry='Telemetrie und App-Vorschlaege reduzieren'; DiagTrack='Telemetriedienst deaktivieren'
    dmwappushservice='WAP-Push-Dienst deaktivieren'; SysMain='SysMain deaktivieren (kann App-Starts verlangsamen)'
    WSearch='Suchindex deaktivieren (kann die Suche verlangsamen)'; OneDrive='OneDrive deinstallieren und Synchronisierung sperren'
    McAfeeRemnants='McAfee-Dienste und Aufgaben entfernen/deaktivieren'; GameBar='Game-Bar-Aufrufe und Hintergrundaufnahme deaktivieren'
    Taskbar='Widgets, Chat, Suche und Task View ausblenden'; TaskbarPins='Taskbar-Verknuepfungen ausser Explorer entfernen (mit Sicherung)'
    'Internet-Explorer-Optional-amd64'='Internet-Explorer-Feature deaktivieren'; WindowsMediaPlayer='Windows Media Player deaktivieren'
}
foreach ($id in $optionLabels.Keys) { [void]$options.Items.Add([pscustomobject]@{ Id=$id; Label=$optionLabels[$id] }) }
$resultsGrid = New-Grid
if ($Tool -eq 'Debloat') {
    foreach ($pair in @(@('Apps',$packages),@('Optionen',$options),@('Ergebnis',$resultsGrid))) {
        $page = [Windows.Forms.TabPage]::new($pair[0]); $page.Controls.Add($pair[1]); $tabs.TabPages.Add($page)
    }
}
$scan.Add_Click({
    try {
        if ($Tool -eq 'Diagnostic') {
            Start-Worker 'Diagnostic' 'param($path) & $path' @((Join-Path $root 'diagnostic\Collect-Diagnostics.ps1'))
        } else {
            $state.AllUsers = $allUsers.Checked; $allUsers.Enabled = $false
            Start-Worker 'Inventory' 'param($path,$all) . $path; Get-DebloatInventory -AllUsers:$all' @((Join-Path $root 'debloat\Debloat.Core.ps1'),$state.AllUsers)
        }
    } catch { $status.Text = $_.Exception.Message; $allUsers.Enabled = $true }
})
$allUsers.Add_CheckedChanged({ $packages.Items.Clear(); $apply.Enabled = $false; $status.Text = 'Umfang geaendert: bitte erneut erfassen.' })
$cancel.Add_Click({
    if ($state.Worker -and $state.Mode -ne 'Apply' -and -not $state.Stop) {
        $state.Stop = $state.Worker.BeginStop($null,$null)
        $cancel.Enabled = $false; $status.Text = 'Erfassung wird abgebrochen ...'
    }
})
$apply.Add_Click({
    $selected = @($packages.CheckedItems | ForEach-Object { $_.Item })
    $chosenOptions = @($options.CheckedItems | ForEach-Object { $_.Id })
    if (-not ($selected.Count + $chosenOptions.Count)) { $status.Text = 'Bitte zuerst Aktionen auswaehlen.'; return }
    $preview = @($selected | ForEach-Object { $_.Kind + ': ' + $_.Name }) + @($chosenOptions | ForEach-Object { $optionLabels[$_] })
    if (-not (Confirm-Selection $preview)) { return }
    $runFolder = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('WindowsDebloat-' + [guid]::NewGuid().ToString('N'))
    $state.LogPath = Join-Path $runFolder 'result.json'
    try {
        Start-Worker 'Apply' 'param($path,$selection,$options,$all,$log) . $path; New-DebloatDirectory (Split-Path -Parent $log); Invoke-DebloatPlan -Selection $selection -Options $options -AllUsers:$all -LogPath $log -Confirm:$false' @((Join-Path $root 'debloat\Debloat.Core.ps1'),$selected,$chosenOptions,$state.AllUsers,$state.LogPath)
        $packages.Enabled = $false; $options.Enabled = $false; $allUsers.Enabled = $false
    } catch { $status.Text = $_.Exception.Message }
})
$export.Add_Click({
    $dialog = [Windows.Forms.SaveFileDialog]::new()
    $dialog.Filter = if ($Tool -eq 'Diagnostic') { 'HTML-Bericht|*.html|JSON-Daten|*.json' } else { 'JSON-Protokoll|*.json' }
    $dialog.FileName = $Tool + '-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
    try {
        if ($dialog.ShowDialog($form) -eq 'OK') {
            $content = if ($Tool -eq 'Diagnostic' -and $dialog.FilterIndex -eq 1) { $state.Data.Html }
                elseif ($Tool -eq 'Debloat' -and $state.LogPath) { [IO.File]::ReadAllText($state.LogPath) }
                else { $state.Data | Select-Object * -ExcludeProperty Html | ConvertTo-Json -Depth 12 }
            [IO.File]::WriteAllText($dialog.FileName,$content,[Text.UTF8Encoding]::new($false))
            $status.Text = 'Gespeichert: ' + $dialog.FileName
        }
    } catch { $status.Text = 'Export fehlgeschlagen: ' + $_.Exception.Message }
    finally { $dialog.Dispose() }
})
$timer = [Windows.Forms.Timer]::new(); $timer.Interval = 100
$timer.Add_Tick({
    if (-not $state.Worker -or -not $state.Pending.IsCompleted) { return }
    if ($state.Stop -and -not $state.Stop.IsCompleted) { return }
    $worker = $state.Worker; $runspace = $worker.Runspace
    try {
        if ($state.Stop) { $worker.EndStop($state.Stop) }
        $output = @($worker.EndInvoke($state.Pending))
        if ($worker.HadErrors) { throw ($worker.Streams.Error | Out-String) }
        switch ($state.Mode) {
            'Diagnostic' { $state.Data = $output[0]; Show-Diagnostic $state.Data; $export.Enabled = $true }
            'Inventory' {
                $packages.Items.Clear()
                foreach ($item in $output) { [void]$packages.Items.Add([pscustomobject]@{ Label=($item.Kind + ': ' + $item.Name); Item=$item }) }
                $apply.Enabled = $true; $status.Text = "$($output.Count) Kandidaten gefunden. Gewuenschte Apps und Optionen auswaehlen."
            }
            'Apply' {
                $state.Data = $output; Set-Grid $resultsGrid $output; $tabs.SelectedIndex = 2
                $export.Enabled = $true; $packages.Items.Clear()
                $status.Text = 'Fertig: ' + @($output | Where-Object Status -eq 'Error').Count + ' Fehler. Protokoll: ' + $state.LogPath
            }
            'Smoke' {
                if ($output[0].Value -ne 42) { throw 'Worker result mismatch' }
                Set-Grid $resultsGrid @([pscustomobject]@{ Name='Smoke'; Status='OK' })
                if ($resultsGrid.DataSource.Rows.Count -ne 1) { throw 'Grid data binding failed' }
                if ($Tool -eq 'Diagnostic') {
                    Show-Diagnostic ([pscustomobject]@{ System=[pscustomobject]@{OS='Test'}; Hardware=[pscustomobject]@{CPUName='Test';Disks=@()}; Errors=@(); ProcessCount=0 })
                    if ($tabs.TabPages.Count -ne 15) { throw 'Diagnostic tabs missing' }
                }
                $state.SmokeDone = $true
            }
        }
    } catch {
        $status.Text = if ($state.Stop) { 'Erfassung abgebrochen.' } else { $_.Exception.Message }
        if ($SmokeTest) { $state.SmokeError = $_.Exception.Message }
    }
    finally {
        $worker.Dispose(); $runspace.Dispose(); $state.Worker = $null; $state.Pending = $null; $state.Stop = $null
        $cancel.Enabled = $false
        $scan.Enabled = $true; $allUsers.Enabled = $true; $packages.Enabled = $true; $options.Enabled = $true; $progress.Visible = $false
    }
    if ($SmokeTest -or $state.CloseAfterStop) { $form.Close() }
})
$form.Add_FormClosing({
    if ($state.Worker) {
        $_.Cancel = $true
        if ($state.Mode -eq 'Apply') { $status.Text = 'Bitte den laufenden Vorgang abschliessen lassen.' }
        else { $state.CloseAfterStop = $true; $cancel.PerformClick() }
    }
})
$form.Add_Shown({
    if ($SmokeTest) { Start-Worker 'Smoke' '[pscustomobject]@{Value=42}' @() }
})
$timer.Start()
try { [void]$form.ShowDialog() }
finally { $timer.Stop(); $timer.Dispose(); $form.Dispose() }
if ($SmokeTest -and -not $state.SmokeDone) { throw ('GUI smoke test failed: ' + $state.SmokeError) }
