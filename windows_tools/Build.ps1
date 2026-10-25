[CmdletBinding()]
param([string]$OutputDirectory = (Join-Path $PSScriptRoot '..\dist\windows-tools'))
$ErrorActionPreference = 'Stop'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw 'Build requires 64-bit Windows with .NET Framework 4.x.' }
$output = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $output -Force | Out-Null
$work = Join-Path ([IO.Path]::GetTempPath()) ('ToolkitBuild-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
$artifacts = [Collections.Generic.List[object]]::new()
try {
    foreach ($tool in @('Diagnostic','Debloat')) {
        $name = if ($tool -eq 'Diagnostic') { 'SecurityDashboard' } else { 'WindowsDebloat' }
        $files = @('Start-Tool.ps1')
        $files += if ($tool -eq 'Diagnostic') { 'diagnostic/Collect-Diagnostics.ps1' } else { 'debloat/Debloat.Core.ps1'; 'debloat/catalog.json' }
        $compilerArguments = @('/nologo','/target:winexe','/platform:x64','/optimize+','/reference:System.Windows.Forms.dll',('/out:' + (Join-Path $output "$name.exe")))
        if ($tool -eq 'Debloat') { $compilerArguments += '/define:DEBLOAT' }
        $level = if ($tool -eq 'Debloat') { 'requireAdministrator' } else { 'asInvoker' }
        $manifest = Join-Path $work 'app.manifest'
        [IO.File]::WriteAllText($manifest, '<?xml version="1.0" encoding="utf-8"?><assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1"><trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges><requestedExecutionLevel level="' + $level + '" uiAccess="false"/></requestedPrivileges></security></trustInfo></assembly>')
        $compilerArguments += '/win32manifest:' + $manifest
        foreach ($file in $files) {
            $compressed = Join-Path $work ([IO.Path]::GetFileName($file) + '.gz')
            $stream = [IO.File]::Create($compressed)
            $gzip = [IO.Compression.GZipStream]::new($stream,[IO.Compression.CompressionLevel]::Optimal)
            try {
                $bytes = [IO.File]::ReadAllBytes((Join-Path $PSScriptRoot $file))
                $gzip.Write($bytes,0,$bytes.Length)
            } finally { $gzip.Dispose(); $stream.Dispose() }
            $compilerArguments += '/resource:' + $compressed + ',' + $file
        }
        & $compiler @compilerArguments (Join-Path $PSScriptRoot 'Launcher.cs')
        if ($LASTEXITCODE -ne 0) { throw "Compiler failed: $name" }
        if (-not (Test-Path -LiteralPath (Join-Path $output "$name.exe"))) { throw "Compiler produced no executable: $name" }
        Compress-Archive -LiteralPath (Join-Path $output "$name.exe") -DestinationPath (Join-Path $output "$name-windows-x64.zip") -Force
        $artifacts.Add([pscustomobject]@{
            Name="$name.exe"; Bytes=(Get-Item (Join-Path $output "$name.exe")).Length
            SHA256=(Get-FileHash (Join-Path $output "$name.exe") -Algorithm SHA256).Hash.ToLowerInvariant()
            ExternalRuntimePackages=0
        })
        Get-Item -LiteralPath (Join-Path $output "$name.exe") | Select-Object Name,Length
    }
    $info = [pscustomobject]@{ BuiltAt=(Get-Date).ToUniversalTime().ToString('o'); BuildHost='Windows'; Artifacts=$artifacts.ToArray() }
    [IO.File]::WriteAllText((Join-Path $output 'build-info.json'),($info | ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
} finally { Remove-Item -LiteralPath $work -Recurse -Force }
