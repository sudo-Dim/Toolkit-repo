@echo off
set "TOOLKIT_GUI=%~dp0Start-Tool.ps1"
powershell.exe -NoLogo -NoProfile -Command "$p=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()); if($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){ & $env:TOOLKIT_GUI -Tool Debloat } else { Start-Process powershell.exe -Verb RunAs -ArgumentList ('-NoProfile -STA -ExecutionPolicy Bypass -File ' + [char]34 + $env:TOOLKIT_GUI + [char]34 + ' -Tool Debloat') }"
