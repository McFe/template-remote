@echo off
setlocal

net session >nul 2>&1
if errorlevel 1 (
    echo This installer must be run as Administrator.
    exit /b 1
)

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%.") do set "SCRIPT_DIR=%%~fI"
set "AGENT_PATH=%SCRIPT_DIR%\agent.py"
set "TASK_NAME=remote"
for /f "usebackq delims=" %%I in (`python -c "import sys; from pathlib import Path; print(Path(sys.executable).with_name('pythonw.exe'))"`) do set "PYTHONW_PATH=%%I"

if not defined PYTHONW_PATH (
    echo Failed to locate pythonw.exe.
    exit /b 1
)

if not exist "%PYTHONW_PATH%" (
    echo Failed to locate pythonw.exe at "%PYTHONW_PATH%".
    exit /b 1
)

set "TASK_COMMAND=\"%PYTHONW_PATH%\" \"%AGENT_PATH%\""
if not "%~1"=="" (
    set "TASK_COMMAND=%TASK_COMMAND% %*"
)

schtasks /delete /tn "%TASK_NAME%" /f >nul 2>&1

schtasks /create ^
    /tn "%TASK_NAME%" ^
    /tr "%TASK_COMMAND%" ^
    /sc ONSTART ^
    /ru SYSTEM ^
    /rl HIGHEST ^
    /f >nul
if errorlevel 1 (
    echo Failed to create scheduled task.
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$ErrorActionPreference = 'Stop';" ^
    "$taskName = '%TASK_NAME%';" ^
    "$xmlPath = Join-Path $env:TEMP ($taskName + '.xml');" ^
    "$xmlContent = schtasks /query /tn $taskName /xml;" ^
    "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }" ^
    "[System.IO.File]::WriteAllLines($xmlPath, $xmlContent);" ^
    "$xml = [xml](Get-Content $xmlPath -Raw);" ^
    "$ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable);" ^
    "$ns.AddNamespace('t', $xml.Task.NamespaceURI);" ^
    "function Get-OrCreateChild([System.Xml.XmlElement]$parent, [string]$name) { $child = $parent.SelectSingleNode('./t:' + $name, $ns); if (-not $child) { $child = $xml.CreateElement($name, $xml.Task.NamespaceURI); $parent.AppendChild($child) | Out-Null }; return [System.Xml.XmlElement]$child }" ^
    "$bootTrigger = $xml.SelectSingleNode('/t:Task/t:Triggers/t:BootTrigger', $ns);" ^
    "if (-not $bootTrigger) { throw 'Expected BootTrigger in task XML.' }" ^
    "$settings = $xml.SelectSingleNode('/t:Task/t:Settings', $ns);" ^
    "$exec = $xml.SelectSingleNode('/t:Task/t:Actions/t:Exec', $ns);" ^
    "$executionTimeLimit = Get-OrCreateChild $settings 'ExecutionTimeLimit';" ^
    "$executionTimeLimit.InnerText = 'PT0S';" ^
    "$multipleInstances = Get-OrCreateChild $settings 'MultipleInstancesPolicy';" ^
    "$multipleInstances.InnerText = 'IgnoreNew';" ^
    "$disallowOnBatteries = Get-OrCreateChild $settings 'DisallowStartIfOnBatteries';" ^
    "$disallowOnBatteries.InnerText = 'false';" ^
    "$startWhenAvailable = Get-OrCreateChild $settings 'StartWhenAvailable';" ^
    "$startWhenAvailable.InnerText = 'true';" ^
    "$workingDirectory = Get-OrCreateChild $exec 'WorkingDirectory';" ^
    "$workingDirectory.InnerText = '%SCRIPT_DIR%';" ^
    "$restart = Get-OrCreateChild $settings 'RestartOnFailure';" ^
    "$interval = Get-OrCreateChild $restart 'Interval';" ^
    "$interval.InnerText = 'PT1M';" ^
    "$count = Get-OrCreateChild $restart 'Count';" ^
    "$count.InnerText = '255';" ^
    "$repetition = $bootTrigger.SelectSingleNode('./t:Repetition', $ns);" ^
    "if ($repetition) { $bootTrigger.RemoveChild($repetition) | Out-Null }" ^
    "$xml.Save($xmlPath);" ^
    "schtasks /create /tn $taskName /xml $xmlPath /f | Out-Null;" ^
    "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }" ^
    "Remove-Item $xmlPath -Force"
if errorlevel 1 (
    echo Failed to configure automatic restart for the scheduled task.
    exit /b 1
)

echo task installed successfully.
