<#
.SYNOPSIS
    Run the Bayesian IDS server as a Windows scheduled task that starts at
    boot and is restarted if it exits.

.DESCRIPTION
    Needs an elevated (administrator) PowerShell, except with -DryRun.

    The task runs as SYSTEM so packet capture has the rights it needs. SYSTEM
    cannot see Python packages installed "for the current user", so use a
    virtual environment inside the project:

        python -m venv .venv
        .\.venv\Scripts\pip install -r requirements-prod.txt

    The script uses .venv\Scripts\python.exe when it exists.

    Settings (passwords, tokens, database path) go in deploy\windows\ids.env,
    one KEY=value per line; see ids.env.example.

.EXAMPLE
    .\install-service.ps1 -ServeArgs '--self-signed --host 0.0.0.0'
.EXAMPLE
    .\install-service.ps1 -DryRun
.EXAMPLE
    .\install-service.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string]$Python,
    [string]$ProjectDir,
    [string]$TaskName = 'BayesianIDS',
    [string]$ServeArgs = '',
    [switch]$Uninstall,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

# ($PSScriptRoot is empty inside a parameter default in Windows PowerShell 5.1)
if (-not $ProjectDir) {
    $ProjectDir = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}

function Test-Administrator {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not $DryRun -and -not (Test-Administrator)) {
    throw 'Run this from an elevated (administrator) PowerShell, or use -DryRun to preview.'
}

if ($Uninstall) {
    if ($DryRun) {
        Write-Host "[dry run] would stop and remove the scheduled task '$TaskName'"
        return
    }

    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed '$TaskName'. Your database and logs were left in place."
    } else {
        Write-Host "No task named '$TaskName'."
    }

    return
}

if (-not $Python) {
    $venv = Join-Path $ProjectDir '.venv\Scripts\python.exe'

    if (Test-Path $venv) {
        $Python = $venv
    } else {
        $Python = (Get-Command python -ErrorAction Stop).Source
    }
}

foreach ($required in @($Python, (Join-Path $ProjectDir 'serve.py'), (Join-Path $ProjectDir 'bayesian_ids.pkl'))) {
    if (-not (Test-Path $required)) { throw "Missing: $required" }
}

if (-not (Test-Path (Join-Path $ProjectDir 'frontend\dist\index.html'))) {
    Write-Warning 'frontend\dist is missing: run "npm run build" in frontend\ or the dashboard page will be empty.'
}

# SYSTEM reads packages from the interpreter's own folders, not a user profile
$packageDir = & $Python -c "import fastapi, os; print(os.path.dirname(fastapi.__file__))" 2>$null

if ($packageDir -match '\\Users\\[^\\]+\\AppData\\Roaming') {
    Write-Warning "Packages are installed in a user profile ($packageDir). The SYSTEM account cannot read them; create a .venv in the project (see Get-Help) and reinstall."
}

$runner = Join-Path $PSScriptRoot 'run-server.ps1'

$arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$runner`" -Python `"$Python`" -ProjectDir `"$ProjectDir`""

if ($ServeArgs) { $arguments += " -ServeArgs `"$ServeArgs`"" }

$action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments -WorkingDirectory $ProjectDir
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -MultipleInstances IgnoreNew

Write-Host "Task name:   $TaskName"
Write-Host "Runs:        powershell.exe $arguments"
Write-Host "Starts:      at boot, as SYSTEM, restarted every minute if it exits"
Write-Host "Logs:        $(Join-Path $ProjectDir 'logs\server.log')"

if ($DryRun) {
    Write-Host '[dry run] nothing was registered.'
    return
}

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null

Start-ScheduledTask -TaskName $TaskName

Write-Host "Installed and started. Check: Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo"
Write-Host 'Health:      curl http://127.0.0.1:8000/api/healthz   (use https:// with --self-signed or --cert)'
