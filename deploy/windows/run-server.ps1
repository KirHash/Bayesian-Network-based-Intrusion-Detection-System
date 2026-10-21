<#
.SYNOPSIS
    Starts the server for the scheduled task: loads ids.env, runs serve.py,
    appends output to logs\server.log (rotated at 10 MB).

    You normally do not run this yourself; install-service.ps1 registers it.
#>
param(
    [Parameter(Mandatory)][string]$Python,
    [Parameter(Mandatory)][string]$ProjectDir,
    [string]$ServeArgs = ''
)

$ErrorActionPreference = 'Stop'

Set-Location $ProjectDir

# KEY=value lines, '#' comments allowed. Keeps secrets out of the task definition.
$envFile = Join-Path $PSScriptRoot 'ids.env'

if (Test-Path $envFile) {
    foreach ($line in Get-Content $envFile) {
        $trimmed = $line.Trim()

        if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { continue }

        if ($trimmed -match '^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$') {
            $value = $Matches[2].Trim().Trim('"')
            [Environment]::SetEnvironmentVariable($Matches[1], $value, 'Process')
        }
    }
}

$logDir = Join-Path $ProjectDir 'logs'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

$log = Join-Path $logDir 'server.log'

if ((Test-Path $log) -and ((Get-Item $log).Length -gt 10MB)) {
    Move-Item -Force $log "$log.1"
}

$arguments = @('serve.py') + @($ServeArgs -split '\s+' | Where-Object { $_ })

"[$(Get-Date -Format s)] starting: $Python $($arguments -join ' ')" | Out-File -Append -Encoding utf8 $log

# the task's restart-on-failure policy brings it back if this exits non-zero
& $Python @arguments *>> $log

exit $LASTEXITCODE
