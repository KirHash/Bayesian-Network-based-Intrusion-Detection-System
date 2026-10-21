<#
.SYNOPSIS
    Downloads Caddy (a reverse proxy with built-in HTTPS) into proxy\bin.

.DESCRIPTION
    The download is checked against the SHA-512 checksum published with the
    release before anything is unpacked or run. Nothing is installed system-wide
    and no administrator rights are needed.

.EXAMPLE
    .\install-caddy.ps1
    .\install-caddy.ps1 -Version 2.11.7
#>
[CmdletBinding()]
param(
    [string]$Version = '2.11.7'
)

$ErrorActionPreference = 'Stop'

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }

$zipName   = "caddy_${Version}_windows_$arch.zip"
$base      = "https://github.com/caddyserver/caddy/releases/download/v$Version"
$target    = Join-Path $PSScriptRoot 'bin'

# a fresh, empty folder: downloads are untrusted until verified
$work = Join-Path ([IO.Path]::GetTempPath()) ("caddy-" + [guid]::NewGuid().ToString('N'))

New-Item -ItemType Directory -Path $work | Out-Null

try {
    $zip  = Join-Path $work $zipName
    $sums = Join-Path $work 'checksums.txt'

    Write-Host "Downloading $zipName ..."

    Invoke-WebRequest "$base/$zipName" -OutFile $zip -UseBasicParsing
    Invoke-WebRequest "$base/caddy_${Version}_checksums.txt" -OutFile $sums -UseBasicParsing

    $line = Get-Content $sums | Where-Object { $_ -match [regex]::Escape($zipName) } | Select-Object -First 1

    if (-not $line) { throw "No checksum for $zipName in the release's checksums file." }

    $expected = ($line -split '\s+')[0].ToLowerInvariant()
    $actual   = (Get-FileHash -Algorithm SHA512 $zip).Hash.ToLowerInvariant()

    if ($actual -ne $expected) {
        throw "Checksum mismatch: the download is not what the release published.`n  expected $expected`n  got      $actual"
    }

    Write-Host "SHA-512 matches the published checksum."

    $unpacked = Join-Path $work 'unpacked'

    Expand-Archive -Path $zip -DestinationPath $unpacked

    New-Item -ItemType Directory -Force -Path $target | Out-Null

    Copy-Item (Join-Path $unpacked 'caddy.exe') (Join-Path $target 'caddy.exe') -Force

    & (Join-Path $target 'caddy.exe') version
}
finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
