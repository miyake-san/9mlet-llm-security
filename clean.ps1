#requires -Version 5.1
<##
.SYNOPSIS
    Remove caches do pytest/ruff e ambientes virtuais do repositorio.
.EXAMPLE
    ./clean.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot

Write-Host "==> Limpando caches e ambientes virtuais em: $Root" -ForegroundColor Cyan

$targets = @(Get-ChildItem -Path $Root -Directory -Recurse -Force |
    Where-Object { $_.Name -in @('.pytest_cache', '.ruff_cache', '.venv') })

foreach ($target in $targets) {
    Write-Host "  - $($target.FullName)" -ForegroundColor Yellow
    Remove-Item -LiteralPath $target.FullName -Recurse -Force
}

Write-Host "==> Limpeza concluida." -ForegroundColor Cyan