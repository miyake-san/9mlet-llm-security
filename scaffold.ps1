#requires -Version 5.1
<#
.SYNOPSIS
    Scaffold idempotente do repositorio-base 9mlet-llm-security.
.DESCRIPTION
    Cria a arvore de diretorios, as 8 pastas de aula e stubs de documentacao
    SEM sobrescrever arquivos existentes. Seguro para reexecucao.
.EXAMPLE
    ./scaffold.ps1
    ./scaffold.ps1 -Root "E:\Personal\08_Projects-Code-Repos\9mlet-llm-security"
#>
[CmdletBinding()]
param(
    [string]$Root = "E:\Personal\08_Projects-Code-Repos\9mlet-llm-security"
)

$ErrorActionPreference = 'Stop'
Write-Host "==> Scaffold do repositorio em: $Root" -ForegroundColor Cyan

# --- Diretorios ----------------------------------------------------------
$dirs = @(
    'docs/architecture/diagrams',
    'docs/architecture/adr',
    'docs/business/process-diagrams',
    'docs/compliance',
    'aula01_ameacas_vulnerabilidades',
    'aula02_guardrails_politicas',
    'aula03_protecao_dados_isolamento',
    'aula04_testes_seguranca_auditoria',
    'aula05_conformidade_lgpd_gdpr',
    'aula06_governanca_monitoramento',
    'aula07_etica_vies_validacao',
    'aula08_governanca_deploy_seguro'
)
foreach ($d in $dirs) {
    $path = Join-Path $Root $d
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        Write-Host "  + dir  $d" -ForegroundColor Green
    } else {
        Write-Host "  = dir  $d (existe)" -ForegroundColor DarkGray
    }
}

# --- Utilitario: cria arquivo apenas se ausente --------------------------
function New-StubFile {
    param([string]$RelPath, [string]$Content = '')
    $path = Join-Path $Root $RelPath
    $parent = Split-Path $path -Parent
    if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    if (-not (Test-Path $path)) {
        Set-Content -Path $path -Value $Content -Encoding UTF8
        Write-Host "  + file $RelPath" -ForegroundColor Green
    } else {
        Write-Host "  = file $RelPath (existe)" -ForegroundColor DarkGray
    }
}

# --- Stubs de documentacao e configuracao --------------------------------
$stub = '<!-- TODO: preencher via PROMPT A (documento de alto valor) -->'
$stubs = @(
    'README.md',
    'pyproject.toml',
    '.gitignore',
    '.env.example',
    'LICENSE',
    'docs/architecture/overview.md',
    'docs/architecture/diagrams/threat-model.md',
    'docs/architecture/diagrams/zero-trust-architecture.md',
    'docs/architecture/diagrams/secure-deployment.md',
    'docs/architecture/adr/template.md',
    'docs/architecture/adr/0001-framework-guardrails.md',
    'docs/architecture/adr/0002-estrategia-pii.md',
    'docs/architecture/adr/0003-isolamento-ferramentas-mcp.md',
    'docs/architecture/adr/0004-observabilidade-llmops.md',
    'docs/architecture/adr/0005-deploy-seguro-gates.md',
    'docs/business/README.md',
    'docs/business/use-cases.md',
    'docs/business/business-case-aurora-assist-guardrails.md',
    'docs/business/business-case-conformidade-lgpd.md',
    'docs/business/business-case-deploy-seguro-governanca.md',
    'docs/business/process-diagrams/secure-sdlc.md',
    'docs/business/process-diagrams/incident-response.md',
    'docs/compliance/README.md',
    'docs/compliance/mapa-lgpd-gdpr-euaiact.md'
)
foreach ($s in $stubs) { New-StubFile -RelPath $s -Content $stub }

# --- .gitkeep nas pastas de aula (vazias) --------------------------------
foreach ($a in ($dirs | Where-Object { $_ -like 'aula0*' })) {
    New-StubFile -RelPath "$a/.gitkeep" -Content ''
}

Write-Host "==> Scaffold concluido." -ForegroundColor Cyan
