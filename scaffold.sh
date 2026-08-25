#!/usr/bin/env bash
# Scaffold idempotente do repositorio-base 9mlet-llm-security.
# Cria a arvore, as 8 pastas de aula e stubs SEM sobrescrever arquivos existentes.
# Uso: ./scaffold.sh [ROOT]
set -euo pipefail

ROOT="${1:-/e/Personal/08_Projects-Code-Repos/9mlet-llm-security}"
echo "==> Scaffold do repositorio em: $ROOT"

dirs=(
  "docs/architecture/diagrams"
  "docs/architecture/adr"
  "docs/business/process-diagrams"
  "docs/compliance"
  "aula01_ameacas_vulnerabilidades"
  "aula02_guardrails_politicas"
  "aula03_protecao_dados_isolamento"
  "aula04_testes_seguranca_auditoria"
  "aula05_conformidade_lgpd_gdpr"
  "aula06_governanca_monitoramento"
  "aula07_etica_vies_validacao"
  "aula08_governanca_deploy_seguro"
)
for d in "${dirs[@]}"; do
  mkdir -p "$ROOT/$d"
  echo "  + dir  $d"
done

new_stub() {
  local rel="$1"; local content="${2:-}"
  local path="$ROOT/$rel"
  mkdir -p "$(dirname "$path")"
  if [[ ! -f "$path" ]]; then
    printf '%s\n' "$content" > "$path"
    echo "  + file $rel"
  else
    echo "  = file $rel (existe)"
  fi
}

STUB='<!-- TODO: preencher via PROMPT A (documento de alto valor) -->'
stubs=(
  "README.md"
  "pyproject.toml"
  ".gitignore"
  ".env.example"
  "LICENSE"
  "docs/architecture/overview.md"
  "docs/architecture/diagrams/threat-model.md"
  "docs/architecture/diagrams/zero-trust-architecture.md"
  "docs/architecture/diagrams/secure-deployment.md"
  "docs/architecture/adr/template.md"
  "docs/architecture/adr/0001-framework-guardrails.md"
  "docs/architecture/adr/0002-estrategia-pii.md"
  "docs/architecture/adr/0003-isolamento-ferramentas-mcp.md"
  "docs/architecture/adr/0004-observabilidade-llmops.md"
  "docs/architecture/adr/0005-deploy-seguro-gates.md"
  "docs/business/README.md"
  "docs/business/use-cases.md"
  "docs/business/business-case-aurora-assist-guardrails.md"
  "docs/business/business-case-conformidade-lgpd.md"
  "docs/business/business-case-deploy-seguro-governanca.md"
  "docs/business/process-diagrams/secure-sdlc.md"
  "docs/business/process-diagrams/incident-response.md"
  "docs/compliance/README.md"
  "docs/compliance/mapa-lgpd-gdpr-euaiact.md"
)
for s in "${stubs[@]}"; do new_stub "$s" "$STUB"; done

for d in "${dirs[@]}"; do
  case "$d" in
    aula0*) new_stub "$d/.gitkeep" "" ;;
  esac
done

echo "==> Scaffold concluido."
