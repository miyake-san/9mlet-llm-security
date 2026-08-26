#!/usr/bin/env bash
# Constroi as imagens Docker das oito aulas e grava um relatorio da execucao.
# Uso: ./build_all.sh [--no-cache] [--pull] [--fail-fast]
set -uo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$ROOT/logs"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$LOG_DIR/build_all_${TIMESTAMP}.log"
NO_CACHE=0
PULL=0
FAIL_FAST=0

for arg in "$@"; do
  case "$arg" in
    --no-cache) NO_CACHE=1 ;;
    --pull) PULL=1 ;;
    --fail-fast) FAIL_FAST=1 ;;
    -h|--help)
      sed -n '2,4p' "$0"
      exit 0
      ;;
    *)
      printf 'Opcao desconhecida: %s\n' "$arg" >&2
      exit 2
      ;;
  esac
done

mkdir -p "$LOG_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1

lessons=(
  aula01_ameacas_vulnerabilidades
  aula02_guardrails_politicas
  aula03_protecao_dados_isolamento
  aula04_testes_seguranca_auditoria
  aula05_conformidade_lgpd_gdpr
  aula06_governanca_monitoramento
  aula07_etica_vies_validacao
  aula08_governanca_deploy_seguro
)

profile_for() {
  case "$1" in
    aula01_ameacas_vulnerabilidades|aula04_testes_seguranca_auditoria) printf 'redteam' ;;
    aula07_etica_vies_validacao) printf 'eval' ;;
    aula08_governanca_deploy_seguro) printf 'security' ;;
    *) printf '' ;;
  esac
}

if ! command -v docker >/dev/null 2>&1; then
  printf 'ERRO: Docker nao foi encontrado no PATH.\n'
  exit 127
fi
if ! docker info >/dev/null 2>&1; then
  printf 'ERRO: Docker Desktop/daemon nao esta disponivel.\n'
  exit 125
fi

printf 'Inicio: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
printf 'Log: %s\n' "$LOG_FILE"
printf 'Opcoes: %s %s\n\n' "$([[ "$NO_CACHE" -eq 1 ]] && printf 'no-cache' || printf 'cache')" "$([[ "$PULL" -eq 1 ]] && printf 'pull' || printf 'sem-pull')"

failed=0
passed=0

run_lesson() {
  local lesson="$1"
  local profile="$(profile_for "$lesson")"
  local -a compose=(docker compose)
  [[ -n "$profile" ]] && compose+=(--profile "$profile")

  printf '\n========== %s ==========%s\n' "$lesson" "${profile:+ perfil=$profile}"
  if ! (cd "$ROOT/$lesson" && docker compose config >/dev/null); then
    printf 'FALHA [%s] docker compose config\n' "$lesson"
    return 1
  fi
  if [[ "$NO_CACHE" -eq 1 && "$PULL" -eq 1 ]]; then
    build_command=(build --no-cache --pull)
  elif [[ "$NO_CACHE" -eq 1 ]]; then
    build_command=(build --no-cache)
  elif [[ "$PULL" -eq 1 ]]; then
    build_command=(build --pull)
  else
    build_command=(build)
  fi
  if ! (cd "$ROOT/$lesson" && "${compose[@]}" "${build_command[@]}"); then
    printf 'FALHA [%s] build\n' "$lesson"
    return 1
  fi
  printf 'SUCESSO [%s]\n' "$lesson"
  return 0
}

for lesson in "${lessons[@]}"; do
  if run_lesson "$lesson"; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    [[ "$FAIL_FAST" -eq 1 ]] && break
  fi
done

printf '\n========== RESUMO =========='\nprintf '\nAulas com sucesso: %d/%d\n' "$passed" "${#lessons[@]}"
printf 'Aulas com falha: %d\n' "$failed"
printf 'Fim: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
printf 'Log completo: %s\n' "$LOG_FILE"

if [[ "$failed" -gt 0 ]]; then
  exit 1
fi
exit 0
