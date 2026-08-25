#!/usr/bin/env bash
# Remove caches do pytest/ruff e ambientes virtuais do repositorio.
# Uso: ./clean.sh
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Limpando caches e ambientes virtuais em: $ROOT"

find "$ROOT" -type d \( \
  -name '.pytest_cache' -o \
  -name '.ruff_cache' -o \
  -name '.venv' \
\) -prune -print -exec rm -rf {} +

echo "==> Limpeza concluida."