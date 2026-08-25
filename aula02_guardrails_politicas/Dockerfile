# syntax=docker/dockerfile:1.9
###############################################################################
# Aurora Assist v1 — imagem HARDENED do serviço de guardrails.
# A MESMA imagem serve dois papéis (APP_ROLE): "gateway" (camadas de defesa) e
# "rag" (backend Aurora Assist). Doc 04, seção 1: defense-in-depth — o menor
# privilégio precisa existir FORA do modelo, no contêiner e na rede.
#
# Multi-stage: (1) resolve dependências com uv; (2) runtime slim, non-root.
# Para pinar por digest (recomendado em produção):
#   FROM python@sha256:<digest> AS runtime
###############################################################################

# uv oficial pinado — copiamos apenas o binário estático.
FROM ghcr.io/astral-sh/uv:0.5.11 AS uv

# ---------- Stage 1: builder (resolve dependências de runtime) ----------
FROM python:3.12.7-slim-bookworm AS builder
COPY --from=uv /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0 \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /build
# Copiamos só o manifesto primeiro: dependências mudam menos que o código (cache).
COPY pyproject.toml ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --no-dev --no-install-project

# ---------- Stage 2: runtime (mínimo, sem toolchain de build) ----------
FROM python:3.12.7-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="aurora-assist-guardrail" \
      org.opencontainers.image.description="Aula 02 — Gateway de guardrails multi-camada (defense-in-depth) para o Aurora Assist" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    APP_ROLE=gateway

# Usuário não-root, uid alto, sem home e sem shell interativo.
RUN groupadd --gid 10001 aurora \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin aurora

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --chown=10001:10001 app/ ./app/
COPY --chown=10001:10001 src/ ./src/
COPY --chown=10001:10001 configs/ ./configs/
COPY --chown=10001:10001 data/ ./data/

USER 10001:10001
# 8000 = papel rag (backend) · 8080 = papel gateway (camadas de guardrail)
EXPOSE 8000 8080

# Healthcheck via stdlib (sem curl/wget na imagem slim). A porta padrão é a do
# gateway (8080); o compose sobrescreve o healthcheck do rag-api para a 8000.
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
  CMD ["python", "-c", "import os,urllib.request,sys; p=os.getenv('APP_PORT','8080'); sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{p}/health', timeout=3).status==200 else 1)"]

# Default = gateway na 8080. O compose define `command` explícito por serviço.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
