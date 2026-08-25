# syntax=docker/dockerfile:1.9
###############################################################################
# Aurora Assist v1 — imagem HARDENED do pipeline Zero Trust de dados (Aula 03).
# A MESMA imagem serve dois papéis (APP_ROLE / entrypoint):
#   - "rag"  (app.main:app, porta 8000): orquestra ingress→LLM→tools→egress.
#   - "mcp"  (app.mcp_server:app, porta 8090): ferramentas isoladas (somente
#            leitura), executadas em rede INTERNA (sem egress) no compose.
#
# Doc 04, §2/§10: o menor privilégio precisa existir FORA do modelo — no
# contêiner (non-root, read-only, seccomp) e na rede (isolamento).
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

LABEL org.opencontainers.image.title="aurora-assist-zerotrust" \
      org.opencontainers.image.description="Aula 03 — Pipeline Zero Trust de proteção de dados (Presidio + tokenização) e ferramentas MCP isoladas para o Aurora Assist" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    APP_ROLE=rag \
    APP_PORT=8000

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
# 8000 = papel rag (Aurora Assist) · 8090 = papel mcp (ferramentas isoladas)
EXPOSE 8000 8090

# Healthcheck via stdlib (sem curl/wget na imagem slim). Usa APP_PORT (o compose
# define a porta correta por serviço).
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
  CMD ["python", "-c", "import os,urllib.request,sys; p=os.getenv('APP_PORT','8000'); sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{p}/health', timeout=3).status==200 else 1)"]

# Default = Aurora Assist (rag) na 8000. O compose define `command` por serviço.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
