# syntax=docker/dockerfile:1.9
###############################################################################
# Aurora Assist v0 — imagem HARDENED da API (deliberadamente vulnerável no app,
# mas endurecida no contêiner). Doc 04, seção 8: "o princípio do menor
# privilégio precisa existir FORA do modelo".
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

LABEL org.opencontainers.image.title="aurora-assist-vulnerable" \
      org.opencontainers.image.description="Aula 01 — API deliberadamente vulnerável para red team em laboratório controlado" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PATH="/opt/venv/bin:$PATH"

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
EXPOSE 8000

# Healthcheck via stdlib (sem curl/wget na imagem slim).
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status==200 else 1)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
