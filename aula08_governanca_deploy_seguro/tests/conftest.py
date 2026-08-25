"""Fixtures compartilhadas: agente offline (StubBackend) e cliente da agent-app.

Backend determinístico offline por padrão (sem rede). O agente ingênuo (guardrails
desligados) reflete a versão que o deploy gate reprova; os testes fixam a linha de
base: ingênuo REPROVA, endurecido PASSA.
"""

from __future__ import annotations

import os
import runpy
from pathlib import Path

os.environ.setdefault("LLM_BACKEND", "stub")
os.environ.setdefault("AGENT_GUARDRAILS_ENABLED", "false")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.agent import Agent  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.llm import StubBackend  # noqa: E402
from app.main import app, get_agent  # noqa: E402
from src.security.observability import InMemoryTraceStore  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session", autouse=True)
def _ensure_datasets():
    """Gera os datasets sintéticos (seed=42) se ainda não existirem (test self-contained)."""
    if not (_ROOT / "data" / "golden" / "golden_qa.jsonl").exists():
        runpy.run_path(str(_ROOT / "scripts" / "generate_datasets.py"), run_name="__main__")
    yield


def build_agent(*, guardrails: bool) -> Agent:
    """Agente offline (StubBackend) com guardrails ligados/desligados."""
    return Agent(
        StubBackend(),
        guardrails_enabled=guardrails,
        trace_store=InMemoryTraceStore(),
        model_version="aurora-assist-3.0.0-test",
    )


@pytest.fixture(autouse=True)
def _clear_caches():
    """Limpa caches de Settings e do agente entre testes (flags via env não vazam)."""
    from app.main import _agent

    get_settings.cache_clear()
    _agent.cache_clear()
    yield
    get_settings.cache_clear()
    _agent.cache_clear()


@pytest.fixture
def client():
    """TestClient com o agente INGÊNUO (guardrails desligados) forçado."""
    app.dependency_overrides[get_agent] = lambda: build_agent(guardrails=False)
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def client_hardened():
    """TestClient com o agente ENDURECIDO (guardrails ligados) forçado."""
    app.dependency_overrides[get_agent] = lambda: build_agent(guardrails=True)
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def naive_agent() -> Agent:
    return build_agent(guardrails=False)


@pytest.fixture
def hardened_agent() -> Agent:
    return build_agent(guardrails=True)
