"""Fixtures compartilhadas: app OTel-instrumentado (backend stub) e isolamento.

Tudo roda **offline** e determinístico: backend ``stub``, OTel/Langfuse
desligados, cache/roteamento ativos e coletor de spans em arquivo efêmero. Cada
teste recebe instrumentação/knowledge/feedback limpos (caches lru zerados) para
que as métricas Prometheus e a telemetria não vazem entre testes (Doc 04, §Obs.).
"""

from __future__ import annotations

import os

# Configuração offline ANTES de instanciar Settings.
os.environ.setdefault("LLM_BACKEND", "stub")
os.environ.setdefault("SEMANTIC_CACHE_ENABLED", "true")
os.environ.setdefault("MODEL_ROUTING_ENABLED", "true")
os.environ.setdefault("MINIMIZE_TELEMETRY_PII", "true")
os.environ.setdefault("OTEL_TRACES_ENABLED", "false")
os.environ.setdefault("LANGFUSE_ENABLED", "false")
os.environ.pop("OTEL_EXPORTER_OTLP_ENDPOINT", None)

from collections.abc import Iterator  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.llm import StubBackend  # noqa: E402
from app.main import (  # noqa: E402
    app,
    get_feedback_store,
    get_instrumentation,
    get_knowledge,
    get_llm,
)

_CACHED = (get_settings, get_instrumentation, get_knowledge, get_feedback_store)


def _clear_caches() -> None:
    for fn in _CACHED:
        fn.cache_clear()


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch) -> Iterator[None]:
    """Estado limpo por teste: coletor de spans efêmero + caches zerados."""
    monkeypatch.setenv("TRACE_STORE_PATH", str(tmp_path / "traces.jsonl"))
    _clear_caches()
    yield
    _clear_caches()


@pytest.fixture
def client() -> Iterator[TestClient]:
    """TestClient do app com backend de LLM forçado para o StubBackend."""
    app.dependency_overrides[get_llm] = lambda: StubBackend()
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
