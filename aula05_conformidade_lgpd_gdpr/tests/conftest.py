"""Fixtures compartilhadas: rag-api COMPLIANT (backend stub) e isolamento de estado.

Tudo roda **offline** e determinístico: backend ``stub``, vector store e consent
em memória, minimização pelo detector BR (Presidio ausente), consent-service
inacessível (fallback local). Cada teste recebe stores limpos e um caminho de
trilha de tratamento efêmero (Doc 04, §12 — 12-factor / minimização).
"""

from __future__ import annotations

import os

# Configuração offline ANTES de instanciar Settings.
os.environ.setdefault("LLM_BACKEND", "stub")
os.environ.setdefault("VECTOR_STORE", "memory")
os.environ.setdefault("CONSENT_STORE", "memory")
os.environ.setdefault("ENFORCE_CONSENT", "true")
os.environ.setdefault("MINIMIZE_PII", "true")
os.environ.setdefault("AI_DISCLOSURE_ENABLED", "true")
os.environ.setdefault("REFUSE_AUTOMATED_CREDIT_DECISION", "true")
os.environ.setdefault("AI_ACT_RISK_TIER", "limited")
# consent-service inexistente -> força o fallback local. O host `.invalid` NUNCA
# resolve (RFC 6761), então o httpx falha no DNS instantaneamente (sem timeout).
os.environ.setdefault("CONSENT_SERVICE_URL", "http://consent-service.invalid")
# Sem Presidio -> detector determinístico BR.
os.environ.pop("PRESIDIO_ANALYZER_URL", None)
os.environ.pop("PRESIDIO_ANONYMIZER_URL", None)

from collections.abc import Iterator  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.llm import StubBackend  # noqa: E402
from app.main import (  # noqa: E402
    app,
    get_consent_gateway,
    get_llm,
    get_minimizer,
    get_treatment_registry,
    get_vector_store,
)

_CACHED = (
    get_settings,
    get_consent_gateway,
    get_vector_store,
    get_treatment_registry,
    get_minimizer,
)


def _clear_caches() -> None:
    for fn in _CACHED:
        fn.cache_clear()


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch) -> Iterator[None]:
    """Estado limpo por teste: trilha efêmera + caches zerados."""
    monkeypatch.setenv("TREATMENT_LOG_PATH", str(tmp_path / "treatment_chain.jsonl"))
    _clear_caches()
    yield
    _clear_caches()


@pytest.fixture
def client() -> Iterator[TestClient]:
    """TestClient da rag-api com backend de LLM forçado para o StubBackend."""
    app.dependency_overrides[get_llm] = lambda: StubBackend()
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
