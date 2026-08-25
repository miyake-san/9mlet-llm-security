"""Fixtures compartilhadas: cliente da target-api (backend stub) e alvos offline.

Backend determinístico offline por padrão (sem rede). As flags de mitigação
começam desligadas, refletindo o Aurora Assist ingênuo (com viés e alucinação).
"""

from __future__ import annotations

import os

os.environ.setdefault("LLM_BACKEND", "stub")
os.environ.setdefault("FAIRNESS_MITIGATION", "false")
os.environ.setdefault("RAG_STRICT_GROUNDING", "false")
os.environ.setdefault("JUDGE_DEBIAS_POSITION", "true")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.eval_ragas import (  # noqa: E402
    InProcessTarget,
    load_counterfactual_pairs,
    load_golden,
    load_profiles,
)
from app.llm import StubBackend  # noqa: E402
from app.main import app, get_llm  # noqa: E402


@pytest.fixture(autouse=True)
def _clear_settings_cache():
    """Limpa o cache de Settings entre testes (flags via env não vazam)."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def client():
    """TestClient com backend de LLM forçado para o StubBackend (offline)."""
    app.dependency_overrides[get_llm] = lambda: StubBackend()
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def naive_target() -> InProcessTarget:
    """Aurora Assist SEM mitigação (viés + alucinação)."""
    return InProcessTarget(mitigate_fairness=False, strict_grounding=False)


@pytest.fixture
def mitigated_target() -> InProcessTarget:
    """Aurora Assist COM mitigação (fairness neutralizado + grounding estrito)."""
    return InProcessTarget(mitigate_fairness=True, strict_grounding=True)


@pytest.fixture(scope="session")
def golden() -> list[dict]:
    return load_golden()


@pytest.fixture(scope="session")
def profiles() -> list[dict]:
    return load_profiles()


@pytest.fixture(scope="session")
def counterfactual_pairs() -> list[dict]:
    return load_counterfactual_pairs()
