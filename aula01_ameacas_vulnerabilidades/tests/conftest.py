"""Fixtures compartilhadas: cliente da API vulnerável (backend stub) e datasets."""

from __future__ import annotations

import os

# Backend determinístico offline por padrão nos testes.
os.environ.setdefault("LLM_BACKEND", "stub")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.llm import StubBackend  # noqa: E402
from app.main import app, get_llm  # noqa: E402
from src.security.redteam import load_attacks, load_benign  # noqa: E402


@pytest.fixture
def client():
    """TestClient com o backend de LLM forçado para o StubBackend (offline)."""
    app.dependency_overrides[get_llm] = lambda: StubBackend()
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture(scope="session")
def attacks():
    return load_attacks()


@pytest.fixture(scope="session")
def benign():
    return load_benign()
