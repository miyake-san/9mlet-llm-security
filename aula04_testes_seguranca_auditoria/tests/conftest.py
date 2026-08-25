"""Fixtures compartilhadas: cliente da target-api (backend stub) e datasets.

Backend determinístico offline por padrão; auditoria desligada (sem rede).
"""

from __future__ import annotations

import os

os.environ.setdefault("LLM_BACKEND", "stub")
os.environ.setdefault("AUDIT_ENABLED", "false")
os.environ.setdefault("GUARDRAIL_ENABLED", "true")
os.environ.setdefault("GUARDRAIL_NORMALIZE", "false")
os.environ.setdefault("GUARDRAIL_CONVERSATION", "false")

from collections.abc import Callable  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.config import Settings, get_settings  # noqa: E402
from app.llm import StubBackend  # noqa: E402
from app.main import app, get_llm  # noqa: E402
from src.security.redteam import load_attacks, load_benign, load_crescendo  # noqa: E402


class ClientTarget:
    """Adapta um TestClient da target-api ao contrato ``Target`` do harness."""

    def __init__(self, client: TestClient) -> None:
        self._c = client
        self.name = "testclient://target-api/chat"

    def send(self, prompt: str) -> str:
        return str(self._c.post("/chat", json={"message": prompt}).json().get("answer", ""))

    def send_conversation(self, turns: list[str]) -> list[str]:
        history: list[dict[str, str]] = []
        out: list[str] = []
        for turn in turns:
            answer = str(
                self._c.post("/chat", json={"message": turn, "history": history})
                .json()
                .get("answer", "")
            )
            history += [{"role": "user", "content": turn}, {"role": "assistant", "content": answer}]
            out.append(answer)
        return out


@pytest.fixture
def client():
    """TestClient com backend de LLM forçado para o StubBackend (offline)."""
    app.dependency_overrides[get_llm] = lambda: StubBackend()
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def client_factory() -> Callable[..., TestClient]:
    """Fábrica de clientes com flags de guardrail customizadas (mitigações)."""
    created: list[TestClient] = []

    def _make(**overrides) -> TestClient:
        base = {
            "llm_backend": "stub",
            "audit_enabled": False,
            "guardrail_enabled": True,
            "guardrail_normalize": False,
            "guardrail_conversation": False,
        }
        base.update(overrides)
        settings = Settings(**base)
        app.dependency_overrides[get_settings] = lambda: settings
        app.dependency_overrides[get_llm] = lambda: StubBackend()
        c = TestClient(app)
        created.append(c)
        return c

    yield _make
    for c in created:
        c.close()
    app.dependency_overrides.clear()


@pytest.fixture(scope="session")
def attacks():
    return load_attacks()


@pytest.fixture(scope="session")
def benign():
    return load_benign()


@pytest.fixture(scope="session")
def crescendo():
    return load_crescendo()
