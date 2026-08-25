"""Fixtures compartilhadas dos testes da Aula 03.

Todos os testes rodam OFFLINE e de forma DETERMINÍSTICA:
- a detecção usa o :class:`DeterministicAnalyzer` (regex + checksum, sem spaCy);
- o cofre usa :class:`InMemoryTokenVault` (nada persiste);
- o isolamento de ferramentas usa um segredo fixo de capability token.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.pii import DataProtectionPipeline
from src.security import (
    AuditTrail,
    DeterministicAnalyzer,
    InMemoryTokenVault,
    ReversibleAnonymizer,
    ToolAuthorizer,
    ToolCatalog,
)

_TOOL_POLICY = Path(__file__).resolve().parent.parent / "app" / "policies" / "tool_policy.yaml"
CAP_SECRET = "test-capability-secret"


@pytest.fixture
def anonymizer() -> ReversibleAnonymizer:
    """Anonimizador offline (determinístico) com cofre em memória."""
    return ReversibleAnonymizer(
        analyzer=DeterministicAnalyzer("pt"),
        vault=InMemoryTokenVault(secret="test-secret"),
        min_score=0.5,
    )


@pytest.fixture
def pipeline(anonymizer: ReversibleAnonymizer) -> DataProtectionPipeline:
    """Pipeline de proteção de dados (usa os perfis de fluxo do thresholds.yaml)."""
    return DataProtectionPipeline(anonymizer=anonymizer)


@pytest.fixture
def catalog() -> ToolCatalog:
    """Catálogo de ferramentas MCP (somente leitura) — Doc 04, §10."""
    return ToolCatalog.from_yaml(_TOOL_POLICY)


@pytest.fixture
def authorizer(catalog: ToolCatalog) -> ToolAuthorizer:
    """Autorizador de ferramentas com trilha de auditoria em memória."""
    return ToolAuthorizer(catalog=catalog, secret=CAP_SECRET, audit=AuditTrail())


@pytest.fixture
def pii_text() -> str:
    """Texto com múltiplas PII BR sintéticas (CPF com checksum válido)."""
    return (
        "Cliente Ana Souza, CPF 529.982.247-25, e-mail ana@example.com, "
        "conta corrente nº 45678-9."
    )
