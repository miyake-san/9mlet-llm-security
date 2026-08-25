"""Suíte de REGRESSÃO de segurança (Aula 03).

Garante que vazamentos de dados e abusos de ferramenta já corrigidos **não
voltem a passar**. Cada teste fixa um cenário concreto do Documento 04.
"""

from __future__ import annotations

from src.security import (
    ReversibleAnonymizer,
    ToolAuthorizer,
    ToolCatalog,
    detect_pii,
    issue_capability,
)
from src.security.schemas import PIIEntity
from tests.conftest import CAP_SECRET


# --- Regressões de PROTEÇÃO DE DADOS (Doc 04, §6-8) ------------------------
def test_regression_cpf_never_leaks_after_anonymization(anonymizer: ReversibleAnonymizer):
    text = "Confirmo que o CPF do titular é 529.982.247-25 para o pagamento."
    result = anonymizer.anonymize(text, allowed_pii=[PIIEntity.BR_CPF])
    assert "529.982.247-25" not in result.text
    assert detect_pii(result.text, min_score=0.5) == []


def test_regression_multi_entity_no_residual(anonymizer: ReversibleAnonymizer, pii_text: str):
    result = anonymizer.anonymize(pii_text)
    assert detect_pii(result.text, min_score=0.5) == []


def test_regression_embedding_doc_pii_is_stripped(anonymizer: ReversibleAnonymizer):
    # Doc 04, §8: anonimizar ANTES de vetorizar. O texto a indexar não pode ter PII.
    doc = "Protocolo: cliente Ana Souza, CPF 529.982.247-25, e-mail ana@example.com."
    to_index = anonymizer.anonymize(doc, allowed_pii=[]).text
    assert detect_pii(to_index, min_score=0.5) == []


# --- Regressões de ISOLAMENTO DE FERRAMENTAS (Doc 04, §9-10) ----------------
def test_regression_no_transfer_capability_in_catalog(catalog: ToolCatalog):
    # A capacidade de transferir NÃO existe (defesa estrutural — Doc 04, §9).
    assert "transferir" not in catalog.names()


def test_regression_indirect_injection_cannot_transfer(authorizer: ToolAuthorizer):
    # Mesmo um token PERFEITAMENTE assinado não invoca capacidade inexistente.
    forged = issue_capability(
        tool="transferir", subject="atacante", scopes={"transfer:write"}, secret=CAP_SECRET
    )
    result = authorizer.authorize(forged, "transferir", "transfer:write")
    assert not result.allowed
    assert result.reason == "unknown_tool"


def test_regression_read_token_cannot_escalate_to_write(authorizer: ToolAuthorizer):
    # Um token de leitura JAMAIS vira escrita (scope escalation).
    token = issue_capability(
        tool="consultar_saldo", subject="tester", scopes={"saldo:read"}, secret=CAP_SECRET
    )
    result = authorizer.authorize(token, "consultar_saldo", "saldo:write")
    assert not result.allowed
    assert result.reason == "scope_not_supported"
