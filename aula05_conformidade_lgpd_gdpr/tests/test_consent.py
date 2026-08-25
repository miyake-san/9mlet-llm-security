"""Testes de consentimento granular e versionado (Aula 05).

Valida o Hands On (Snippet 1) e o §3 do Documento 04: consentimento específico
por finalidade, versionamento (trilha auditável) e revogação instantânea — além
do *enforcement* de base legal na rag-api (LGPD art. 7).
"""

from __future__ import annotations

from src.security.consent import InMemoryConsentStore
from src.security.schemas import ConsentRecord


def test_upsert_incrementa_versao():
    store = InMemoryConsentStore()
    store.upsert(ConsentRecord(subject_id="cli-1", purposes={"faq_produtos": True}))
    v2 = store.upsert(ConsentRecord(subject_id="cli-1", purposes={"treino_modelo": True}))
    assert v2.version == 2
    assert len(store.history("cli-1")) == 2


def test_revogacao_desautoriza_finalidade():
    store = InMemoryConsentStore()
    store.upsert(ConsentRecord(subject_id="cli-2", purposes={"treino_modelo": True}))
    assert store.get("cli-2").allows("treino_modelo") is True
    revoked = store.revoke("cli-2")
    assert revoked.revoked is True
    assert store.get("cli-2").allows("treino_modelo") is False


def test_allows_falso_sem_consentimento():
    rec = ConsentRecord(subject_id="cli-3", purposes={"faq_produtos": True})
    assert rec.allows("treino_modelo") is False
    assert rec.allows("faq_produtos") is True


def test_chat_bloqueia_sem_consentimento_para_treino(client):
    """Finalidade que exige opt-in (treino_modelo) sem consentimento -> bloqueio."""
    resp = client.post(
        "/chat",
        json={
            "message": "Use minha conversa para treinar o modelo.",
            "subject_id": "cli-404",
            "purpose": "treino_modelo",
            "top_k": 0,
        },
    )
    body = resp.json()
    assert body["blocked"] is True
    assert body["block_reason"] == "missing_consent"


def test_chat_permite_apos_consentimento(client):
    """Com consentimento vigente para a finalidade, o tratamento prossegue."""
    client.post(
        "/consent",
        json={"subject_id": "cli-77", "purposes": {"treino_modelo": True}},
    )
    resp = client.post(
        "/chat",
        json={
            "message": "Pode usar esta conversa conforme consenti.",
            "subject_id": "cli-77",
            "purpose": "treino_modelo",
            "top_k": 0,
        },
    )
    body = resp.json()
    assert body["blocked"] is False
    assert body["consent_ok"] is True


def test_finalidade_sem_consentimento_nao_exige(client):
    """faq_produtos usa legítimo interesse — não exige consentimento (art. 7, IX)."""
    resp = client.post(
        "/chat",
        json={
            "message": "Qual a taxa do CDB?",
            "subject_id": "anon",
            "purpose": "faq_produtos",
            "top_k": 0,
        },
    )
    assert resp.json()["blocked"] is False
