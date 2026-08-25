"""Testes do direito ao esquecimento — purga seletiva (Aula 05).

Valida o §10 do Documento 04 (Snippet 3): a purga remove TODOS os vetores do
titular solicitante e **apenas** os dele, preservando documentos institucionais
e de outros titulares. O limite do fine-tuning é sinalizado no resultado.
"""

from __future__ import annotations

from src.security.vector_store import InMemoryVectorStore, VectorRecord


def _seed(store: InMemoryVectorStore) -> None:
    store.upsert(VectorRecord(doc_id="inst-1", subject_id="banco", text="Horários das agências."))
    store.upsert(VectorRecord(doc_id="a-1", subject_id="cli-A", text="Atendimento do cliente A."))
    store.upsert(VectorRecord(doc_id="a-2", subject_id="cli-A", text="Segunda via do cliente A."))
    store.upsert(VectorRecord(doc_id="b-1", subject_id="cli-B", text="Atendimento do cliente B."))


def test_purga_remove_apenas_o_titular():
    store = InMemoryVectorStore()
    _seed(store)
    assert store.count() == 4
    result = store.purge_subject("cli-A")
    assert result.deleted_count == 2
    assert set(result.doc_ids) == {"a-1", "a-2"}
    assert store.count() == 2
    # Institucional e outro titular permanecem.
    assert store.list_by_subject("banco")
    assert store.list_by_subject("cli-B")
    assert store.list_by_subject("cli-A") == []


def test_purga_sinaliza_limite_de_unlearning():
    store = InMemoryVectorStore()
    _seed(store)
    result = store.purge_subject("cli-A")
    assert "fine-tuning" in result.model_unlearning_note.lower()


def test_purga_via_api_esquecimento(client):
    """POST /dsr/erasure remove os vetores do titular do índice do Aurora Assist."""
    client.post(
        "/rag/index",
        json={"doc_id": "d1", "subject_id": "cli-Z", "text": "Protocolo do cliente Z."},
    )
    client.post(
        "/rag/index",
        json={"doc_id": "d2", "subject_id": "cli-Z", "text": "Segunda via do cliente Z."},
    )
    client.post(
        "/rag/index", json={"doc_id": "inst", "subject_id": "banco", "text": "Tarifas de serviços."}
    )
    erasure = client.post("/dsr/erasure", json={"subject_id": "cli-Z"}).json()
    assert erasure["deleted_count"] == 2
    # O índice ainda tem o documento institucional.
    access = client.post("/dsr/access", json={"subject_id": "cli-Z"}).json()
    assert access["indexed_documents"] == []


def test_acesso_do_titular_retorna_documentos(client):
    """Direito de acesso (art. 18, I-II): lista os documentos indexados do titular."""
    client.post(
        "/rag/index",
        json={"doc_id": "x1", "subject_id": "cli-ACC", "text": "Atendimento do titular."},
    )
    access = client.post("/dsr/access", json={"subject_id": "cli-ACC"}).json()
    assert access["subject_id"] == "cli-ACC"
    assert len(access["indexed_documents"]) == 1
