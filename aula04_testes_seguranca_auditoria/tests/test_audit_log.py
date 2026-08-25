"""Testes da trilha de auditoria imutável (Aula 04, vídeo 3)."""

from __future__ import annotations

from fastapi.testclient import TestClient

import app.audit_log as audit_mod
from app.audit_log import app as audit_app
from app.config import Settings
from src.security.hash_chain import HashChain
from src.security.merkle import merkle_root


def test_cadeia_intacta_verifica_ok():
    chain = HashChain()
    chain.append({"action": "chat", "decision": "allow", "risk": 0.05})
    chain.append({"action": "chat", "decision": "block", "risk": 0.9})
    result = chain.verify()
    assert result.intact is True
    assert result.count == 2
    assert result.broken_at is None
    assert len(result.merkle_root) == 64


def test_adulteracao_de_registro_e_detectada():
    """Alterar um registro antigo quebra a cadeia (Doc 04, seção 11)."""
    chain = HashChain()
    for i in range(4):
        chain.append({"seq": i, "decision": "block"})
    assert chain.verify().intact is True
    # Encobrir um incidente: mudar 'block' -> 'allow' no elo 1.
    chain.entries[1].record["decision"] = "allow"
    result = chain.verify()
    assert result.intact is False
    assert result.broken_at == 1


def test_remocao_de_elo_quebra_linkagem():
    chain = HashChain()
    for i in range(3):
        chain.append({"seq": i})
    del chain.entries[1]  # remove um elo do meio
    result = chain.verify()
    assert result.intact is False


def test_merkle_root_deterministico_e_sensivel_ao_conteudo():
    a = merkle_root(["e1", "e2", "e3"])
    b = merkle_root(["e1", "e2", "e3"])
    c = merkle_root(["e1", "e2", "e4"])
    assert a == b
    assert a != c
    assert len(a) == 64


def test_audit_api_registra_e_verifica(monkeypatch, tmp_path):
    """A API do audit-log encadeia eventos e reporta integridade."""
    monkeypatch.setattr(audit_mod, "_index_opensearch", lambda *a, **k: None)
    settings = Settings(audit_chain_path=str(tmp_path / "chain.jsonl"), audit_enabled=True)
    monkeypatch.setattr(audit_mod, "get_settings", lambda: settings)

    with TestClient(audit_app) as c:
        r1 = c.post("/events", json={"action": "chat", "decision": "allow", "risk_score": 0.05})
        assert r1.status_code == 200
        body = r1.json()
        assert body["seq"] == 0 and "hash" in body and "merkle_root" in body

        c.post("/events", json={"action": "chat", "decision": "block", "risk_score": 0.9})
        events = c.get("/events").json()
        assert events["count"] == 2

        verify = c.get("/verify").json()
        assert verify["intact"] is True
        assert verify["count"] == 2
