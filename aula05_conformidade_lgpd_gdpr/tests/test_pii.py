"""Testes de minimização de PII BR (Aula 05).

Valida o princípio da necessidade (LGPD art. 6, V; Doc 04, §2): o detector BR
determinístico identifica CPF/CNPJ/e-mail/telefone e o minimizador os remove do
prompt, sem gerar falso positivo em texto benigno.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from src.security.minimization import (
    DeterministicMinimizer,
    detect_pii,
    is_valid_cnpj,
    is_valid_cpf,
)
from src.security.schemas import PIIEntity

_DATA = Path(__file__).resolve().parents[1] / "data"
_CPF_RE = re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")


def test_validacao_cpf():
    assert is_valid_cpf("529.982.247-25") is True
    assert is_valid_cpf("111.111.111-11") is False
    assert is_valid_cpf("123") is False


def test_validacao_cnpj():
    assert is_valid_cnpj("11.222.333/0001-81") is True
    assert is_valid_cnpj("00.000.000/0000-00") is False


def test_detecta_cpf_valido_no_texto():
    matches = detect_pii("O CPF é 529.982.247-25, confirme.")
    assert any(m.entity is PIIEntity.BR_CPF for m in matches)


def test_minimizador_remove_pii():
    minimizer = DeterministicMinimizer()
    texto = "Cliente com CPF 529.982.247-25 e e-mail joao@exemplo.com."
    result = minimizer.minimize(texto)
    assert "529.982.247-25" not in result.text
    assert "joao@exemplo.com" not in result.text
    entities = {m.entity for m in result.matches}
    assert PIIEntity.BR_CPF in entities
    assert PIIEntity.EMAIL_ADDRESS in entities


def test_benigno_sem_falso_positivo():
    minimizer = DeterministicMinimizer()
    result = minimizer.minimize("Qual é o horário de funcionamento da agência central?")
    assert result.removed == 0
    assert result.text == "Qual é o horário de funcionamento da agência central?"


def test_recall_no_dataset_de_pii():
    """No corpus sintético, os CPFs rotulados devem ser majoritariamente detectados."""
    path = _DATA / "pii_samples" / "pii_samples.jsonl"
    if not path.exists():  # dataset é gerado por `task seed-data`
        return
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    cpf_rows = [r for r in rows if "BR_CPF" in r.get("entities", [])]
    detected = sum(
        1 for r in cpf_rows if any(m.entity is PIIEntity.BR_CPF for m in detect_pii(r["text"]))
    )
    assert cpf_rows, "esperado ao menos um texto rotulado com BR_CPF"
    assert detected / len(cpf_rows) >= 0.8


def test_chat_minimiza_pii_no_prompt(client):
    """A rag-api reporta as entidades minimizadas no prompt (art. 6, V)."""
    resp = client.post(
        "/chat",
        json={
            "message": "Meu CPF é 529.982.247-25, qual meu saldo?",
            "subject_id": "cli-9",
            "purpose": "faq_produtos",
            "top_k": 0,
        },
    )
    body = resp.json()
    assert "BR_CPF" in body["minimized_entities"]
    assert not _CPF_RE.search(body["answer"])
