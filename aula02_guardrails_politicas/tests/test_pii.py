"""Testes de detecção/anonimização de PII BR (guardrail de saída — Doc 04 §6).

Precursor da proteção de dados aprofundada na Aula 03 (Microsoft Presidio).
Aqui validamos a detecção determinística offline (regex + dígitos verificadores).
"""

from __future__ import annotations

from src.security import detect_pii, is_valid_cnpj, is_valid_cpf, redact_pii


def test_valid_cpf_is_detected():
    matches = detect_pii("O CPF é 529.982.247-25.")
    assert any(m.entity == "CPF" for m in matches)


def test_invalid_cpf_is_ignored():
    # Dígitos verificadores inválidos não devem gerar falso positivo.
    assert detect_pii("O número 111.111.111-11 não é um CPF válido.") == []


def test_cpf_checksum():
    assert is_valid_cpf("529.982.247-25")
    assert not is_valid_cpf("123.456.789-00")


def test_cnpj_checksum():
    assert is_valid_cnpj("11.222.333/0001-81")
    assert not is_valid_cnpj("11.222.333/0001-00")


def test_email_phone_cep_detected():
    text = "Contato: joao@example.com, (11) 91234-5678, CEP 01310-100."
    entities = {m.entity for m in detect_pii(text)}
    assert {"EMAIL_ADDRESS", "PHONE_NUMBER", "CEP"} <= entities


def test_redaction_removes_all_pii():
    text = "CPF 529.982.247-25 e e-mail ana@example.com."
    redacted, matches = redact_pii(text)
    assert "529.982.247-25" not in redacted
    assert "ana@example.com" not in redacted
    assert len(matches) == 2
    assert "[REDACTED_CPF]" in redacted
    assert "[REDACTED_EMAIL_ADDRESS]" in redacted


def test_no_false_positive_on_plain_banking_text():
    text = "Qual o meu saldo na conta corrente e o limite do cartão?"
    assert detect_pii(text) == []


def test_redact_entity_subset():
    text = "CPF 529.982.247-25 e e-mail ana@example.com."
    redacted, _ = redact_pii(text, entities=["EMAIL_ADDRESS"])
    # Apenas o e-mail é redigido; o CPF permanece (subset controlado).
    assert "529.982.247-25" in redacted
    assert "ana@example.com" not in redacted
