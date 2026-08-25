"""Detecção e anonimização de PII BR (Aula 03 — Doc 04, §5-7).

Valida a engine determinística (regex + contexto + checksum) que serve de padrão
em CI e de *fallback* do Presidio, além da anonimização reversível/minimização.
"""

from __future__ import annotations

from app.pii import DataProtectionPipeline
from src.security import ReversibleAnonymizer, detect_pii, is_valid_cnpj, is_valid_cpf
from src.security.schemas import PIIEntity


def test_valid_cpf_is_detected():
    matches = detect_pii("O CPF é 529.982.247-25.", min_score=0.5)
    assert any(m.entity == PIIEntity.BR_CPF for m in matches)


def test_invalid_cpf_is_ignored():
    # Dígitos verificadores inválidos não devem gerar falso positivo (Doc 04, §6).
    assert detect_pii("O número 111.111.111-11 não é um CPF válido.", min_score=0.5) == []


def test_cpf_and_cnpj_checksum():
    assert is_valid_cpf("529.982.247-25")
    assert not is_valid_cpf("123.456.789-00")
    assert is_valid_cnpj("11.222.333/0001-81")
    assert not is_valid_cnpj("11.222.333/0001-00")


def test_email_phone_cep_detected():
    text = "Contato: joao@example.com, (11) 91234-5678, CEP 01310-100."
    entities = {m.entity for m in detect_pii(text, min_score=0.5)}
    assert {PIIEntity.EMAIL_ADDRESS, PIIEntity.PHONE_NUMBER, PIIEntity.BR_CEP} <= entities


def test_account_requires_context():
    # BR_ACCOUNT exige o rótulo "conta" (reduz FP — Doc 04, §6).
    assert any(
        m.entity == PIIEntity.BR_ACCOUNT
        for m in detect_pii("Minha conta corrente nº 45678-9 está bloqueada.", min_score=0.5)
    )


def test_person_detected_by_context():
    matches = detect_pii("O cliente Ana Souza pediu a segunda via.", min_score=0.5)
    assert any(m.entity == PIIEntity.PERSON for m in matches)


def test_no_false_positive_on_benign_text():
    text = "Qual o horário de funcionamento da agência central?"
    assert detect_pii(text, min_score=0.5) == []


def test_anonymize_tokenizes_cpf(anonymizer: ReversibleAnonymizer, pii_text: str):
    result = anonymizer.anonymize(pii_text)
    # O dado bruto não pode sobrar; deve haver um token reversível de CPF.
    assert "529.982.247-25" not in result.text
    assert any(tok.startswith("[BR_CPF_TOKEN_") for tok in result.reversible_tokens)
    assert result.has_pii


def test_anonymize_leaves_no_residual_pii(anonymizer: ReversibleAnonymizer, pii_text: str):
    result = anonymizer.anonymize(pii_text)
    # Re-detectar no texto anonimizado não deve encontrar PII (leak_rate -> 0).
    assert detect_pii(result.text, min_score=0.5) == []


def test_minimization_removes_disallowed_pii(anonymizer: ReversibleAnonymizer, pii_text: str):
    # Fluxo que NÃO permite nenhuma PII -> tudo é removido (Doc 04, §12).
    result = anonymizer.anonymize(pii_text, allowed_pii=[])
    assert result.minimized  # houve minimização
    assert not result.reversible_tokens  # nada foi tokenizado (foi removido)
    assert detect_pii(result.text, min_score=0.5) == []


def test_reversible_roundtrip(anonymizer: ReversibleAnonymizer):
    original = "Meu CPF é 529.982.247-25."
    result = anonymizer.anonymize(original, allowed_pii=[PIIEntity.BR_CPF])
    assert "529.982.247-25" not in result.text
    # Reidratação (egress autorizado) devolve o valor real.
    assert anonymizer.deanonymize(result.text) == original


def test_pipeline_flow_minimization(pipeline: DataProtectionPipeline, pii_text: str):
    # No fluxo "faq" (allowed_pii: []), nenhuma PII deve permanecer.
    result = pipeline.anonymize(pii_text, flow="faq")
    assert detect_pii(result.text, min_score=0.5) == []
    # No fluxo "authenticated", CPF/conta são tokenizados (reversíveis).
    auth = pipeline.anonymize(pii_text, flow="authenticated")
    assert auth.reversible_tokens
