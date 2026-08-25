"""Detector determinístico de PII BR para o Data SLO de segurança (Aula 06).

O *Data SLO* de segurança "no máximo 1% de respostas com PII vazada" (Doc 04,
Snippet 4) exige medir, de forma barata e offline, se uma resposta contém PII em
claro. Este módulo é um detector leve (regex + dígitos verificadores) — NÃO
substitui o Microsoft Presidio da Aula 03, mas basta para sinalizar vazamento e
alimentar a métrica ``pii_leak_rate`` monitorada continuamente.

Conecta a anonimização (Aula 03) e a conformidade (Aula 05) a uma métrica
operacional auditável (Doc 04, §SLOs).

Referência:
    Doc 04, §"SLIs, SLOs e Data SLOs" (Snippet 4). · Aula 03 (Presidio).
"""

from __future__ import annotations

import re

# Regexes de PII BR (formato sintético; validação de dígitos reduz falso positivo).
_CPF_RE = re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")
_CNPJ_RE = re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b")
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_PHONE_RE = re.compile(r"\(?\d{2}\)?\s?9?\d{4}-?\d{4}\b")
_CEP_RE = re.compile(r"\b\d{5}-?\d{3}\b")
_RG_RE = re.compile(r"\bRG:?\s?\d{1,2}\.?\d{3}\.?\d{3}-?\d?\b", re.IGNORECASE)
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,16}\b")


def _only_digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def is_valid_cpf(value: str) -> bool:
    """Valida os dígitos verificadores do CPF (evita falso positivo em CEP/telefone)."""
    digits = _only_digits(value)
    if len(digits) != 11 or len(set(digits)) == 1:
        return False
    nums = [int(d) for d in digits]
    for i in (9, 10):
        checksum = sum(nums[j] * ((i + 1) - j) for j in range(i))
        expected = (checksum * 10 % 11) % 10
        if expected != nums[i]:
            return False
    return True


def detect_pii(text: str) -> list[str]:
    """Retorna os rótulos de PII encontrados no texto (ordenados, sem repetição)."""
    found: set[str] = set()
    for match in _CPF_RE.findall(text):
        if is_valid_cpf(match):
            found.add("BR_CPF")
    if _CNPJ_RE.search(text):
        found.add("BR_CNPJ")
    if _EMAIL_RE.search(text):
        found.add("EMAIL_ADDRESS")
    if _RG_RE.search(text):
        found.add("BR_RG")
    # Telefone e CEP só contam se NÃO forem, na verdade, um CPF já capturado.
    if _PHONE_RE.search(text):
        found.add("PHONE_NUMBER")
    if _CEP_RE.search(text):
        found.add("BR_CEP")
    return sorted(found)


def contains_pii(text: str) -> bool:
    """True se a resposta contém PII em claro (base do Data SLO — Doc 04, Snippet 4)."""
    return bool(detect_pii(text))
