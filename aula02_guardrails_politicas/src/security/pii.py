"""Detecção e redação de PII brasileira — guardrail de SAÍDA (Aula 02).

Implementa a validação de saída (LLM02 — Insecure Output Handling / LLM06 —
Sensitive Information Disclosure) discutida na seção 6 do Documento 04 e no
Snippet 2 (Guardrails AI ``DetectPII``). Aqui a detecção é feita de forma
DETERMINÍSTICA e OFFLINE (regex + dígitos verificadores), sem depender de
modelos pesados — o caminho de produção com Microsoft Presidio é aprofundado
na Aula 03.

Contexto BR: além de EMAIL/PHONE, reconhece CPF, CNPJ, RG, CEP e cartão.

Referência:
    Guardrails AI (2024). Documentation — DetectPII / Rail Spec.
    OWASP Foundation (2025). Top 10 for LLM Applications — LLM02, LLM06.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# --- Assinaturas regex de PII (formato BR) --------------------------------
# São propositalmente permissivas na captura; a validação de dígito reduz FP.
_PATTERNS: dict[str, re.Pattern[str]] = {
    "CPF": re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"),
    "CNPJ": re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b"),
    "CEP": re.compile(r"\b\d{5}-?\d{3}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    "EMAIL_ADDRESS": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "PHONE_NUMBER": re.compile(r"\b(?:\+55\s?)?\(?\d{2}\)?\s?9?\d{4}-?\d{4}\b"),
    # RG é ambíguo (formatos variam por estado); exigimos rótulo de contexto.
    "RG": re.compile(r"\bRG[:\s]*\d{1,2}\.?\d{3}\.?\d{3}-?[\dxX]\b", re.IGNORECASE),
}

# Ordem de detecção: entidades mais específicas primeiro para evitar que o
# padrão de cartão/telefone "engula" um CPF/CNPJ/CEP.
_ORDER = ["EMAIL_ADDRESS", "CNPJ", "CPF", "RG", "CEP", "CREDIT_CARD", "PHONE_NUMBER"]


@dataclass(frozen=True)
class PIIMatch:
    """Ocorrência de PII detectada no texto."""

    entity: str
    text: str
    start: int
    end: int


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def is_valid_cpf(value: str) -> bool:
    """Valida dígitos verificadores de CPF (evita falsos positivos)."""
    cpf = _digits(value)
    if len(cpf) != 11 or cpf == cpf[0] * 11:
        return False
    for length in (9, 10):
        acc = sum(int(cpf[i]) * ((length + 1) - i) for i in range(length))
        check = (acc * 10) % 11 % 10
        if check != int(cpf[length]):
            return False
    return True


def is_valid_cnpj(value: str) -> bool:
    """Valida dígitos verificadores de CNPJ."""
    cnpj = _digits(value)
    if len(cnpj) != 14 or cnpj == cnpj[0] * 14:
        return False
    weights_1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    weights_2 = [6, *weights_1]
    for weights, pos in ((weights_1, 12), (weights_2, 13)):
        acc = sum(int(cnpj[i]) * weights[i] for i in range(pos))
        check = (acc % 11)
        check = 0 if check < 2 else 11 - check
        if check != int(cnpj[pos]):
            return False
    return True


def _luhn_ok(value: str) -> bool:
    """Checagem de Luhn para reduzir FP em cartões (números aleatórios falham)."""
    digits = [int(c) for c in _digits(value)]
    if not 13 <= len(digits) <= 16:
        return False
    checksum = 0
    for idx, digit in enumerate(reversed(digits)):
        if idx % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def detect_pii(text: str, entities: list[str] | None = None) -> list[PIIMatch]:
    """Detecta PII BR no ``text``.

    Args:
        text: texto a inspecionar (geralmente a resposta do LLM).
        entities: subconjunto de entidades a considerar; ``None`` = todas.

    Returns:
        Lista de :class:`PIIMatch` sem sobreposição, na ordem de ocorrência.
    """
    wanted = set(entities) if entities else set(_PATTERNS)
    matches: list[PIIMatch] = []
    claimed: list[tuple[int, int]] = []

    def overlaps(start: int, end: int) -> bool:
        return any(start < c_end and end > c_start for c_start, c_end in claimed)

    for entity in _ORDER:
        if entity not in wanted:
            continue
        for match in _PATTERNS[entity].finditer(text):
            start, end = match.start(), match.end()
            if overlaps(start, end):
                continue
            captured = match.group(0)
            if entity == "CPF" and not is_valid_cpf(captured):
                continue
            if entity == "CNPJ" and not is_valid_cnpj(captured):
                continue
            if entity == "CREDIT_CARD" and not _luhn_ok(captured):
                continue
            matches.append(PIIMatch(entity=entity, text=captured, start=start, end=end))
            claimed.append((start, end))

    return sorted(matches, key=lambda pii: pii.start)


def redact_pii(
    text: str,
    entities: list[str] | None = None,
    token: str = "[REDACTED_{entity}]",
) -> tuple[str, list[PIIMatch]]:
    """Substitui PII detectada por um token de redação.

    Returns:
        ``(texto_redigido, ocorrências)``. Se nada for detectado, o texto
        original é devolvido inalterado.
    """
    found = detect_pii(text, entities)
    if not found:
        return text, []
    redacted = text
    for match in sorted(found, key=lambda pii: pii.start, reverse=True):
        replacement = token.format(entity=match.entity)
        redacted = redacted[: match.start] + replacement + redacted[match.end :]
    return redacted, found
