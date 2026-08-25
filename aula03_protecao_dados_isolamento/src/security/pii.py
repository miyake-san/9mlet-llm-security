"""Detecção determinística de PII brasileira — engine OFFLINE (Aula 03).

Implementa a detecção discutida no *Saiba Mais* do Documento 04 (§5-6): o
Analyzer combina **regex** (padrão estrutural), **contexto** (palavras próximas
que elevam a confiança) e **validação de dígito verificador** (*checksum*) para
reduzir *falsos positivos* sem aumentar *falsos negativos*.

Esta é a implementação **determinística e sem dependências pesadas** (sem spaCy):
serve de *engine* padrão em CI e de *fallback* quando o Microsoft Presidio não
está instalado (ver :mod:`src.security.presidio_bridge`). O caminho de PRODUÇÃO
com Presidio + NER é aprofundado no Snippet 1 do Doc 04 e no vídeo 2.

Referência:
    Microsoft (2024b). Presidio — Data Protection and De-identification SDK.
    OWASP Foundation (2025). Top 10 for LLM Applications — LLM06.
"""

from __future__ import annotations

import re

from src.security.schemas import PIIEntity, PIIMatch

# --- Assinaturas regex de PII (formato BR) --------------------------------
# Propositalmente permissivas na captura; a validação de dígito/contexto reduz FP.
_PATTERNS: dict[PIIEntity, re.Pattern[str]] = {
    PIIEntity.BR_CPF: re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"),
    PIIEntity.BR_CNPJ: re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b"),
    PIIEntity.BR_CEP: re.compile(r"\b\d{5}-?\d{3}\b"),
    PIIEntity.CREDIT_CARD: re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    PIIEntity.EMAIL_ADDRESS: re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    PIIEntity.PHONE_NUMBER: re.compile(r"\b(?:\+55\s?)?\(?\d{2}\)?\s?9?\d{4}-?\d{4}\b"),
    # RG e CONTA são ambíguos: exigimos rótulo de contexto (reduz FP — Doc 04, §6).
    PIIEntity.BR_RG: re.compile(r"\bRG[:\s]*\d{1,2}\.?\d{3}\.?\d{3}-?[\dxX]\b", re.IGNORECASE),
    PIIEntity.BR_ACCOUNT: re.compile(
        r"\bconta\s*(?:corrente\s*)?n?[º°]?\.?\s*\d{4,8}-?\d\b", re.IGNORECASE
    ),
    # PERSON: heurística de contexto (o NER robusto vem do Presidio — §5).
    PIIEntity.PERSON: re.compile(
        r"\b(?:cliente|correntista|titular|senhor(?:a)?|sr\.?|sra\.?|chamad[oa]|nome)\s+"
        r"([A-ZÀ-Ú][a-zà-ú]+(?:\s+(?:d[aeo]s?\s+)?[A-ZÀ-Ú][a-zà-ú]+)+)"
    ),
}

# Score-base por entidade (0-1). Entidades com checksum sobem depois de validar.
_BASE_SCORE: dict[PIIEntity, float] = {
    PIIEntity.BR_CPF: 0.6,
    PIIEntity.BR_CNPJ: 0.6,
    PIIEntity.BR_CEP: 0.5,
    PIIEntity.CREDIT_CARD: 0.6,
    PIIEntity.EMAIL_ADDRESS: 0.9,
    PIIEntity.PHONE_NUMBER: 0.7,
    PIIEntity.BR_RG: 0.7,
    PIIEntity.BR_ACCOUNT: 0.7,
    PIIEntity.PERSON: 0.6,
}

# Ordem de detecção: entidades mais específicas primeiro, para o padrão de
# cartão/telefone não "engolir" um CPF/CNPJ/CEP/conta.
_ORDER = [
    PIIEntity.EMAIL_ADDRESS,
    PIIEntity.BR_CNPJ,
    PIIEntity.BR_CPF,
    PIIEntity.BR_RG,
    PIIEntity.BR_ACCOUNT,
    PIIEntity.BR_CEP,
    PIIEntity.CREDIT_CARD,
    PIIEntity.PHONE_NUMBER,
    PIIEntity.PERSON,
]


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def is_valid_cpf(value: str) -> bool:
    """Valida dígitos verificadores de CPF (checksum — Doc 04, §6)."""
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
        check = acc % 11
        check = 0 if check < 2 else 11 - check
        if check != int(cnpj[pos]):
            return False
    return True


def _luhn_ok(value: str) -> bool:
    """Checagem de Luhn (reduz FP em cartões; números aleatórios falham)."""
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


# Palavras de contexto que ELEVAM a confiança (Doc 04, §6: o `context` do Presidio).
_CONTEXT_WORDS: dict[PIIEntity, tuple[str, ...]] = {
    PIIEntity.BR_CPF: ("cpf", "documento", "contribuinte"),
    PIIEntity.BR_CNPJ: ("cnpj", "empresa", "inscrição"),
    PIIEntity.BR_CEP: ("cep", "endereço", "endereco"),
    PIIEntity.CREDIT_CARD: ("cartão", "cartao", "card"),
    PIIEntity.PHONE_NUMBER: ("telefone", "celular", "contato", "fone"),
}


def _context_boost(text: str, entity: PIIEntity, start: int) -> float:
    """Acrescenta confiança se uma palavra de contexto aparece perto (±40 chars)."""
    words = _CONTEXT_WORDS.get(entity)
    if not words:
        return 0.0
    window = text[max(0, start - 40) : start].lower()
    return 0.3 if any(word in window for word in words) else 0.0


def detect_pii(
    text: str,
    entities: list[PIIEntity] | list[str] | None = None,
    min_score: float = 0.0,
) -> list[PIIMatch]:
    """Detecta PII BR no ``text`` (regex + contexto + checksum).

    Args:
        text: texto a inspecionar (prompt do usuário ou resposta do LLM).
        entities: subconjunto a considerar; ``None`` = todas.
        min_score: descarta detecções abaixo deste score (equilíbrio FN/FP — §6).

    Returns:
        Lista de :class:`PIIMatch` sem sobreposição, na ordem de ocorrência.
    """
    wanted = _normalize_entities(entities)
    matches: list[PIIMatch] = []
    claimed: list[tuple[int, int]] = []

    def overlaps(start: int, end: int) -> bool:
        return any(start < c_end and end > c_start for c_start, c_end in claimed)

    for entity in _ORDER:
        if entity not in wanted:
            continue
        for match in _PATTERNS[entity].finditer(text):
            # PERSON e ACCOUNT capturam o nome/conta em grupo 1 quando existir.
            if entity in (PIIEntity.PERSON,) and match.groups():
                start, end = match.start(1), match.end(1)
                captured = match.group(1)
            else:
                start, end = match.start(), match.end()
                captured = match.group(0)
            if overlaps(start, end):
                continue

            score = _BASE_SCORE[entity]
            if entity == PIIEntity.BR_CPF:
                if not is_valid_cpf(captured):
                    continue
                score = 0.95
            elif entity == PIIEntity.BR_CNPJ:
                if not is_valid_cnpj(captured):
                    continue
                score = 0.95
            elif entity == PIIEntity.CREDIT_CARD:
                if not _luhn_ok(captured):
                    continue
                score = 0.9
            score = min(1.0, score + _context_boost(text, entity, start))

            if score < min_score:
                continue
            matches.append(
                PIIMatch(entity=entity, text=captured, start=start, end=end, score=score)
            )
            claimed.append((start, end))

    return sorted(matches, key=lambda pii: pii.start)


def _normalize_entities(
    entities: list[PIIEntity] | list[str] | None,
) -> set[PIIEntity]:
    if not entities:
        return set(_PATTERNS)
    result: set[PIIEntity] = set()
    for item in entities:
        result.add(item if isinstance(item, PIIEntity) else PIIEntity(item))
    return result
