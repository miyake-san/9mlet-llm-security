"""Minimização de dados pessoais no prompt (Aula 05).

Implementa o princípio da **necessidade** da LGPD (art. 6, V) discutido no
Documento 04 (§2): *"o dado mais seguro é aquele que não existe"*. Antes de
enviar o prompt ao modelo, removemos/mascaramos a PII — a lei **codifica o que a
boa engenharia já recomendava** (a minimização da Aula 03 vira obrigação legal).

Este módulo é **determinístico e offline** (regex + contexto + validação de
dígito verificador), servindo de engine padrão em CI e de *fallback* quando o
Microsoft Presidio não está disponível (ver :class:`PresidioHttpMinimizer`).

Referência:
    BRASIL (2018). LGPD — art. 6, V (necessidade). · Doc 04, §2.
    Microsoft (2024). Presidio — Data Protection and De-identification SDK.
    Sweeney, L. (2002). k-Anonymity.
"""

from __future__ import annotations

import logging
import re
from typing import Protocol

from src.security.schemas import MinimizationResult, PIIEntity, PIIMatch

logger = logging.getLogger(__name__)

# --- Assinaturas regex de PII (formato BR). Permissivas na captura; validação
#     de dígito/contexto reduz falso positivo (Doc 04, §2 — mesmo raciocínio da
#     Aula 03).
_PATTERNS: dict[PIIEntity, re.Pattern[str]] = {
    PIIEntity.BR_CPF: re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"),
    PIIEntity.BR_CNPJ: re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b"),
    PIIEntity.BR_CEP: re.compile(r"\b\d{5}-?\d{3}\b"),
    PIIEntity.CREDIT_CARD: re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    PIIEntity.EMAIL_ADDRESS: re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    PIIEntity.PHONE_NUMBER: re.compile(r"\b(?:\+55\s?)?\(?\d{2}\)?\s?9?\d{4}-?\d{4}\b"),
    PIIEntity.BR_RG: re.compile(r"\bRG[:\s]*\d{1,2}\.?\d{3}\.?\d{3}-?[\dxX]\b", re.IGNORECASE),
    PIIEntity.BR_ACCOUNT: re.compile(
        r"\bconta\s*(?:corrente\s*)?n?[º°]?\.?\s*\d{4,8}-?\d\b", re.IGNORECASE
    ),
    PIIEntity.PERSON: re.compile(
        r"\b(?:cliente|correntista|titular|senhor(?:a)?|sr\.?|sra\.?|chamad[oa]|nome)\s+"
        r"([A-ZÀ-Ú][a-zà-ú]+(?:\s+(?:d[aeo]s?\s+)?[A-ZÀ-Ú][a-zà-ú]+)+)"
    ),
}

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

# Entidades mais específicas primeiro (cartão/telefone não "engolem" CPF/CEP).
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
    """Valida dígitos verificadores de CPF (checksum reduz falso positivo)."""
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
    """Checagem de Luhn (números de cartão aleatórios falham -> menos FP)."""
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


def detect_pii(text: str, min_score: float = 0.5) -> list[PIIMatch]:
    """Detecta PII no texto (regex + validação + contexto). Doc 04, §2."""
    matches: list[PIIMatch] = []
    taken: list[tuple[int, int]] = []

    def _overlaps(start: int, end: int) -> bool:
        return any(start < e and s < end for s, e in taken)

    for entity in _ORDER:
        pattern = _PATTERNS[entity]
        for m in pattern.finditer(text):
            start, end = m.start(), m.end()
            if _overlaps(start, end):
                continue
            raw = m.group(0)
            score = _BASE_SCORE[entity]
            # Validação de checksum eleva a confiança (ou descarta o match).
            if entity is PIIEntity.BR_CPF:
                if not is_valid_cpf(raw):
                    continue
                score = 0.95
            elif entity is PIIEntity.BR_CNPJ:
                if not is_valid_cnpj(raw):
                    continue
                score = 0.95
            elif entity is PIIEntity.CREDIT_CARD:
                if not _luhn_ok(raw):
                    continue
                score = 0.9
            if entity is PIIEntity.PERSON and m.groups():
                # Captura só o nome, não a palavra-gatilho ("cliente Fulano").
                start = m.start(1)
                raw = m.group(1)
                end = start + len(raw)
            if score < min_score:
                continue
            matches.append(PIIMatch(entity=entity, text=raw, start=start, end=end, score=score))
            taken.append((start, end))

    matches.sort(key=lambda mt: mt.start)
    return matches


def _replacement(match: PIIMatch, operators: dict[str, str] | None) -> str:
    """Escolhe o placeholder de minimização por entidade (redact | mask | hash)."""
    op = (operators or {}).get(match.entity.value, "redact")
    if op == "mask":
        return f"[{match.entity.value}]"
    if op == "hash":
        import hashlib

        digest = hashlib.sha256(match.text.encode("utf-8")).hexdigest()[:8]
        return f"[{match.entity.value}_{digest}]"
    return f"[{match.entity.value}]"


class Minimizer(Protocol):
    """Contrato de um minimizador de PII (offline determinístico ou Presidio)."""

    name: str

    def minimize(self, text: str) -> MinimizationResult:  # pragma: no cover
        ...


class DeterministicMinimizer:
    """Minimizador OFFLINE (regex + checksum). Engine padrão em CI/testes."""

    name = "deterministic-br"

    def __init__(self, min_score: float = 0.5, operators: dict[str, str] | None = None) -> None:
        self.min_score = min_score
        self.operators = operators or {}

    def minimize(self, text: str) -> MinimizationResult:
        """Remove/mascarará PII do texto, retornando o texto minimizado + matches."""
        matches = detect_pii(text, min_score=self.min_score)
        # Substitui de trás para frente para não invalidar offsets.
        out = text
        for match in sorted(matches, key=lambda m: m.start, reverse=True):
            out = out[: match.start] + _replacement(match, self.operators) + out[match.end :]
        return MinimizationResult(text=out, matches=matches)


class PresidioHttpMinimizer:
    """Minimizador via Microsoft Presidio (analyzer + anonymizer) por HTTP.

    Caminho de PRODUÇÃO (Doc 04, §2 / Snippet 1). Requer os containers oficiais
    ``mcr.microsoft.com/presidio-analyzer`` e ``presidio-anonymizer`` no ar.
    Se indisponível, caia no :class:`DeterministicMinimizer` (feito em ``main``).
    """

    name = "presidio-http"

    def __init__(
        self,
        analyzer_url: str,
        anonymizer_url: str,
        timeout: float = 10.0,
        fallback: Minimizer | None = None,
    ) -> None:
        self.analyzer_url = analyzer_url.rstrip("/")
        self.anonymizer_url = anonymizer_url.rstrip("/")
        self._timeout = timeout
        self._fallback = fallback

    def minimize(self, text: str) -> MinimizationResult:
        import httpx  # local: só é necessário no caminho HTTP

        try:
            analyze_resp = httpx.post(
                f"{self.analyzer_url}/analyze",
                json={"text": text, "language": "pt"},
                timeout=self._timeout,
            )
            analyze_resp.raise_for_status()
            results = analyze_resp.json()
            anon_resp = httpx.post(
                f"{self.anonymizer_url}/anonymize",
                json={
                    "text": text,
                    "analyzer_results": results,
                    "anonymizers": {"DEFAULT": {"type": "replace", "new_value": "[PII]"}},
                },
                timeout=self._timeout,
            )
            anon_resp.raise_for_status()
            anonymized = anon_resp.json().get("text", text)
            matches = [
                PIIMatch(
                    entity=_coerce_entity(r.get("entity_type", "PERSON")),
                    text=text[r["start"] : r["end"]],
                    start=int(r["start"]),
                    end=int(r["end"]),
                    score=float(r.get("score", 0.85)),
                )
                for r in results
            ]
            return MinimizationResult(text=anonymized, matches=matches)
        except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
            if self._fallback is None:
                raise
            logger.warning("Presidio falhou (%s) — usando minimizador determinístico.", exc)
            return self._fallback.minimize(text)


def _coerce_entity(entity_type: str) -> PIIEntity:
    """Mapeia o tipo do Presidio para o nosso enum (fallback PERSON)."""
    try:
        return PIIEntity(entity_type)
    except ValueError:
        return PIIEntity.PERSON
