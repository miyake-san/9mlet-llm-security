"""Ponte para o Microsoft Presidio com *fallback* determinístico (Aula 03).

Espelha a arquitetura do Analyzer do Documento 04 (§5): detecção de PII por
**regex + contexto + NER + checksum**, com *recognizers* brasileiros customizados
(Snippet 1: CPF/CNPJ/RG/CEP/CONTA). Segue a filosofia *offline-first* do repo —
três modos selecionáveis por ``PRESIDIO_MODE``:

- ``deterministic`` (padrão/CI): usa :mod:`src.security.pii` (sem spaCy/rede).
- ``python``: usa a biblioteca ``presidio-analyzer`` local (grupo ``presidio``).
- ``http``: chama o serviço ``presidio-analyzer`` do docker-compose.

Qualquer falha nos modos pesados **degrada com segurança** para o determinístico
(*fail-safe*): é melhor detectar com heurística do que não detectar nada.

Referência:
    Microsoft (2024b). Presidio — Analyzer + custom recognizers.
    Doc 04, §5-6 e Snippet 1 (recognizer de CPF com contexto).
"""

from __future__ import annotations

import os
from typing import Protocol

import httpx

from src.security.pii import detect_pii, is_valid_cnpj, is_valid_cpf
from src.security.schemas import PIIEntity, PIIMatch


class Analyzer(Protocol):
    """Contrato mínimo de um analisador de PII."""

    def analyze(
        self, text: str, entities: list[PIIEntity] | None = None, min_score: float = 0.0
    ) -> list[PIIMatch]: ...


class DeterministicAnalyzer:
    """Analisador OFFLINE (regex + checksum + contexto). Sempre disponível."""

    def __init__(self, language: str = "pt") -> None:
        self.language = language

    def analyze(
        self, text: str, entities: list[PIIEntity] | None = None, min_score: float = 0.0
    ) -> list[PIIMatch]:
        return detect_pii(text, entities=entities, min_score=min_score)


class PresidioHttpAnalyzer:
    """Chama o serviço ``presidio-analyzer`` (imagem oficial) via HTTP.

    Em caso de erro de rede/serviço, faz *fallback* determinístico (fail-safe).
    """

    _ENTITY_MAP = {
        "BR_CPF": PIIEntity.BR_CPF,
        "BR_CNPJ": PIIEntity.BR_CNPJ,
        "BR_RG": PIIEntity.BR_RG,
        "BR_CEP": PIIEntity.BR_CEP,
        "BR_ACCOUNT": PIIEntity.BR_ACCOUNT,
        "EMAIL_ADDRESS": PIIEntity.EMAIL_ADDRESS,
        "PHONE_NUMBER": PIIEntity.PHONE_NUMBER,
        "CREDIT_CARD": PIIEntity.CREDIT_CARD,
        "PERSON": PIIEntity.PERSON,
    }

    def __init__(
        self, base_url: str | None = None, language: str = "pt", timeout: float | None = None
    ) -> None:
        self.base_url = (
            base_url or os.getenv("PRESIDIO_ANALYZER_URL", "http://localhost:5002")
        ).rstrip("/")
        self.language = language
        self.timeout = timeout or float(os.getenv("LLM_TIMEOUT", "30"))
        self._fallback = DeterministicAnalyzer(language)

    def analyze(
        self, text: str, entities: list[PIIEntity] | None = None, min_score: float = 0.0
    ) -> list[PIIMatch]:
        payload: dict[str, object] = {"text": text, "language": self.language}
        if entities:
            payload["entities"] = [e.value for e in entities]
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(f"{self.base_url}/analyze", json=payload)
                response.raise_for_status()
                results = response.json()
        except (httpx.HTTPError, ValueError):
            # Fail-safe: serviço indisponível não pode significar "sem PII".
            return self._fallback.analyze(text, entities, min_score)

        matches: list[PIIMatch] = []
        for item in results:
            entity = self._ENTITY_MAP.get(item.get("entity_type", ""))
            score = float(item.get("score", 0.0))
            if entity is None or score < min_score:
                continue
            start, end = int(item["start"]), int(item["end"])
            matches.append(
                PIIMatch(entity=entity, text=text[start:end], start=start, end=end, score=score)
            )
        return sorted(matches, key=lambda m: m.start)


class PresidioPythonAnalyzer:
    """Usa a lib ``presidio-analyzer`` local com *recognizers* BR (grupo ``presidio``)."""

    def __init__(self, language: str = "pt") -> None:
        self.language = language
        self._fallback = DeterministicAnalyzer(language)
        self._engine = None  # construído tardiamente (lazy) para não pesar o import

    def _ensure_engine(self):
        if self._engine is not None:
            return self._engine
        # Import tardio: só quando o modo python é efetivamente usado.
        from presidio_analyzer import AnalyzerEngine  # noqa: PLC0415

        engine = AnalyzerEngine(supported_languages=[self.language, "en"])
        for recognizer in _build_br_recognizers():
            engine.registry.add_recognizer(recognizer)
        self._engine = engine
        return engine

    def analyze(
        self, text: str, entities: list[PIIEntity] | None = None, min_score: float = 0.0
    ) -> list[PIIMatch]:
        try:
            engine = self._ensure_engine()
            wanted = [e.value for e in entities] if entities else None
            results = engine.analyze(text=text, language=self.language, entities=wanted)
        except Exception:  # noqa: BLE001 — degrada para o determinístico (fail-safe)
            return self._fallback.analyze(text, entities, min_score)

        matches: list[PIIMatch] = []
        for res in results:
            try:
                entity = PIIEntity(res.entity_type)
            except ValueError:
                continue
            if res.score < min_score:
                continue
            matches.append(
                PIIMatch(
                    entity=entity,
                    text=text[res.start : res.end],
                    start=res.start,
                    end=res.end,
                    score=float(res.score),
                )
            )
        return sorted(matches, key=lambda m: m.start)


def _build_br_recognizers() -> list:
    """Cria os *recognizers* brasileiros (Snippet 1 do Doc 04).

    O CPF/CNPJ combinam **regex + contexto + validação de dígito verificador**
    (``validate_result``), exatamente a estratégia de redução de FN/FP do §6.
    """
    from presidio_analyzer import Pattern, PatternRecognizer  # noqa: PLC0415

    class _CpfRecognizer(PatternRecognizer):
        def validate_result(self, pattern_text: str) -> bool | None:  # type: ignore[override]
            return is_valid_cpf(pattern_text)

    class _CnpjRecognizer(PatternRecognizer):
        def validate_result(self, pattern_text: str) -> bool | None:  # type: ignore[override]
            return is_valid_cnpj(pattern_text)

    cpf = _CpfRecognizer(
        supported_entity="BR_CPF",
        supported_language="pt",
        patterns=[Pattern(name="cpf", regex=r"\d{3}\.?\d{3}\.?\d{3}-?\d{2}", score=0.6)],
        context=["cpf", "documento", "contribuinte"],
    )
    cnpj = _CnpjRecognizer(
        supported_entity="BR_CNPJ",
        supported_language="pt",
        patterns=[Pattern(name="cnpj", regex=r"\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}", score=0.6)],
        context=["cnpj", "empresa", "inscrição"],
    )
    cep = PatternRecognizer(
        supported_entity="BR_CEP",
        supported_language="pt",
        patterns=[Pattern(name="cep", regex=r"\d{5}-?\d{3}", score=0.4)],
        context=["cep", "endereço", "endereco"],
    )
    rg = PatternRecognizer(
        supported_entity="BR_RG",
        supported_language="pt",
        patterns=[Pattern(name="rg", regex=r"\d{1,2}\.?\d{3}\.?\d{3}-?[\dxX]", score=0.4)],
        context=["rg", "identidade", "registro geral"],
    )
    return [cpf, cnpj, cep, rg]


def get_analyzer(mode: str | None = None, language: str | None = None) -> Analyzer:
    """Fábrica de analisador a partir de ``PRESIDIO_MODE`` (ou do argumento)."""
    mode = (mode or os.getenv("PRESIDIO_MODE", "deterministic")).lower()
    language = language or os.getenv("PRESIDIO_LANGUAGE", "pt")
    if mode == "http":
        return PresidioHttpAnalyzer(language=language)
    if mode == "python":
        return PresidioPythonAnalyzer(language=language)
    return DeterministicAnalyzer(language=language)
