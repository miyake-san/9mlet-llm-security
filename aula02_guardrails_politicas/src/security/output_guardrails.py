"""Guardrail de SAÍDA — validação estruturada estilo Rail Spec (Aula 02).

Última muralha do *defense-in-depth* (Doc 04, seções 1 e 6): a resposta do LLM
deixa de ser "texto livre" e passa a ser um CONTRATO DE INTEGRAÇÃO. Antes de
entregar ao cliente, validamos três coisas discutidas no Snippet 2 e na
seção 6:

1. **Contrato/schema** (Rail Spec): quando o fluxo exige resposta estruturada,
   o JSON precisa conter os campos obrigatórios e tipos corretos.
2. **Ausência de PII** (``DetectPII``): CPF, saldo, e-mail etc. não podem
   vazar; a saída é corrigida (redação) ou bloqueada.
3. **Ausência de toxicidade** e limites de tamanho.

Em produção o caminho é o **Guardrails AI** com Rail Spec declarativa
(grupo ``frameworks``); aqui a validação é offline e determinística.

Referência:
    Guardrails AI (2024). Rail Spec / DetectPII.
    OWASP Foundation (2025). Top 10 for LLM Applications — LLM02.
    Doc 04, seção 6 (validação de saída como fronteira de confiabilidade).
"""

from __future__ import annotations

import json
import re
import time

from pydantic import BaseModel, ValidationError

from . import pii
from .schemas import Layer, LayerResult, Verdict

# Denylist DIDÁTICA de toxicidade (PT-BR/EN). Curta e sem termos gráficos: o
# foco é demonstrar o guardrail de saída, não catalogar ofensas.
_TOXIC_TERMS = [
    r"\bidiota\b", r"\bimbecil\b", r"\best[úu]pid[oa]\b",
    r"\bstupid\b", r"\bidiot\b", r"\bmoron\b", r"\bshut up\b", r"\bcale a boca\b",
]


class BalanceResponse(BaseModel):
    """Contrato de saída para consulta de saldo (exemplo de Rail Spec).

    Doc 04, seção 6: uma resposta sobre saldo deve conter moeda, valor, data e
    produto — se o modelo omite um campo ou inventa uma moeda, a aplicação NÃO
    deve entregar o texto ao usuário.
    """

    produto: str
    moeda: str
    valor: float
    data_consulta: str
    mensagem: str


def check_output_schema(text: str, model: type[BaseModel] = BalanceResponse) -> LayerResult:
    """Valida a saída contra um contrato Pydantic (quando o fluxo exige JSON)."""
    start = time.perf_counter()
    try:
        payload = json.loads(text)
        model.model_validate(payload)
        verdict, reason = Verdict.ALLOW, "Saída aderente ao contrato"
    except (json.JSONDecodeError, ValidationError, TypeError) as error:
        verdict, reason = Verdict.BLOCK, f"Saída viola o contrato Rail Spec: {error}"
    latency_ms = (time.perf_counter() - start) * 1000
    return LayerResult(
        layer=Layer.OUTPUT_SCHEMA,
        verdict=verdict,
        score=1.0 if verdict == Verdict.BLOCK else 0.0,
        reason=reason,
        details={"model": model.__name__},
        latency_ms=latency_ms,
    )


def check_output_pii(
    text: str,
    entities: list[str] | None = None,
    token: str = "[REDACTED_{entity}]",
) -> LayerResult:
    """Detecta PII na saída e a corrige (redação). Doc 04, Snippet 2."""
    start = time.perf_counter()
    redacted, matches = pii.redact_pii(text, entities=entities, token=token)
    latency_ms = (time.perf_counter() - start) * 1000
    if not matches:
        return LayerResult(
            layer=Layer.OUTPUT_PII,
            verdict=Verdict.ALLOW,
            reason="Nenhuma PII detectada na saída",
            latency_ms=latency_ms,
        )
    return LayerResult(
        layer=Layer.OUTPUT_PII,
        verdict=Verdict.REDACT,
        score=1.0,
        reason=f"PII removida da saída: {sorted({m.entity for m in matches})}",
        details={
            "entities": sorted({m.entity for m in matches}),
            "count": len(matches),
            "redacted_text": redacted,
        },
        latency_ms=latency_ms,
    )


def check_output_toxicity(text: str) -> LayerResult:
    """Bloqueia respostas com toxicidade (guardrail de saída)."""
    start = time.perf_counter()
    hits = [term for term in _TOXIC_TERMS if re.search(term, text, re.IGNORECASE)]
    latency_ms = (time.perf_counter() - start) * 1000
    blocked = bool(hits)
    return LayerResult(
        layer=Layer.OUTPUT_TOXICITY,
        verdict=Verdict.BLOCK if blocked else Verdict.ALLOW,
        score=1.0 if blocked else 0.0,
        reason=("Toxicidade detectada na saída" if blocked else "Saída sem toxicidade"),
        details={"matches": hits},
        latency_ms=latency_ms,
    )
