"""Esquemas compartilhados do pipeline de guardrails (Aula 02).

Define os tipos que trafegam entre as camadas de *defense-in-depth* discutidas
na seção 1 do Documento 04: cada camada produz um :class:`LayerResult` e o
pipeline agrega tudo em uma :class:`GuardDecision` auditável.

Referência:
    Sutton, S. (2025). *AI-Native LLM Security*. Packt. (defense-in-depth)
    OWASP Foundation (2025). Top 10 for LLM Applications — LLM01/LLM02.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Verdict(StrEnum):
    """Decisão de uma camada ou do pipeline como um todo."""

    ALLOW = "allow"      # segue adiante
    BLOCK = "block"      # interrompe e recusa
    REDACT = "redact"    # entrega, mas com conteúdo corrigido (ex.: PII removida)
    REVIEW = "review"    # permite, porém sinaliza para revisão humana


class Layer(StrEnum):
    """Camadas de guardrail. Ordem reflete o fluxo entrada → modelo → saída."""

    INPUT_SCHEMA = "input_schema"          # Pydantic (formato/limites) — Doc 04 §2
    INPUT_INJECTION = "input_injection"    # heurísticas de injection/jailbreak — §1
    LLAMA_GUARD = "llama_guard"            # classificador de safety — Doc 04 §7
    CONTENT_SAFETY = "content_safety"      # AACS severidade graduada — §7
    BEHAVIOR = "behavior"                  # política Colang (escopo) — §5
    OUTPUT_SCHEMA = "output_schema"        # Rail Spec (contrato) — §6
    OUTPUT_PII = "output_pii"              # DetectPII na saída — §6 / Snippet 2
    OUTPUT_TOXICITY = "output_toxicity"    # toxicidade na saída — §6


@dataclass
class LayerResult:
    """Resultado de uma única camada de guardrail."""

    layer: Layer
    verdict: Verdict
    score: float = 0.0
    reason: str = ""
    details: dict = field(default_factory=dict)
    latency_ms: float = 0.0

    @property
    def blocked(self) -> bool:
        return self.verdict == Verdict.BLOCK

    def to_dict(self) -> dict:
        return {
            "layer": self.layer.value,
            "verdict": self.verdict.value,
            "score": round(self.score, 4),
            "reason": self.reason,
            "details": self.details,
            "latency_ms": round(self.latency_ms, 3),
        }


@dataclass
class GuardDecision:
    """Decisão agregada do pipeline de *defense-in-depth*.

    ``allowed`` é ``True`` apenas se NENHUMA camada bloqueou. A saída pode ter
    sido corrigida (``REDACT``) mesmo quando ``allowed`` é ``True``.
    """

    allowed: bool = True
    verdict: Verdict = Verdict.ALLOW
    layers: list[LayerResult] = field(default_factory=list)
    final_text: str | None = None
    blocked_by: Layer | None = None
    reason: str = ""
    flow: str = "faq"

    def add(self, result: LayerResult) -> LayerResult:
        """Registra o resultado de uma camada e propaga bloqueio/redação."""
        self.layers.append(result)
        if result.verdict == Verdict.BLOCK:
            self.allowed = False
            self.verdict = Verdict.BLOCK
            self.blocked_by = result.layer
            self.reason = result.reason
        elif result.verdict == Verdict.REDACT and self.verdict != Verdict.BLOCK:
            self.verdict = Verdict.REDACT
        elif result.verdict == Verdict.REVIEW and self.verdict == Verdict.ALLOW:
            self.verdict = Verdict.REVIEW
        return result

    @property
    def total_latency_ms(self) -> float:
        return round(sum(layer_result.latency_ms for layer_result in self.layers), 3)

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "verdict": self.verdict.value,
            "flow": self.flow,
            "blocked_by": self.blocked_by.value if self.blocked_by else None,
            "reason": self.reason,
            "final_text": self.final_text,
            "total_latency_ms": self.total_latency_ms,
            "layers": [layer_result.to_dict() for layer_result in self.layers],
        }
