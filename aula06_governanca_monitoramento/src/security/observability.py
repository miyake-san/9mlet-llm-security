"""Observabilidade de LLM: spans gen_ai.*, custo, cache semântico e routing (Aula 06).

Núcleo de domínio (agnóstico de framework) para a §"Observabilidade" do Doc 04:

* :class:`CostModel` — custo por request a partir de tokens (token economics).
* :class:`SemanticCache` — reutiliza respostas para perguntas similares (hit = 0
  tokens), reduzindo TCO (Doc 04, §"token economics").
* :func:`route_model` — model routing: pergunta simples -> modelo barato; complexa
  -> modelo capaz (Doc 04).
* :class:`InMemoryTraceStore` — coletor de spans gen_ai.* offline (Figura 3),
  espelhando as convenções do OpenTelemetry sem exigir o SDK.
* :func:`redact_preview` — mascara PII antes de gravar telemetria (a
  observabilidade não pode virar nova fonte de risco — Doc 04, §Obs.).

O wiring de PRODUÇÃO (Prometheus, OTLP, Langfuse) fica em ``app/observability.py``.

Referência:
    OpenTelemetry (2024). Semantic Conventions for Generative AI Systems.
    Langfuse (2024). · Doc 04, §"Observabilidade" e §"token economics".
"""

from __future__ import annotations

import json
import logging
import re
import threading
import uuid
from collections import OrderedDict
from pathlib import Path

import numpy as np

from src.security.drift import embed
from src.security.schemas import GenAISpan, RequestMetric

logger = logging.getLogger(__name__)

_MASK = "[REDACTED]"
_PII_PATTERNS = (
    re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"),  # CPF
    re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b"),  # CNPJ
    re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),  # e-mail
    re.compile(r"\(?\d{2}\)?\s?9?\d{4}-?\d{4}\b"),  # telefone
)


def pseudonymize(subject_id: str) -> str:
    """Referência pseudonimizada e estável (nunca PII em claro nos spans/logs)."""
    import hashlib

    digest = hashlib.sha256(subject_id.encode("utf-8")).hexdigest()[:12]
    return f"subj_{digest}"


def redact_preview(text: str, max_chars: int = 120) -> str:
    """Mascara PII e trunca o texto para virar um *preview* seguro no span.

    Implementa a exigência do Doc 04 (§Obs.): a telemetria aplica minimização de
    dados — só um trecho mascarado do prompt é registrado, nunca PII em claro.
    """
    redacted = text
    for pattern in _PII_PATTERNS:
        redacted = pattern.sub(_MASK, redacted)
    redacted = " ".join(redacted.split())
    return redacted[:max_chars]


# --------------------------------------------------------------------------- #
# Modelo de custo (token economics — Doc 04)                                   #
# --------------------------------------------------------------------------- #
class CostModel:
    """Custo por request a partir de tokens de entrada/saída (USD)."""

    def __init__(
        self,
        input_per_1k: float = 0.005,
        output_per_1k: float = 0.015,
        per_model: dict[str, dict[str, float]] | None = None,
    ) -> None:
        self.input_per_1k = input_per_1k
        self.output_per_1k = output_per_1k
        self.per_model = per_model or {}

    @classmethod
    def from_config(cls, cost_cfg: dict) -> CostModel:
        return cls(
            input_per_1k=float(cost_cfg.get("input_per_1k", 0.005)),
            output_per_1k=float(cost_cfg.get("output_per_1k", 0.015)),
            per_model=cost_cfg.get("models", {}) or {},
        )

    def cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        """Custo (USD) do request; usa a tabela por modelo quando disponível."""
        prices = self.per_model.get(model)
        in_price = float(prices["input_per_1k"]) if prices else self.input_per_1k
        out_price = float(prices["output_per_1k"]) if prices else self.output_per_1k
        return (input_tokens / 1000.0) * in_price + (output_tokens / 1000.0) * out_price


# --------------------------------------------------------------------------- #
# Model routing (Doc 04, §"token economics")                                   #
# --------------------------------------------------------------------------- #
def route_model(prompt: str, cfg: dict) -> tuple[str, bool]:
    """Roteia por complexidade: (modelo, is_complex).

    Pergunta simples (horário, tarifa) -> modelo barato; dúvida complexa
    (renegociação, crédito) -> modelo capaz e maior escrutínio (Doc 04).
    """
    routing = cfg or {}
    if not routing.get("enabled", True):
        return routing.get("capable_model", "aurora-pro"), True
    low = prompt.lower()
    min_tokens = int(routing.get("complex_min_tokens", 24))
    terms = routing.get("complex_terms", [])
    is_complex = len(low.split()) >= min_tokens or any(term in low for term in terms)
    model = routing.get("capable_model", "aurora-pro") if is_complex else routing.get(
        "cheap_model", "aurora-mini"
    )
    return model, is_complex


# --------------------------------------------------------------------------- #
# Cache semântico (Doc 04, §"token economics")                                 #
# --------------------------------------------------------------------------- #
class SemanticCache:
    """Cache por similaridade de cosseno de embeddings (hit reduz tokens/custo).

    Um HIT ocorre quando a similaridade com uma pergunta já respondida é >=
    ``threshold``. Usa ``RLock`` (reentrante) porque métodos sob lock podem
    chamar outros métodos que também travam.
    """

    def __init__(self, threshold: float = 0.92, max_entries: int = 512) -> None:
        self.threshold = threshold
        self.max_entries = max_entries
        self._items: OrderedDict[str, tuple[np.ndarray, str]] = OrderedDict()
        self._lock = threading.RLock()
        self.hits = 0
        self.misses = 0

    def _best_match(self, vector: np.ndarray) -> tuple[str | None, float]:
        best_key, best_score = None, -1.0
        for key, (vec, _answer) in self._items.items():
            score = float(vector @ vec)  # ambos L2-normalizados -> cosseno
            if score > best_score:
                best_key, best_score = key, score
        return best_key, best_score

    def get(self, prompt: str) -> str | None:
        """Retorna a resposta cacheada se houver pergunta suficientemente similar."""
        vector = embed(prompt)
        with self._lock:
            key, score = self._best_match(vector)
            if key is not None and score >= self.threshold:
                self._items.move_to_end(key)
                self.hits += 1
                return self._items[key][1]
            self.misses += 1
            return None

    def put(self, prompt: str, answer: str) -> None:
        """Insere/atualiza uma entrada, com evicção LRU quando cheio."""
        vector = embed(prompt)
        with self._lock:
            self._items[prompt] = (vector, answer)
            self._items.move_to_end(prompt)
            while len(self._items) > self.max_entries:
                self._items.popitem(last=False)

    @property
    def hit_ratio(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total else 0.0

    def reset(self) -> None:
        with self._lock:
            self._items.clear()
            self.hits = self.misses = 0


# --------------------------------------------------------------------------- #
# Coletor de spans em memória (offline; espelha OpenTelemetry gen_ai.*)         #
# --------------------------------------------------------------------------- #
class InMemoryTraceStore:
    """Armazena spans gen_ai.* em memória e, opcionalmente, em JSONL (tmpfs).

    Serve à Figura 3 do Doc 04 (trace de conversa) sem exigir o OTel SDK. O
    arquivo (``path``) só recebe METADADOS já mascarados (Doc 04, §Obs.).
    """

    def __init__(self, path: str | None = None) -> None:
        self._spans: list[GenAISpan] = []
        self._lock = threading.RLock()
        self._path = Path(path) if path else None

    def record(self, span: GenAISpan) -> GenAISpan:
        with self._lock:
            self._spans.append(span)
        self._append_file(span)
        return span

    def _append_file(self, span: GenAISpan) -> None:
        if self._path is None:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(span.to_otel_attributes(), ensure_ascii=False) + "\n")
        except OSError as exc:  # limite: FS somente-leitura -> telemetria em memória
            logger.debug("Trace file indisponível (%s); mantendo apenas em memória.", exc)

    def spans(self) -> list[GenAISpan]:
        with self._lock:
            return list(self._spans)

    def metrics(self) -> list[RequestMetric]:
        """Converte spans em telemetria por request (base dos SLIs)."""
        out: list[RequestMetric] = []
        for span in self.spans():
            out.append(
                RequestMetric(
                    latency_ms=span.latency_ms,
                    input_tokens=span.input_tokens,
                    output_tokens=span.output_tokens,
                    cost_usd=span.cost_usd,
                    groundedness=span.groundedness,
                    cache_hit=span.cache_hit,
                    blocked=span.blocked,
                    jailbreak_attempt=span.block_reason == "jailbreak",
                    jailbreak_blocked=span.blocked and span.block_reason == "jailbreak",
                    pii_leak=span.pii_leak,
                    regulated=span.regulated,
                    timestamp=span.timestamp,
                )
            )
        return out

    def count(self) -> int:
        with self._lock:
            return len(self._spans)

    def reset(self) -> None:
        with self._lock:
            self._spans.clear()


def new_span(
    name: str,
    *,
    system: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    latency_ms: float,
    cost_usd: float,
    **flags: object,
) -> GenAISpan:
    """Constrói um :class:`GenAISpan` com trace/span ids (helper de instrumentação)."""
    return GenAISpan(
        name=name,
        gen_ai_system=system,
        gen_ai_request_model=model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        latency_ms=latency_ms,
        cost_usd=cost_usd,
        trace_id=uuid.uuid4().hex,
        span_id=uuid.uuid4().hex[:16],
        **flags,  # type: ignore[arg-type]
    )


def _self_test() -> None:  # pragma: no cover - utilitário de linha de comando
    """Demo offline: gera spans sintéticos e imprime um resumo (task monitor)."""
    from rich import print as rprint

    store = InMemoryTraceStore()
    cost = CostModel()
    cache = SemanticCache(threshold=0.9)
    prompts = [
        "Qual o horário da agência central?",
        "Qual o horario da agencia central?",  # similar -> hit
        "Explique a renegociação de dívida com garantia imobiliária em detalhe.",
    ]
    for i, prompt in enumerate(prompts):
        hit = cache.get(prompt) is not None
        in_tok, out_tok = (0, 0) if hit else (12 + i * 20, 30 + i * 40)
        span = new_span(
            "aurora_assist.chat",
            system="ollama",
            model="aurora-mini" if i < 2 else "aurora-pro",
            input_tokens=in_tok,
            output_tokens=out_tok,
            latency_ms=90.0 + i * 120,
            cost_usd=cost.cost("aurora-mini", in_tok, out_tok),
            cache_hit=hit,
            groundedness=0.8,
        )
        store.record(span)
        if not hit:
            cache.put(prompt, "resposta")
    rprint("[bold]Spans gerados[/bold]:", store.count())
    rprint("Cache hit ratio:", round(cache.hit_ratio, 2))
    rprint("Exemplo de atributos gen_ai.*:", store.spans()[0].to_otel_attributes())


if __name__ == "__main__":  # pragma: no cover
    import sys

    if "--self-test" in sys.argv:
        _self_test()
    else:
        print("uso: python -m src.security.observability --self-test")
