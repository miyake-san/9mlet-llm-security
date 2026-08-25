"""Agente Aurora Assist: guardrails + MCP isolado + observabilidade (Doc 04, §9).

Este é o ponto de integração do capstone. Reproduz o que o Doc 04 (§9) atribui ao
**Microsoft Agent Framework**: um agente com **observabilidade nativa**, **guardrails
(Aula 2)** e **isolamento de ferramentas via MCP (Aula 3)**. O fluxo por invocação é:

    entrada → guardrail de entrada → RAG (retrieval) → ferramenta MCP (opcional,
    menor privilégio) → LLM → guardrail de saída (PII + grounding) → span gen_ai.*

Com ``guardrails_enabled=False`` (padrão), o agente é ingênuo: jailbreaks passam,
respostas alucinam e PII vaza — sinais que o deploy gate (Doc 04, §6) reprova.

Referência:
    Microsoft (2025). Microsoft Agent Framework.
    OpenTelemetry (2024). Semantic Conventions for GenAI. · Doc 04, §§6,9.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from app.llm import JAILBREAK_LEAK_MARKER, LLMBackend
from app.mcp_tools import LocalToolClient
from app.rag import Retriever
from src.security.guardrails import GuardrailPipeline
from src.security.observability import CostModel, InMemoryTraceStore, redact_preview
from src.security.schemas import GenAISpan, ToolResult

_REFUSAL = "Desculpe, não posso ajudar com essa solicitação por motivos de segurança."

# Gatilhos simples de ferramenta (o agente só chama capacidades de LEITURA).
_TOOL_TRIGGERS: tuple[tuple[tuple[str, ...], str, dict[str, str]], ...] = (
    (("saldo",), "consultar_saldo", {"conta_token": "tok-conta-0001"}),
    (
        ("horário", "horario", "agência", "agencia"),
        "consultar_horario_agencia",
        {"agencia": "central"},
    ),
)


@dataclass
class AgentResult:
    """Resultado de uma invocação do agente (base da avaliação e do trace)."""

    answer: str
    blocked: bool
    stage: str  # "input" | "output" | "ok"
    contexts: list[str] = field(default_factory=list)
    grounded: bool = True
    jailbroken: bool = False
    tool_calls: list[dict] = field(default_factory=list)
    span: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "answer": self.answer,
            "blocked": self.blocked,
            "stage": self.stage,
            "grounded": self.grounded,
            "jailbroken": self.jailbroken,
            "tool_calls": self.tool_calls,
            "span": self.span,
        }


class Agent:
    """Orquestra guardrails, RAG, ferramentas MCP, LLM e observabilidade."""

    def __init__(
        self,
        backend: LLMBackend,
        *,
        retriever: Retriever | None = None,
        tool_client: LocalToolClient | None = None,
        guardrails_enabled: bool = False,
        top_k: int = 3,
        cost_model: CostModel | None = None,
        trace_store: InMemoryTraceStore | None = None,
        model_version: str = "aurora-assist-3.0.0",
    ) -> None:
        self.backend = backend
        self.retriever = retriever or Retriever.from_corpus()
        self.tool_client = tool_client or LocalToolClient()
        self.guardrails = GuardrailPipeline(
            enabled=guardrails_enabled, strict_grounding=guardrails_enabled
        )
        self.top_k = top_k
        self.cost_model = cost_model or CostModel()
        self.trace_store = trace_store or InMemoryTraceStore()
        self.model_version = model_version

    # ------------------------------------------------------------------ #
    def _maybe_call_tool(self, prompt: str) -> list[dict]:
        """Chama uma ferramenta MCP de leitura se o prompt pedir (menor privilégio)."""
        low = prompt.lower()
        calls: list[dict] = []
        for triggers, tool, args in _TOOL_TRIGGERS:
            if any(t in low for t in triggers):
                result: ToolResult = self.tool_client.call(tool, args)
                calls.append({**result.to_dict(), "output": result.output})
                break
        return calls

    def run(self, prompt: str, *, request_id: str = "req") -> AgentResult:
        """Executa o pipeline completo do agente para um prompt."""
        started = time.perf_counter()
        span: GenAISpan = self.trace_store.new_span("chat", self.backend.name)
        span.prompt_preview = redact_preview(prompt)

        # 1) Guardrail de ENTRADA (bloqueia jailbreak/injeção quando habilitado).
        input_decision = self.guardrails.run_input(prompt)
        if not input_decision.allowed:
            span.blocked = True
            span.latency_ms = (time.perf_counter() - started) * 1000
            self.trace_store.record(span)
            return AgentResult(answer=_REFUSAL, blocked=True, stage="input", span=span.to_dict())

        # 2) RAG + 3) ferramenta MCP (opcional; a saída da ferramenta vira contexto).
        contexts = [doc.text for doc, _ in self.retriever.search(prompt, self.top_k)]
        tool_calls = self._maybe_call_tool(prompt)
        for call in tool_calls:
            if call.get("allowed") and call.get("output"):
                contexts.append(f"[ferramenta:{call['tool']}] {call['output']}")
        span.tool_calls = len(tool_calls)

        # 4) LLM (grounding estrito segue o flag de guardrails).
        response = self.backend.generate(prompt, contexts, strict_grounding=self.guardrails.enabled)
        span.input_tokens = response.input_tokens
        span.output_tokens = response.output_tokens
        span.cost_usd = self.cost_model.cost(response.input_tokens, response.output_tokens)

        # 5) Guardrail de SAÍDA (redige PII e checa grounding quando habilitado).
        output_decision = self.guardrails.run_output(response.text, contexts)
        final_text = output_decision.final_text or response.text
        grounded = output_decision.allowed
        jailbroken = JAILBREAK_LEAK_MARKER in response.text

        span.grounded = grounded
        span.latency_ms = (time.perf_counter() - started) * 1000

        if not output_decision.allowed:
            # Alucinação detectada (não sustentada pelo contexto) -> recusa segura.
            span.blocked = True
            self.trace_store.record(span)
            return AgentResult(
                answer=_REFUSAL,
                blocked=True,
                stage="output",
                contexts=contexts,
                grounded=False,
                jailbroken=jailbroken,
                tool_calls=tool_calls,
                span=span.to_dict(),
            )

        self.trace_store.record(span)
        return AgentResult(
            answer=final_text,
            blocked=False,
            stage="ok",
            contexts=contexts,
            grounded=grounded,
            jailbroken=jailbroken,
            tool_calls=tool_calls,
            span=span.to_dict(),
        )
