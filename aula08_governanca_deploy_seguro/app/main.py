"""Aurora Assist v3.0 — agent-app do capstone (Aula 08).

Aplicação FastAPI que serve o **agente** Aurora Assist em produção (Doc 04, §§9-10):
guardrails (Aula 2) + ferramentas MCP isoladas (Aula 3) + observabilidade (Aula 6),
sob governança (NIST AI RMF / ISO 42001 / EU AI Act). A flag ``AGENT_GUARDRAILS_ENABLED``
controla se o agente é ingênuo (padrão) ou endurecido — a base do deploy gate.

Endpoints:
    GET  /health                 — liveness.
    GET  /                       — identidade do serviço.
    GET  /config                 — flags de mitigação e estratégia de deploy.
    POST /chat                   — invoca o agente (answer + contexts + telemetria).
    GET  /metrics/summary        — SLIs de runtime agregados dos spans gen_ai.*.
    GET  /slo/report             — status dos SLOs em runtime (Aula 06).
    GET  /aibom                  — AIBOM (CycloneDX ML-BOM) do sistema (§8).
    GET  /governance/crosswalk   — crosswalk NIST/ISO/EU AI Act ↔ Aulas 1-7 (§§2-4).
    POST /deploy/evaluate        — roda o deploy gate sobre uma candidata (§6).

Referência:
    Microsoft (2025). Azure AI Foundry / Microsoft Agent Framework. · Doc 04, §§9-10.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, FastAPI
from pydantic import BaseModel, Field

from app.agent import Agent
from app.config import Settings, get_settings
from app.deploy_gates import InProcessCandidate, run_deploy_gate
from app.llm import get_backend
from src.security.aibom import aibom_completeness, build_aibom
from src.security.governance import build_crosswalk, coverage_report
from src.security.observability import InMemoryTraceStore
from src.security.slo import evaluate_all, load_slo_definitions

logger = logging.getLogger(__name__)

_trace_store = InMemoryTraceStore()


@lru_cache
def _agent() -> Agent:
    """Agente único do processo (retriever carregado uma vez)."""
    s = get_settings()
    return Agent(
        get_backend(s),
        guardrails_enabled=s.agent_guardrails_enabled,
        top_k=s.rag_top_k,
        trace_store=_trace_store,
        model_version=s.model_version,
    )


def get_agent() -> Agent:
    """Dependência do agente (sobrescrevível em testes)."""
    return _agent()


@asynccontextmanager
async def lifespan(_: FastAPI):
    s = get_settings()
    logging.basicConfig(level=s.log_level)
    logger.info(
        "Aurora Assist %s | guardrails=%s strategy=%s canary=%.0f%% docs=%d",
        s.model_version,
        s.agent_guardrails_enabled,
        s.deployment_strategy,
        s.canary_percent,
        len(_agent().retriever.documents),
    )
    yield


app = FastAPI(
    title="Aurora Assist v3.0 (agent-app)",
    description="Agente em produção com governança e deploy seguro (Aula 08 — capstone).",
    version="3.0.0",
    lifespan=lifespan,
)


# --------------------------------------------------------------------------- #
# Schemas                                                                      #
# --------------------------------------------------------------------------- #
class ChatRequest(BaseModel):
    prompt: str = Field(..., min_length=1, examples=["Qual a taxa do CDB Aurora Prime?"])


class ChatResponse(BaseModel):
    answer: str
    contexts: list[str]
    blocked: bool
    grounded: bool
    jailbroken: bool
    stage: str
    tool_calls: list[dict]
    latency_ms: float
    cost_usd: float
    backend: str
    model_version: str


class DeployEvalRequest(BaseModel):
    guardrails: bool = Field(default=True, description="Avaliar a candidata endurecida?")


# --------------------------------------------------------------------------- #
# Endpoints                                                                    #
# --------------------------------------------------------------------------- #
@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
def root() -> dict[str, object]:
    return {
        "service": "aurora-assist-agent",
        "version": "3.0.0",
        "endpoints": [
            "/chat",
            "/config",
            "/aibom",
            "/slo/report",
            "/governance/crosswalk",
            "/health",
        ],
    }


@app.get("/config")
def config(settings: Annotated[Settings, Depends(get_settings)]) -> dict[str, object]:
    """Flags de mitigação e estratégia de deploy (o deploy gate usa isto)."""
    return {
        "model_version": settings.model_version,
        "agent_guardrails_enabled": settings.agent_guardrails_enabled,
        "deployment_strategy": settings.deployment_strategy,
        "canary_percent": settings.canary_percent,
        "mcp_enabled": settings.mcp_enabled,
    }


@app.post("/chat", response_model=ChatResponse)
def chat(
    req: ChatRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    agent: Annotated[Agent, Depends(get_agent)],
) -> ChatResponse:
    """Invoca o agente (guardrails + MCP + observabilidade) e retorna a telemetria."""
    result = agent.run(req.prompt)
    span = result.span
    return ChatResponse(
        answer=result.answer,
        contexts=result.contexts,
        blocked=result.blocked,
        grounded=result.grounded,
        jailbroken=result.jailbroken,
        stage=result.stage,
        tool_calls=result.tool_calls,
        latency_ms=float(span.get("latency_ms", 0.0)),
        cost_usd=float(span.get("gen_ai.usage.cost_usd", 0.0)),
        backend=agent.backend.name,
        model_version=settings.model_version,
    )


@app.get("/metrics/summary")
def metrics_summary(agent: Annotated[Agent, Depends(get_agent)]) -> dict[str, object]:
    """SLIs de runtime agregados dos spans gen_ai.* (Aula 06)."""
    return agent.trace_store.summary()


@app.get("/slo/report")
def slo_report(
    settings: Annotated[Settings, Depends(get_settings)],
    agent: Annotated[Agent, Depends(get_agent)],
) -> dict[str, object]:
    """Status dos SLOs em runtime a partir da telemetria coletada (Doc 04, §7)."""
    summary = agent.trace_store.summary()
    slis = {
        "latency_p95_ms": float(summary.get("latency_p95_ms", 0.0)),
        "groundedness": float(summary.get("groundedness", 1.0)),
        "cost_per_request_usd": float(summary.get("total_cost_usd", 0.0))
        / max(1, int(summary.get("count", 1))),
    }
    defs = load_slo_definitions(settings.slo_path)
    return {"sli_snapshot": slis, "report": evaluate_all(defs, slis).to_dict()}


@app.get("/aibom")
def aibom() -> dict[str, object]:
    """AIBOM (CycloneDX ML-BOM) do Aurora Assist (Doc 04, §8, Snippet 1)."""
    bom = build_aibom()
    return {"aibom": bom, "completeness": aibom_completeness(bom)}


@app.get("/governance/crosswalk")
def governance_crosswalk() -> dict[str, object]:
    """Crosswalk de governança ↔ controles do curso (Doc 04, §§2-4, 10)."""
    return {"crosswalk": build_crosswalk(), "coverage": coverage_report()}


@app.post("/deploy/evaluate")
def deploy_evaluate(req: DeployEvalRequest) -> dict[str, object]:
    """Roda o deploy gate sobre uma candidata in-process (Doc 04, §6)."""
    return run_deploy_gate(InProcessCandidate(guardrails=req.guardrails))
