"""FastAPI do Aurora Assist — pipeline Zero Trust de proteção de dados (Aula 03).

Papel ``rag`` (porta 8000): orquestra o fluxo da **Figura 1** do Documento 04:

    ingress (tokeniza PII) → LLM (vê só tokens) → ferramentas MCP isoladas
    → egress (reidrata para o titular autorizado).

O LLM e as ferramentas **jamais** recebem o dado bruto do cliente (§7). As
ferramentas são acionadas por **capability tokens** de escopo mínimo (§9-10),
via o ``mcp-server`` isolado em rede interna. O tratamento de erro fica nos
LIMITES (entrada da API e chamadas externas).

Endpoints:
    POST /chat         — pipeline completo (ingress → LLM/tools → egress).
    POST /anonymize    — só ingress (usado por ``task scan`` / notebooks).
    POST /deanonymize  — egress (reidratação autorizada).
    POST /tools/{name} — chamada de ferramenta MCP proxied (demonstra isolamento).

Referência:
    Doc 04, §7 (LLM vê só tokens), §9-10 (isolamento/least privilege), Figura 1.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Literal

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.llm import get_backend
from app.pii import DataProtectionPipeline
from src.security import issue_capability

MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "http://localhost:8090").rstrip("/")
MCP_CAPABILITY_SECRET = os.getenv("MCP_CAPABILITY_SECRET", "dev-capability-secret")
MCP_CAPABILITY_TTL = float(os.getenv("MCP_CAPABILITY_TTL", "120"))
LLM_TIMEOUT = float(os.getenv("LLM_TIMEOUT", "60"))

Flow = Literal["faq", "authenticated", "transactional"]

# Escopo exigido por ferramenta (o gateway concede o MÍNIMO necessário).
_TOOL_SCOPE = {
    "consultar_saldo": "saldo:read",
    "consultar_horario_agencia": "agencia:read",
}
_DEFAULT_ACCOUNT_TOKEN = "[BR_ACCOUNT_TOKEN_demo0001]"


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=8000)
    flow: Flow = "faq"
    subject: str = "cliente-anon"          # identidade autenticada (§2 identity-first)


class AnonymizeRequest(BaseModel):
    message: str = Field(min_length=1, max_length=8000)
    flow: Flow = "faq"


class DeanonymizeRequest(BaseModel):
    text: str = Field(min_length=1, max_length=8000)
    flow: Flow = "authenticated"


class ToolRequest(BaseModel):
    args: dict[str, str] = Field(default_factory=dict)
    flow: Flow = "authenticated"
    subject: str = "cliente-anon"


_state: dict[str, object] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    _state["pipeline"] = DataProtectionPipeline()
    _state["backend"] = get_backend()
    yield
    _state.clear()


app = FastAPI(
    title="Aurora Assist — Zero Trust (rag)",
    description="Aula 03 — Proteção de Dados e Isolamento de Ferramentas em LLMs",
    version="0.1.0",
    lifespan=lifespan,
)


def _pipeline() -> DataProtectionPipeline:
    pipeline = _state.get("pipeline")
    if pipeline is None:  # defensivo: chamada antes do lifespan
        pipeline = DataProtectionPipeline()
        _state["pipeline"] = pipeline
    return pipeline  # type: ignore[return-value]


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "role": "rag"}


@app.get("/")
def root() -> dict[str, object]:
    return {
        "service": "Aurora Assist",
        "role": "rag",
        "lesson": "Aula 03 — Proteção de Dados e Isolamento de Ferramentas em LLMs",
        "endpoints": ["POST /chat", "POST /anonymize", "POST /deanonymize", "POST /tools/{name}"],
    }


# ---------------------------------------------------------------------- #
# Cliente das ferramentas MCP isoladas (rede interna; capability token)
# ---------------------------------------------------------------------- #
def _call_mcp_tool(tool: str, scope: str, args: dict[str, str], subject: str) -> dict:
    """Emite um capability token de escopo mínimo e chama o mcp-server."""
    token = issue_capability(
        subject=subject,
        tool=tool,
        scopes={scope},
        secret=MCP_CAPABILITY_SECRET,
        ttl_seconds=MCP_CAPABILITY_TTL,
    )
    payload = {
        "capability": {
            "subject": token.subject,
            "tool": token.tool,
            "scopes": sorted(token.scopes),
            "issued_at": token.issued_at,
            "expires_at": token.expires_at,
            "signature": token.signature,
        },
        "args": args,
    }
    try:
        with httpx.Client(timeout=LLM_TIMEOUT) as client:
            response = client.post(f"{MCP_SERVER_URL}/tools/{tool}", json=payload)
    except httpx.HTTPError as error:
        raise HTTPException(status_code=502, detail=f"mcp-server indisponível: {error}") from error

    if response.status_code == 403:
        # Ferramenta recusada por política de isolamento (esperado em abusos).
        return {"allowed": False, "denied": response.json().get("detail", {})}
    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"mcp-server erro: {response.text}")
    return response.json().get("result", {})


# ---------------------------------------------------------------------- #
# POST /chat — pipeline Zero Trust completo
# ---------------------------------------------------------------------- #
@app.post("/chat")
def chat(req: ChatRequest) -> dict[str, object]:
    pipeline = _pipeline()
    profile = pipeline.profile(req.flow)

    # (1) INGRESS: anonimiza/minimiza — a partir daqui o dado bruto não circula.
    ingress = pipeline.anonymize(req.message, flow=req.flow)

    tool_trace: dict | None = None
    used_tool = False

    # (2) Orquestração determinística: consulta de saldo aciona a ferramenta MCP.
    wants_balance = "saldo" in req.message.lower()
    if wants_balance and "saldo:read" in profile.required_tool_scopes:
        used_tool = True
        conta_token = _pick_account_token(ingress.reversible_tokens)
        tool_trace = _call_mcp_tool(
            "consultar_saldo", "saldo:read", {"conta_token": conta_token}, req.subject
        )
        raw_balance = str(tool_trace.get("output") or "saldo indisponível")
        # (3) O resultado da ferramenta é TOKENIZADO antes de voltar ao contexto:
        #     nem o LLM nem o log veem o valor real (Doc 04, §7).
        saldo_token = pipeline.anonymizer.vault.tokenize("SALDO", raw_balance)
        answer_internal = f"O saldo solicitado é {saldo_token}."
    else:
        # (2') Sem ferramenta: o LLM gera a partir do texto ANONIMIZADO.
        backend = _state.get("backend") or get_backend()
        try:
            answer_internal = backend.generate(ingress.text)  # type: ignore[union-attr]
        except httpx.HTTPError as error:
            raise HTTPException(status_code=503, detail=f"LLM indisponível: {error}") from error

    # (4) EGRESS: reidrata tokens SOMENTE se o fluxo autorizar (titular).
    answer_delivered = pipeline.deanonymize(answer_internal, flow=req.flow)

    return {
        "answer": answer_delivered,           # entregue ao titular autenticado
        "answer_internal": answer_internal,   # o que o LLM/log realmente viram (tokens)
        "flow": req.flow,
        "used_tool": used_tool,
        "tool": tool_trace,
        "ingress": ingress.to_dict(),
        "rehydrated": profile.rehydrate_on_egress,
    }


def _pick_account_token(tokens: list[str]) -> str:
    """Escolhe o token de conta detectado no ingress, ou um token demo."""
    for token in tokens:
        if token.startswith("[BR_ACCOUNT_TOKEN_"):
            return token
    return _DEFAULT_ACCOUNT_TOKEN


# ---------------------------------------------------------------------- #
# POST /anonymize — só ingress (análise). Usado por `task scan` e notebooks.
# ---------------------------------------------------------------------- #
@app.post("/anonymize")
def anonymize(req: AnonymizeRequest) -> dict[str, object]:
    result = _pipeline().anonymize(req.message, flow=req.flow)
    return result.to_dict()


# ---------------------------------------------------------------------- #
# POST /deanonymize — egress (reidratação autorizada)
# ---------------------------------------------------------------------- #
@app.post("/deanonymize")
def deanonymize(req: DeanonymizeRequest) -> dict[str, object]:
    pipeline = _pipeline()
    profile = pipeline.profile(req.flow)
    return {
        "text": pipeline.deanonymize(req.text, flow=req.flow),
        "rehydrated": profile.rehydrate_on_egress,
        "flow": req.flow,
    }


# ---------------------------------------------------------------------- #
# POST /tools/{name} — chamada MCP proxied (demonstra o isolamento)
# ---------------------------------------------------------------------- #
@app.post("/tools/{name}")
def tools(name: str, req: ToolRequest) -> dict[str, object]:
    pipeline = _pipeline()
    profile = pipeline.profile(req.flow)
    scope = _TOOL_SCOPE.get(name, "unknown:scope")

    # Autorização de FLUXO (defense-in-depth antes mesmo do capability token):
    # o fluxo precisa exigir aquele escopo — senão nem emitimos o token.
    if scope not in profile.required_tool_scopes:
        raise HTTPException(
            status_code=403,
            detail={"reason": "flow_not_authorized_for_scope", "flow": req.flow, "scope": scope},
        )
    result = _call_mcp_tool(name, scope, req.args, req.subject)
    return {"tool": name, "result": result}
