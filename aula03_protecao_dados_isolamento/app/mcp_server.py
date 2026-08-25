"""Servidor de ferramentas MCP ISOLADO do Aurora Assist (Aula 03 — vídeo 3/4).

Materializa o **Snippet 3** do Documento 04 (§10): um servidor de ferramentas que
expõe **apenas** capacidades de leitura, com **capability tokens** verificados a
cada chamada. É executado como contêiner *hardened* em **rede interna sem egress**
(``docker-compose.yml``), de modo que — mesmo comprometido — não alcance recursos
fora do seu escopo (menor privilégio + isolamento de rede).

> Nota de engenharia: em produção usa-se o **SDK oficial do MCP** (Anthropic, 2024;
> ``uv sync --group mcp``). Aqui implementamos um servidor HTTP compatível com a
> mesma semântica (ferramenta = capacidade nomeada + escopo), para manter o lab
> *offline-first*, contêinerizável e testável sem transporte stdio/SSE.

Equivalente conceitual (Snippet 3 do Doc 04)::

    from mcp.server import Server
    app = Server("aurora-saldo")

    @app.tool()  # única capacidade exposta: LER saldo, jamais transferir
    async def consultar_saldo(conta_token: str) -> str:
        return saldo_service.read_only(conta_token)

Referência:
    Anthropic (2024). Model Context Protocol.
    Hardy, N. (1988). The Confused Deputy.
    OWASP Foundation (2025). Top 10 for LLM Applications — LLM07/LLM08.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from src.security.mcp_isolation import AuditTrail, ToolAuthorizer, ToolCatalog
from src.security.schemas import CapabilityToken

_APP_DIR = Path(__file__).resolve().parent
_TOOL_POLICY = _APP_DIR / "policies" / "tool_policy.yaml"

# --- Dados SINTÉTICOS da ferramenta (fictícios; jamais dados reais) ---------
# Mapa conta-token -> saldo. O "conta_token" já é a forma anonimizada da conta
# (o servidor NUNCA recebe o número real): reforça que o dado bruto não circula.
_ACCOUNTS: dict[str, str] = {
    "[BR_ACCOUNT_TOKEN_demo0001]": "R$ 12.340,55",
    "[BR_ACCOUNT_TOKEN_demo0002]": "R$ 987,10",
    "[BR_ACCOUNT_TOKEN_demo0003]": "R$ 45.008,00",
}
_AGENCIES: dict[str, str] = {
    "central": "Seg-Sex 10h-16h",
    "paulista": "Seg-Sex 09h-15h",
}

_state: dict[str, object] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    catalog = ToolCatalog.from_yaml(_TOOL_POLICY)
    audit = AuditTrail(sink=os.getenv("MCP_AUDIT_LOG", "reports/mcp_audit.jsonl"))
    _state["authorizer"] = ToolAuthorizer(catalog=catalog, audit=audit)
    _state["catalog"] = catalog
    yield
    _state.clear()


app = FastAPI(
    title="Aurora Assist — MCP tool server (isolado)",
    description="Aula 03 — ferramentas MCP com capacidade mínima (least privilege)",
    version="0.1.0",
    lifespan=lifespan,
)


class CapabilityTokenModel(BaseModel):
    """Capability token transportado pelo cliente (rag-api)."""

    subject: str
    tool: str
    scopes: list[str]
    issued_at: float
    expires_at: float
    signature: str

    def to_domain(self) -> CapabilityToken:
        return CapabilityToken(
            subject=self.subject,
            tool=self.tool,
            scopes=frozenset(self.scopes),
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            signature=self.signature,
        )


class ToolCallBody(BaseModel):
    capability: CapabilityTokenModel
    args: dict[str, str] = Field(default_factory=dict)


# Escopo exigido por ferramenta (o servidor NÃO confia no cliente para isso).
_REQUIRED_SCOPE = {
    "consultar_saldo": "saldo:read",
    "consultar_horario_agencia": "agencia:read",
}


def _authorizer() -> ToolAuthorizer:
    authorizer = _state.get("authorizer")
    if authorizer is None:  # defensivo: chamada antes do lifespan
        catalog = ToolCatalog.from_yaml(_TOOL_POLICY)
        authorizer = ToolAuthorizer(catalog=catalog)
        _state["authorizer"] = authorizer
    return authorizer  # type: ignore[return-value]


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "role": "mcp"}


@app.get("/tools")
def list_tools() -> dict[str, object]:
    """Lista as capacidades expostas (somente leitura)."""
    catalog: ToolCatalog = _state.get("catalog") or ToolCatalog.from_yaml(_TOOL_POLICY)
    return {"tools": catalog.to_dict()}


@app.post("/tools/{tool_name}")
def call_tool(tool_name: str, body: ToolCallBody) -> dict[str, object]:
    """Executa uma ferramenta APÓS verificar o capability token (§9-10).

    A verificação é feita pelo :class:`ToolAuthorizer`: assinatura, expiração,
    *confused deputy* (token atado à ferramenta), *scope creep* e read-only.
    """
    scope = _REQUIRED_SCOPE.get(tool_name, "unknown:scope")
    result = _authorizer().authorize(
        token=body.capability.to_domain(),
        tool=tool_name,
        scope=scope,
        actor=body.capability.subject,
    )
    if not result.allowed:
        # 403: a autoridade foi negada por política (não é erro do cliente HTTP).
        raise HTTPException(status_code=403, detail=result.to_dict())

    output = _run_tool(tool_name, body.args)
    result.output = output
    return {"result": result.to_dict()}


def _run_tool(tool_name: str, args: dict[str, str]) -> str:
    """Executa a lógica da ferramenta (apenas leitura de dados sintéticos)."""
    if tool_name == "consultar_saldo":
        conta_token = args.get("conta_token", "")
        return _ACCOUNTS.get(conta_token, "conta não encontrada")
    if tool_name == "consultar_horario_agencia":
        agencia = args.get("agencia", "central").lower()
        return _AGENCIES.get(agencia, "agência não encontrada")
    # Nunca deveria chegar aqui: escopo desconhecido já teria sido negado.
    raise HTTPException(status_code=404, detail={"reason": "unknown_tool", "tool": tool_name})
