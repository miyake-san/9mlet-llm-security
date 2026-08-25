"""Servidor de ferramentas MCP ISOLADO + cliente in-process (reuso da Aula 03).

Expõe **apenas** capacidades de LEITURA do Banco Aurora, verificando um
*capability token* a cada chamada (menor privilégio). No ``docker-compose.yml``
este serviço roda em **rede interna sem egress** e *hardened*: mesmo comprometido,
não alcança recursos fora do escopo. O agente usa o :class:`LocalToolClient`
in-process (offline-first) ou, em produção, o servidor HTTP.

Referência:
    Anthropic (2024). Model Context Protocol.
    OWASP Foundation (2025). Top 10 for LLM Applications — LLM07/LLM08.
    Doc 04, §9 (isolamento de ferramentas via MCP).
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from src.security.mcp import TOOL_SCOPES, ToolAuthorizer, issue_token
from src.security.schemas import CapabilityToken, ToolResult

# --- Dados SINTÉTICOS das ferramentas (fictícios; jamais dados reais) --------
_ACCOUNTS: dict[str, str] = {
    "tok-conta-0001": "R$ 12.340,55",
    "tok-conta-0002": "R$ 987,10",
    "tok-conta-0003": "R$ 45.008,00",
}
_PRODUCTS: dict[str, str] = {
    "cdb_prime": "CDB Aurora Prime: rende 12% ao ano; aplicação mínima R$ 1.000.",
    "poupanca": "Poupança Aurora: rende 0,5% ao mês; isenta de IR; liquidez diária.",
}
_AGENCIES: dict[str, str] = {"central": "Seg-Sex 10h-16h", "paulista": "Seg-Sex 09h-15h"}


def run_tool(tool: str, args: dict[str, str]) -> str:
    """Executa a lógica da ferramenta (apenas leitura de dados sintéticos)."""
    if tool == "consultar_saldo":
        return _ACCOUNTS.get(args.get("conta_token", ""), "conta não encontrada")
    if tool == "consultar_produto":
        return _PRODUCTS.get(args.get("produto", ""), "produto não encontrado")
    if tool == "consultar_horario_agencia":
        return _AGENCIES.get(args.get("agencia", ""), "agência não encontrada")
    return "ferramenta não implementada"


class LocalToolClient:
    """Cliente in-process: emite o token, autoriza e executa (offline-first)."""

    def __init__(self, subject: str = "aurora-agent") -> None:
        self.subject = subject
        self._authorizer = ToolAuthorizer()

    def call(self, tool: str, args: dict[str, str]) -> ToolResult:
        scope = TOOL_SCOPES.get(tool, "unknown:scope")
        token = issue_token(self.subject, tool, {scope})
        result = self._authorizer.authorize(token, tool, actor=self.subject)
        if result.allowed:
            result.output = run_tool(tool, args)
        return result


# --------------------------------------------------------------------------- #
# Servidor HTTP (serviço `mcp-server` do compose — rede interna sem egress)     #
# --------------------------------------------------------------------------- #
mcp_app = FastAPI(
    title="Aurora Assist — MCP tool server (isolado)",
    description="Aula 08 — ferramentas MCP com menor privilégio (least privilege).",
    version="1.0.0",
)
_authorizer = ToolAuthorizer()


class CapabilityTokenModel(BaseModel):
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


@mcp_app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "role": "mcp"}


@mcp_app.get("/")
def root() -> dict[str, object]:
    return {"service": "aurora-mcp-server", "tools": sorted(TOOL_SCOPES)}


@mcp_app.get("/tools")
def list_tools() -> dict[str, object]:
    """Lista as capacidades expostas (somente leitura)."""
    return {"tools": [{"name": name, "scope": scope} for name, scope in TOOL_SCOPES.items()]}


@mcp_app.post("/tools/{tool_name}")
def call_tool(tool_name: str, body: ToolCallBody) -> dict[str, object]:
    """Executa uma ferramenta APÓS verificar o capability token (menor privilégio)."""
    result = _authorizer.authorize(
        body.capability.to_domain(), tool_name, actor=body.capability.subject
    )
    if not result.allowed:
        raise HTTPException(status_code=403, detail=result.to_dict())
    result.output = run_tool(tool_name, body.args)
    return {"result": {**result.to_dict(), "output": result.output}}
