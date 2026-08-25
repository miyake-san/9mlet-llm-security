"""Isolamento de ferramentas MCP com *capability tokens* (reuso da Aula 03).

O agente do capstone (Doc 04, §9) usa ferramentas via **Model Context Protocol**
com o princípio do menor privilégio da Aula 03: cada ferramenta é uma *capacidade
nomeada + escopo*, e a autoridade é verificada a CADA chamada. Este módulo
implementa o emissor/verificador de tokens e o autorizador, defendendo contra:

    * **Confused deputy** — o token é atado a UMA ferramenta; não vale para outra.
    * **Scope creep**     — o escopo exigido pelo servidor não pode ser ampliado
      pelo cliente (ex.: uma ferramenta *read-only* nunca autoriza escrita).
    * **Token expirado / adulterado** — assinatura HMAC e expiração verificadas.

Referência:
    Anthropic (2024). Model Context Protocol.
    Hardy, N. (1988). The Confused Deputy.
    OWASP Foundation (2025). Top 10 for LLM Applications — LLM07/LLM08.
    Doc 04, §9 (isolamento de ferramentas via MCP).
"""

from __future__ import annotations

import hashlib
import hmac
import time

from src.security.schemas import CapabilityToken, ToolResult

# Chave de assinatura de laboratório (em produção viria de Key Vault / env).
_LAB_SIGNING_KEY = b"aurora-mcp-lab-signing-key-nao-usar-em-producao"

# Catálogo de ferramentas expostas: nome -> escopo exigido. Apenas LEITURA.
TOOL_SCOPES: dict[str, str] = {
    "consultar_saldo": "saldo:read",
    "consultar_produto": "produto:read",
    "consultar_horario_agencia": "agencia:read",
}

# Ferramentas de ESCRITA existem no domínio do banco, mas NÃO são expostas ao
# agente (menor privilégio): qualquer tentativa é negada por política.
_FORBIDDEN_TOOLS = frozenset({"transferir", "encerrar_conta", "alterar_limite"})


def _sign(
    subject: str, tool: str, scopes: frozenset[str], issued_at: float, expires_at: float
) -> str:
    payload = f"{subject}|{tool}|{','.join(sorted(scopes))}|{issued_at}|{expires_at}".encode()
    return hmac.new(_LAB_SIGNING_KEY, payload, hashlib.sha256).hexdigest()


def issue_token(
    subject: str, tool: str, scopes: set[str] | frozenset[str], *, ttl: float = 300.0
) -> CapabilityToken:
    """Emite um capability token atado a UMA ferramenta e a escopos específicos."""
    now = time.time()
    frozen = frozenset(scopes)
    return CapabilityToken(
        subject=subject,
        tool=tool,
        scopes=frozen,
        issued_at=now,
        expires_at=now + ttl,
        signature=_sign(subject, tool, frozen, now, now + ttl),
    )


def verify_signature(token: CapabilityToken) -> bool:
    """Recalcula a assinatura HMAC e compara em tempo constante."""
    expected = _sign(token.subject, token.tool, token.scopes, token.issued_at, token.expires_at)
    return hmac.compare_digest(expected, token.signature)


class ToolAuthorizer:
    """Autoriza chamadas de ferramenta MCP verificando o token e a política.

    O servidor NÃO confia no cliente para definir o escopo: ele consulta
    :data:`TOOL_SCOPES` e exige que o token traga exatamente o escopo requerido
    para a ferramenta pedida (defesa contra *scope creep* e *confused deputy*).
    """

    def authorize(self, token: CapabilityToken, tool: str, *, actor: str) -> ToolResult:
        # 1) Ferramenta de escrita jamais é exposta ao agente (menor privilégio).
        if tool in _FORBIDDEN_TOOLS:
            return ToolResult(
                tool=tool,
                allowed=False,
                reason="ferramenta de escrita não exposta (least privilege)",
            )
        # 2) Ferramenta inexistente no catálogo.
        required = TOOL_SCOPES.get(tool)
        if required is None:
            return ToolResult(tool=tool, allowed=False, reason="ferramenta desconhecida")
        # 3) Assinatura e expiração do token.
        if not verify_signature(token):
            return ToolResult(
                tool=tool, allowed=False, reason="assinatura inválida (token adulterado)"
            )
        if token.expired:
            return ToolResult(tool=tool, allowed=False, reason="token expirado")
        # 4) Confused deputy: o token precisa ter sido emitido para ESTA ferramenta.
        if token.tool != tool:
            return ToolResult(
                tool=tool, allowed=False, reason=f"confused deputy: token para '{token.tool}'"
            )
        # 5) Scope creep: o escopo exigido pelo servidor precisa constar no token.
        if required not in token.scopes:
            return ToolResult(
                tool=tool, allowed=False, reason=f"scope creep: falta escopo '{required}'"
            )
        # 6) Sujeito coerente.
        if token.subject != actor:
            return ToolResult(tool=tool, allowed=False, reason="sujeito do token diverge do ator")
        return ToolResult(tool=tool, allowed=True, reason="autorizado")
