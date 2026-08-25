"""Isolamento de ferramentas por capability tokens (Aula 03 — Doc 04, §9-10).

Valida a defesa ESTRUTURAL contra *confused deputy*, *scope creep*, tokens
forjados/expirados e escrita em ferramenta somente-leitura.
"""

from __future__ import annotations

import dataclasses

from src.security import ToolAuthorizer, ToolCatalog, issue_capability
from src.security.schemas import ToolCapability
from tests.conftest import CAP_SECRET


def _cap(tool: str, scopes: set[str], ttl: float = 120.0):
    return issue_capability(
        tool=tool, subject="tester", scopes=scopes, secret=CAP_SECRET, ttl_seconds=ttl
    )


def test_valid_capability_allows_readonly(authorizer: ToolAuthorizer):
    token = _cap("consultar_saldo", {"saldo:read"})
    result = authorizer.authorize(token, "consultar_saldo", "saldo:read")
    assert result.allowed


def test_confused_deputy_is_blocked(authorizer: ToolAuthorizer):
    # Token emitido para consultar_saldo NÃO vale para outra ferramenta.
    token = _cap("consultar_saldo", {"saldo:read"})
    result = authorizer.authorize(token, "consultar_horario_agencia", "agencia:read")
    assert not result.allowed
    assert result.reason == "confused_deputy"


def test_scope_creep_is_blocked(authorizer: ToolAuthorizer):
    # Token sem o escopo pedido (mesmo que a ferramenta o suporte) -> negado.
    token = _cap("consultar_saldo", set())
    result = authorizer.authorize(token, "consultar_saldo", "saldo:read")
    assert not result.allowed
    assert result.reason == "scope_creep"


def test_forged_signature_is_blocked(authorizer: ToolAuthorizer):
    token = _cap("consultar_saldo", {"saldo:read"})
    tampered = dataclasses.replace(token, signature="deadbeefdeadbeef")
    result = authorizer.authorize(tampered, "consultar_saldo", "saldo:read")
    assert not result.allowed
    assert result.reason == "invalid_signature"


def test_expired_token_is_blocked(authorizer: ToolAuthorizer):
    token = _cap("consultar_saldo", {"saldo:read"}, ttl=-1.0)  # já expirado
    result = authorizer.authorize(token, "consultar_saldo", "saldo:read")
    assert not result.allowed
    assert result.reason == "expired_token"


def test_unknown_tool_is_blocked(authorizer: ToolAuthorizer):
    # Ferramenta fora do catálogo (ex.: "transferir") — allowlist explícita.
    token = _cap("transferir", {"transfer:write"})
    result = authorizer.authorize(token, "transferir", "transfer:write")
    assert not result.allowed
    assert result.reason == "unknown_tool"


def test_write_scope_denied_on_readonly_tool():
    # Ferramenta read-only que (por erro) exponha escopo de escrita: negado.
    catalog = ToolCatalog(
        {"x": ToolCapability(name="x", scopes=frozenset({"x:write"}), read_only=True)}
    )
    authorizer = ToolAuthorizer(catalog=catalog, secret=CAP_SECRET)
    token = _cap("x", {"x:write"})
    result = authorizer.authorize(token, "x", "x:write")
    assert not result.allowed
    assert result.reason == "write_denied_on_readonly_tool"


def test_audit_trail_records_decisions(authorizer: ToolAuthorizer):
    authorizer.authorize(_cap("consultar_saldo", {"saldo:read"}), "consultar_saldo", "saldo:read")
    authorizer.authorize(_cap("consultar_saldo", {"saldo:read"}), "transferir", "transfer:write")
    actions = {entry.action for entry in authorizer.audit.entries}
    assert {"allow", "deny"} <= actions
