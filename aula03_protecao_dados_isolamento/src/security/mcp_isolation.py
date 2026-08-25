"""Isolamento de ferramentas via capability tokens (Aula 03 — Doc 04, §9-10).

Implementa a defesa estrutural contra os ataques do *Saiba Mais* §9:

- **Confused deputy** (Hardy, 1988): um agente com autoridade legítima é enganado
  para usá-la em benefício do atacante. Aqui, um *capability token* emitido para a
  ferramenta ``consultar_saldo`` **não** vale para nenhuma outra ferramenta.
- **Scope creep**: o token concede APENAS o escopo mínimo necessário; escopos não
  concedidos são recusados, ainda que a ferramenta os suporte.
- **Prompt-as-payload**: a autorização não depende do texto do prompt, mas de um
  token assinado (HMAC) e verificável.

Combina o padrão *policy-as-code* (catálogo de capacidades em YAML) com uma
**trilha de auditoria append-only** (§12): cada decisão de autorização é registrada.

Referência:
    Hardy, N. (1988). The Confused Deputy.
    Anthropic (2024). Model Context Protocol (MCP).
    OWASP Foundation (2025). Top 10 for LLM Applications — LLM07/LLM08.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from pathlib import Path

import yaml

from src.security.schemas import (
    AuditEntry,
    CapabilityToken,
    ToolCallResult,
    ToolCapability,
)


# --------------------------------------------------------------------------- #
# Assinatura e emissão de capability tokens (HMAC)
# --------------------------------------------------------------------------- #
def sign_payload(payload: str, secret: str) -> str:
    """Assina o corpo canônico do token com HMAC-SHA256."""
    return hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def issue_capability(
    subject: str,
    tool: str,
    scopes: set[str] | frozenset[str],
    secret: str | None = None,
    ttl_seconds: float | None = None,
    now: float | None = None,
) -> CapabilityToken:
    """Emite um capability token de escopo MÍNIMO e vida CURTA (menor privilégio)."""
    secret = secret or os.getenv("MCP_CAPABILITY_SECRET", "dev-capability-secret")
    ttl = ttl_seconds if ttl_seconds is not None else float(os.getenv("MCP_CAPABILITY_TTL", "120"))
    issued = now if now is not None else time.time()
    token = CapabilityToken(
        subject=subject,
        tool=tool,
        scopes=frozenset(scopes),
        issued_at=issued,
        expires_at=issued + ttl,
    )
    signature = sign_payload(token.payload(), secret)
    return CapabilityToken(
        subject=token.subject,
        tool=token.tool,
        scopes=token.scopes,
        issued_at=token.issued_at,
        expires_at=token.expires_at,
        signature=signature,
    )


def verify_signature(token: CapabilityToken, secret: str | None = None) -> bool:
    """Verifica o HMAC do token (comparação em tempo constante)."""
    secret = secret or os.getenv("MCP_CAPABILITY_SECRET", "dev-capability-secret")
    expected = sign_payload(token.payload(), secret)
    return hmac.compare_digest(expected, token.signature)


# --------------------------------------------------------------------------- #
# Catálogo de capacidades (policy-as-code) e trilha de auditoria
# --------------------------------------------------------------------------- #
class ToolCatalog:
    """Catálogo de ferramentas expostas e seus escopos MÍNIMOS (Doc 04, §10)."""

    def __init__(self, capabilities: dict[str, ToolCapability]) -> None:
        self._caps = capabilities

    @classmethod
    def from_yaml(cls, path: str | Path) -> ToolCatalog:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        caps: dict[str, ToolCapability] = {}
        for name, cfg in (raw.get("tools") or {}).items():
            caps[name] = ToolCapability(
                name=name,
                scopes=frozenset(cfg.get("scopes", [])),
                read_only=bool(cfg.get("read_only", True)),
                description=cfg.get("description", ""),
            )
        return cls(caps)

    def get(self, name: str) -> ToolCapability | None:
        return self._caps.get(name)

    def names(self) -> list[str]:
        return sorted(self._caps)

    def to_dict(self) -> dict:
        return {
            name: {
                "scopes": sorted(cap.scopes),
                "read_only": cap.read_only,
                "description": cap.description,
            }
            for name, cap in self._caps.items()
        }


class AuditTrail:
    """Trilha append-only das decisões de autorização (Doc 04, §12)."""

    def __init__(self, sink: str | Path | None = None) -> None:
        self._entries: list[AuditEntry] = []
        self._sink = Path(sink) if sink else None

    def log(
        self,
        actor: str,
        tool: str,
        action: str,
        scope: str | None = None,
        reason: str = "",
        **details: object,
    ) -> AuditEntry:
        entry = AuditEntry(
            actor=actor, tool=tool, action=action, scope=scope, reason=reason, details=details
        )
        self._entries.append(entry)
        if self._sink is not None:
            self._sink.parent.mkdir(parents=True, exist_ok=True)
            with self._sink.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")
        return entry

    @property
    def entries(self) -> list[AuditEntry]:
        return list(self._entries)


# --------------------------------------------------------------------------- #
# Autorização de chamadas de ferramenta
# --------------------------------------------------------------------------- #
# Escopos considerados de ESCRITA (jamais permitidos em ferramentas read-only).
_WRITE_SCOPES = {"write", "transfer", "delete", "update", "admin"}


class ToolAuthorizer:
    """Aplica menor privilégio a cada chamada de ferramenta (defense-in-depth)."""

    def __init__(
        self,
        catalog: ToolCatalog,
        secret: str | None = None,
        audit: AuditTrail | None = None,
    ) -> None:
        self.catalog = catalog
        self.secret = secret or os.getenv("MCP_CAPABILITY_SECRET", "dev-capability-secret")
        self.audit = audit or AuditTrail()

    def authorize(
        self,
        token: CapabilityToken,
        tool: str,
        scope: str,
        actor: str = "aurora-assist",
        now: float | None = None,
    ) -> ToolCallResult:
        """Autoriza (ou nega) uma chamada, registrando a decisão na trilha."""

        def deny(reason: str) -> ToolCallResult:
            self.audit.log(actor, tool, "deny", scope=scope, reason=reason)
            return ToolCallResult(allowed=False, tool=tool, scope=scope, reason=reason)

        # 1) Integridade: assinatura do token deve bater (anti-forjamento).
        if not verify_signature(token, self.secret):
            return deny("invalid_signature")

        # 2) Validade temporal: tokens são de vida curta (menor janela de abuso).
        if token.is_expired(now):
            return deny("expired_token")

        # 3) Confused deputy: o token é atado À FERRAMENTA para a qual foi emitido.
        if token.tool != tool:
            return deny("confused_deputy")

        # 4) A ferramenta precisa existir no catálogo (allowlist explícita).
        capability = self.catalog.get(tool)
        if capability is None:
            return deny("unknown_tool")

        # 5) A ferramenta precisa SUPORTAR o escopo pedido.
        if not capability.covers(scope):
            return deny("scope_not_supported")

        # 6) Scope creep: o token precisa CONCEDER exatamente aquele escopo.
        if not token.grants(scope):
            return deny("scope_creep")

        # 7) Read-only estrutural: nenhuma escrita em ferramenta somente leitura.
        if capability.read_only and _is_write_scope(scope):
            return deny("write_denied_on_readonly_tool")

        self.audit.log(actor, tool, "allow", scope=scope, reason="ok")
        return ToolCallResult(allowed=True, tool=tool, scope=scope, reason="ok")


def _is_write_scope(scope: str) -> bool:
    """Um escopo é de escrita se seu verbo (após ':') estiver na lista de escrita."""
    verb = scope.split(":")[-1].lower()
    return verb in _WRITE_SCOPES
