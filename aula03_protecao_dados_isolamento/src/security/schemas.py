"""Esquemas compartilhados da proteção de dados e isolamento (Aula 03).

Define os tipos que trafegam pelo pipeline **Zero Trust** do Documento 04:
entidades de PII detectadas (§5-6), resultado de anonimização reversível (§7),
capacidades e *capability tokens* de ferramentas (§9-10) e entradas de trilha de
auditoria (§12 — canais laterais / logs).

Referência:
    Stafford, V. (2020). NIST SP 800-207 — Zero Trust Architecture.
    Anthropic (2024). Model Context Protocol (MCP).
    OWASP Foundation (2025). Top 10 for LLM Applications — LLM06/LLM07/LLM08.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import StrEnum


class PIIEntity(StrEnum):
    """Entidades de PII reconhecidas pelo pipeline (recognizers BR + genéricos)."""

    BR_CPF = "BR_CPF"                # Cadastro de Pessoa Física
    BR_CNPJ = "BR_CNPJ"             # Cadastro Nacional da Pessoa Jurídica
    BR_RG = "BR_RG"                 # Registro Geral (identidade)
    BR_CEP = "BR_CEP"               # Código de Endereçamento Postal
    BR_ACCOUNT = "BR_ACCOUNT"       # número de conta bancária (agência/conta)
    EMAIL_ADDRESS = "EMAIL_ADDRESS"
    PHONE_NUMBER = "PHONE_NUMBER"
    CREDIT_CARD = "CREDIT_CARD"
    PERSON = "PERSON"               # nome de pessoa (NER)


class Operator(StrEnum):
    """Operadores de anonimização (Doc 04, §5-7)."""

    TOKENIZE = "tokenize"   # substitui por token REVERSÍVEL (cofre) — §7
    MASK = "mask"           # mascara parte dos dígitos (irreversível)
    REDACT = "redact"       # remove por completo
    HASH = "hash"           # pseudonimização irreversível (HMAC)


@dataclass(frozen=True)
class PIIMatch:
    """Ocorrência de PII detectada no texto."""

    entity: PIIEntity
    text: str
    start: int
    end: int
    score: float = 1.0

    def to_dict(self) -> dict:
        return {
            "entity": self.entity.value,
            "text": self.text,
            "start": self.start,
            "end": self.end,
            "score": round(self.score, 4),
        }


@dataclass
class AnonymizationResult:
    """Resultado da anonimização de um texto (ingress do pipeline — Doc 04, §7)."""

    text: str                                   # texto anonimizado (o que o LLM vê)
    matches: list[PIIMatch] = field(default_factory=list)
    reversible_tokens: list[str] = field(default_factory=list)
    minimized: list[PIIMatch] = field(default_factory=list)  # PII removida por minimização

    @property
    def entities_found(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for match in self.matches:
            counts[match.entity.value] = counts.get(match.entity.value, 0) + 1
        return counts

    @property
    def has_pii(self) -> bool:
        return bool(self.matches)

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "entities_found": self.entities_found,
            "reversible_tokens": self.reversible_tokens,
            "minimized": [m.entity.value for m in self.minimized],
            "matches": [m.to_dict() for m in self.matches],
        }


# --------------------------------------------------------------------------- #
# Isolamento de ferramentas (Doc 04, §9-10)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ToolCapability:
    """Capacidade EXATA de uma ferramenta (menor privilégio — Doc 04, §10).

    ``read_only`` reforça, na definição, que a ferramenta jamais escreve/transfere:
    é a defesa estrutural contra o *confused deputy* do §9 (a de saldo não
    transfere porque a CAPACIDADE de transferir simplesmente não existe).
    """

    name: str
    scopes: frozenset[str]
    read_only: bool = True
    description: str = ""

    def covers(self, scope: str) -> bool:
        return scope in self.scopes


@dataclass(frozen=True)
class CapabilityToken:
    """Token de capacidade assinado (HMAC) — concede escopo mínimo e temporário."""

    subject: str                 # quem porta o token (ex.: sessão autenticada)
    tool: str                    # ferramenta-alvo
    scopes: frozenset[str]       # escopos concedidos (subconjunto do necessário)
    issued_at: float
    expires_at: float
    signature: str = ""

    def is_expired(self, now: float | None = None) -> bool:
        return (now or time.time()) >= self.expires_at

    def grants(self, scope: str) -> bool:
        return scope in self.scopes

    def payload(self) -> str:
        """Corpo canônico assinado (ordem estável para verificação do HMAC)."""
        scopes = ",".join(sorted(self.scopes))
        return f"{self.subject}|{self.tool}|{scopes}|{self.issued_at:.0f}|{self.expires_at:.0f}"


@dataclass
class ToolCallResult:
    """Resultado de uma tentativa de chamada de ferramenta (auditável)."""

    allowed: bool
    tool: str
    reason: str = ""
    output: str | None = None
    scope: str | None = None
    latency_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "tool": self.tool,
            "scope": self.scope,
            "reason": self.reason,
            "output": self.output,
            "latency_ms": round(self.latency_ms, 3),
        }


@dataclass
class AuditEntry:
    """Entrada append-only da trilha de auditoria (Doc 04, §12).

    A trilha é ela própria um controle de segurança: registra CADA decisão de
    autorização de ferramenta, permitindo *due diligence* (aprofundado na Aula 04).
    """

    actor: str
    tool: str
    action: str                  # "allow" | "deny"
    scope: str | None = None
    reason: str = ""
    timestamp: float = field(default_factory=time.time)
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "timestamp": round(self.timestamp, 3),
            "actor": self.actor,
            "tool": self.tool,
            "action": self.action,
            "scope": self.scope,
            "reason": self.reason,
            "details": self.details,
        }
