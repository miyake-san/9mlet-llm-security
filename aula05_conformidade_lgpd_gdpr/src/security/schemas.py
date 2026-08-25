"""Esquemas compartilhados da camada de conformidade (Aula 05).

Define os tipos que traduzem requisitos jurídicos em estruturas de engenharia
verificáveis (Doc 04): bases legais e direitos do titular da LGPD (§2-3), níveis
de risco do EU AI Act (§6-7), registro de tratamento / RoPA (§4), DPIA e cálculo
de risco R = Σ Pj·Ij (§7-8), solicitações do titular (DSR) e resultado da purga
seletiva em vector store (§10).

Referência:
    BRASIL (2018). Lei nº 13.709 (LGPD) — arts. 6, 7, 11, 17-22, 37.
    UNIÃO EUROPEIA (2016). GDPR — arts. 6, 22, 25, 30, 35.
    UNIÃO EUROPEIA (2024). EU AI Act (Regulation EU 2024/1689).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


def utc_now_iso() -> str:
    """Timestamp ISO-8601 em UTC (proveniência do registro de tratamento)."""
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


# --------------------------------------------------------------------------- #
# Enums regulatórios                                                           #
# --------------------------------------------------------------------------- #
class LegalBasis(StrEnum):
    """Bases legais para tratamento de dados (LGPD art. 7; GDPR art. 6)."""

    CONSENT = "consentimento"  # art. 7, I  / GDPR 6(1)(a)
    CONTRACT = "execucao_contrato"  # art. 7, V  / GDPR 6(1)(b)
    LEGAL_OBLIGATION = "obrigacao_legal"  # art. 7, II / GDPR 6(1)(c)
    VITAL_INTEREST = "protecao_da_vida"  # art. 7, VII/ GDPR 6(1)(d)
    PUBLIC_INTEREST = "politica_publica"  # art. 7, III/ GDPR 6(1)(e)
    LEGITIMATE_INTEREST = "legitimo_interesse"  # art. 7, IX / GDPR 6(1)(f)
    CREDIT_PROTECTION = "protecao_ao_credito"  # art. 7, X (específico da LGPD)


class DataSubjectRight(StrEnum):
    """Direitos do titular (LGPD arts. 17-22)."""

    CONFIRMATION_ACCESS = "confirmacao_e_acesso"  # art. 18, I e II
    CORRECTION = "correcao"  # art. 18, III
    DELETION = "eliminacao"  # art. 18, VI (esquecimento)
    PORTABILITY = "portabilidade"  # art. 18, V
    INFORMATION_SHARING = "informacao_compartilhamento"  # art. 18, VII
    CONSENT_REVOCATION = "revogacao_consentimento"  # art. 18, IX
    AUTOMATED_DECISION_REVIEW = "revisao_decisao_automatizada"  # art. 20 / GDPR 22


class RiskTier(StrEnum):
    """Pirâmide de risco do EU AI Act (Regulation EU 2024/1689)."""

    UNACCEPTABLE = "unacceptable"
    HIGH = "high"
    LIMITED = "limited"
    MINIMAL = "minimal"


class DSRType(StrEnum):
    """Tipos de solicitação do titular (Data Subject Request)."""

    ACCESS = "access"  # confirmação e acesso (art. 18, I-II)
    ERASURE = "erasure"  # eliminação / direito ao esquecimento (art. 18, VI)
    RECTIFICATION = "rectification"
    PORTABILITY = "portability"
    REVIEW = "review"  # revisão de decisão automatizada (art. 20)


class DSRStatus(StrEnum):
    """Ciclo de vida de uma DSR."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    REJECTED = "rejected"


class PIIEntity(StrEnum):
    """Entidades de PII reconhecidas na minimização (recognizers BR + genéricos)."""

    BR_CPF = "BR_CPF"
    BR_CNPJ = "BR_CNPJ"
    BR_RG = "BR_RG"
    BR_CEP = "BR_CEP"
    BR_ACCOUNT = "BR_ACCOUNT"
    EMAIL_ADDRESS = "EMAIL_ADDRESS"
    PHONE_NUMBER = "PHONE_NUMBER"
    CREDIT_CARD = "CREDIT_CARD"
    PERSON = "PERSON"


class ImpactCategory(StrEnum):
    """Categorias de dano usadas para ponderar o impacto na DPIA (Doc 04, §7)."""

    PII_LEAK = "pii_leak"
    SENSITIVE_DATA = "sensitive_data"
    AUTOMATED_DECISION = "automated_decision"
    UNLAWFUL_BASIS = "unlawful_basis"
    RETENTION_EXCESS = "retention_excess"
    CROSS_BORDER = "cross_border"


# --------------------------------------------------------------------------- #
# Modelos de domínio (dataclasses serializáveis)                               #
# --------------------------------------------------------------------------- #
@dataclass
class ConsentRecord:
    """Consentimento granular e versionado (Doc 04, Hands On / §3).

    Cada escolha do titular gera um documento auditável e revogável. O
    versionamento responde à pergunta do auditor: *qual versão dos termos o
    titular aceitou, e quando?*
    """

    subject_id: str
    purposes: dict[str, bool] = field(default_factory=dict)
    terms_version: str = "2026-06-v1"
    timestamp: str = field(default_factory=utc_now_iso)
    revocable: bool = True
    revoked: bool = False
    version: int = 1

    def allows(self, purpose: str) -> bool:
        """True se o titular consentiu com a finalidade e não revogou."""
        return (not self.revoked) and bool(self.purposes.get(purpose, False))

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> ConsentRecord:
        return cls(
            subject_id=data["subject_id"],
            purposes=dict(data.get("purposes", {})),
            terms_version=data.get("terms_version", "2026-06-v1"),
            timestamp=data.get("timestamp", utc_now_iso()),
            revocable=bool(data.get("revocable", True)),
            revoked=bool(data.get("revoked", False)),
            version=int(data.get("version", 1)),
        )


@dataclass
class TreatmentRecord:
    """Registro de operação de tratamento (LGPD art. 37 / GDPR art. 30).

    Contém APENAS metadados (Doc 04, §4 — minimização): nunca o conteúdo bruto.
    """

    operation: str
    legal_basis: str
    data_categories: list[str]
    retention_days: int
    transferred_to: str
    subject_ref: str  # id pseudonimizado (não o dado real)
    special_category: bool = False
    gdpr_basis: str = ""
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RiskScenario:
    """Cenário de risco j: probabilidade Pj e categoria de impacto (Doc 04, §7)."""

    name: str
    probability: float  # Pj ∈ [0, 1]
    impact: ImpactCategory
    description: str = ""
    mitigation: str = ""

    def to_dict(self) -> dict:
        data = asdict(self)
        data["impact"] = self.impact.value
        return data


@dataclass
class DPIAResult:
    """Resultado de uma DPIA/RIPD (GDPR art. 35; Doc 04, §8)."""

    system_name: str
    risk_tier: RiskTier
    obligations: list[str]
    scenarios: list[RiskScenario]
    aggregate_risk: float  # R = Σ Pj·Ij normalizado (0-1)
    decision: str  # accept | mitigate | high_risk_review
    residual_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "system_name": self.system_name,
            "risk_tier": self.risk_tier.value,
            "obligations": list(self.obligations),
            "scenarios": [s.to_dict() for s in self.scenarios],
            "aggregate_risk": round(self.aggregate_risk, 4),
            "decision": self.decision,
            "residual_notes": list(self.residual_notes),
        }


@dataclass(frozen=True)
class PIIMatch:
    """Ocorrência de PII detectada (minimização — Doc 04, §2)."""

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
class MinimizationResult:
    """Resultado da minimização de PII de um texto (o que o modelo vê)."""

    text: str
    matches: list[PIIMatch] = field(default_factory=list)

    @property
    def removed(self) -> int:
        return len(self.matches)


@dataclass
class DataSubjectRequest:
    """Solicitação do titular (DSR) — acesso, exclusão, revisão etc."""

    request_id: str
    subject_id: str
    dsr_type: DSRType
    status: DSRStatus = DSRStatus.PENDING
    created_at: str = field(default_factory=utc_now_iso)
    resolved_at: str | None = None
    note: str = ""

    def to_dict(self) -> dict:
        data = asdict(self)
        data["dsr_type"] = self.dsr_type.value
        data["status"] = self.status.value
        return data

    @classmethod
    def from_dict(cls, data: dict) -> DataSubjectRequest:
        return cls(
            request_id=data["request_id"],
            subject_id=data["subject_id"],
            dsr_type=DSRType(data["dsr_type"]),
            status=DSRStatus(data.get("status", "pending")),
            created_at=data.get("created_at", utc_now_iso()),
            resolved_at=data.get("resolved_at"),
            note=data.get("note", ""),
        )


@dataclass
class PurgeResult:
    """Resultado da purga seletiva no vector store (direito ao esquecimento)."""

    subject_id: str
    store: str
    deleted_count: int
    doc_ids: list[str] = field(default_factory=list)
    model_unlearning_note: str = (
        "Purga na camada de RECUPERAÇÃO concluída. O conhecimento absorvido em "
        "fine-tuning NÃO é endereçável por delete (Doc 04, §10 — machine "
        "unlearning aproximado). Limite registrado no DPIA."
    )

    def to_dict(self) -> dict:
        return asdict(self)
