"""Modelagem de ameaças aplicada ao Aurora Assist (STRIDE → OWASP) e escore de risco.

Implementa os conceitos das seções 2 e 10 do Documento 04:
    * STRIDE (Microsoft) como vocabulário comum entre engenharia, segurança e
      jurídico (Shostack, 2014);
    * a Tabela 1 do Doc 04 (STRIDE aplicado ao Aurora Assist);
    * a formulação de risco R(t) = P(t) · I(t) (Doc 04, seção 10; NIST, 2024).

Referência:
    Shostack, A. (2014). Threat Modeling: Designing for Security. Wiley.
    NIST (2024). Adversarial Machine Learning — NIST AI 100-2 E2023.
    OWASP Foundation (2025). Top 10 for LLM Applications, v2025.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from src.security.owasp import OWASP_LLM_TOP10

# Escala qualitativa compartilhada com configs/thresholds.yaml.
_LEVELS: dict[str, int] = {"baixo": 1, "medio": 2, "alto": 3}


class STRIDE(StrEnum):
    """Categorias STRIDE (Microsoft) para classificação de ameaças."""

    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


@dataclass(frozen=True)
class ThreatEntry:
    """Uma linha da modelagem de ameaças do Aurora Assist.

    Attributes:
        stride: categoria STRIDE.
        example: exemplo concreto no Aurora Assist (Doc 04, Tabela 1).
        impact: impacto provável descrito em linguagem de negócio.
        owasp: classe OWASP Top 10 for LLM correspondente.
        probability: probabilidade qualitativa ('baixo'|'medio'|'alto').
        severity: impacto qualitativo ('baixo'|'medio'|'alto').
    """

    stride: STRIDE
    example: str
    impact: str
    owasp: str
    probability: str
    severity: str

    @property
    def risk(self) -> RiskScore:
        """Escore de risco R = P · I desta ameaça."""
        return risk_score(self.probability, self.severity)


@dataclass(frozen=True)
class RiskScore:
    """Resultado de R(t) = P(t) · I(t) com faixa de severidade (Doc 04, seção 10)."""

    probability: int
    impact: int
    value: int
    band: str


def risk_score(probability: str, impact: str) -> RiskScore:
    """Calcula R = P · I e classifica em faixa (baixo/medio/alto).

    Implementa a formulação R(t) = P(t) · I(t) discutida na seção 10 do
    Documento 04. As faixas seguem configs/thresholds.yaml:
    1–3 = baixo, 4–5 = medio, 6–9 = alto.

    Args:
        probability: 'baixo' | 'medio' | 'alto'.
        impact: 'baixo' | 'medio' | 'alto'.

    Returns:
        RiskScore com o produto numérico e a faixa qualitativa.

    Raises:
        ValueError: se um nível qualitativo for inválido.
    """
    try:
        p = _LEVELS[probability.strip().lower()]
        i = _LEVELS[impact.strip().lower()]
    except KeyError as exc:  # limite de entrada: validar aqui
        raise ValueError(
            f"Nível inválido {exc.args[0]!r}; use 'baixo', 'medio' ou 'alto'."
        ) from None
    value = p * i
    if value <= 3:
        band = "baixo"
    elif value <= 5:
        band = "medio"
    else:
        band = "alto"
    return RiskScore(probability=p, impact=i, value=value, band=band)


def aurora_threat_model() -> list[ThreatEntry]:
    """Modelo de ameaças de referência do Aurora Assist (Doc 04, Tabela 1).

    A matriz probabilidade × impacto reproduz a Figura 4 do Documento 04:
    prompt injection direta e vazamento de PII no quadrante alto-alto; roubo
    de modelo com impacto alto e probabilidade média; Model DoS em faixa média.
    """
    return [
        ThreatEntry(
            STRIDE.SPOOFING,
            "Usuário tenta assumir a identidade de outro cliente.",
            "Acesso indevido e fraude.",
            "LLM01",
            probability="medio",
            severity="alto",
        ),
        ThreatEntry(
            STRIDE.TAMPERING,
            "Documento de RAG contém instrução oculta (injeção indireta).",
            "Resposta manipulada.",
            "LLM01",
            probability="alto",
            severity="alto",
        ),
        ThreatEntry(
            STRIDE.INFORMATION_DISCLOSURE,
            "Assistente revela saldo ou CPF de terceiros.",
            "Incidente LGPD e dano reputacional.",
            "LLM06",
            probability="alto",
            severity="alto",
        ),
        ThreatEntry(
            STRIDE.DENIAL_OF_SERVICE,
            "Atacante envia prompts longos e caros.",
            "Indisponibilidade e aumento de custo.",
            "LLM04",
            probability="medio",
            severity="medio",
        ),
        ThreatEntry(
            STRIDE.ELEVATION_OF_PRIVILEGE,
            "Prompt induz a ferramenta além da permissão (confused deputy).",
            "Ação financeira não autorizada.",
            "LLM08",
            probability="medio",
            severity="alto",
        ),
        ThreatEntry(
            STRIDE.REPUDIATION,
            "Ausência de trilha de auditoria da decisão automatizada.",
            "Dificuldade de responsabilização e forense.",
            "LLM10",
            probability="baixo",
            severity="medio",
        ),
    ]


def stride_to_owasp() -> dict[STRIDE, str]:
    """Mapa STRIDE → classe OWASP dominante, derivado do modelo de referência."""
    mapping: dict[STRIDE, str] = {}
    for entry in aurora_threat_model():
        mapping.setdefault(entry.stride, entry.owasp)
    return mapping


def validate_owasp_ids() -> None:
    """Garante que todas as classes citadas no modelo existem no catálogo 2025."""
    for entry in aurora_threat_model():
        if entry.owasp not in OWASP_LLM_TOP10:
            raise ValueError(f"Classe OWASP inválida no modelo: {entry.owasp!r}")
