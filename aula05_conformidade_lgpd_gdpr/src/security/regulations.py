"""Mapeamento normativo LGPD ↔ GDPR ↔ EU AI Act (Aula 05).

Codifica, como dados verificáveis, os marcos discutidos no Documento 04: os dez
princípios da LGPD (§2 — art. 6), a correspondência entre bases legais LGPD/GDPR
(§2, §5), os direitos do titular (§3 — arts. 17-22), a cadeia de responsabilidade
controlador/operador/DPO (§3) e o mapeamento cruzado de obrigações por framework
(§8, MERCADO). Serve de referência única para código e notebooks — evitando que
constantes jurídicas fiquem espalhadas e divergentes.

Referência:
    BRASIL (2018). LGPD (Lei 13.709). · UNIÃO EUROPEIA (2016). GDPR.
    UNIÃO EUROPEIA (2024). EU AI Act. · NIST (2023). AI RMF 1.0.
"""

from __future__ import annotations

from src.security.schemas import DataSubjectRight, LegalBasis, RiskTier

# --- Os dez princípios da LGPD (art. 6) — Doc 04, §2 --------------------------
LGPD_PRINCIPLES: list[str] = [
    "finalidade",
    "adequacao",
    "necessidade",  # minimização — conecta ao Presidio da Aula 03
    "livre_acesso",
    "qualidade_dos_dados",
    "transparencia",
    "seguranca",
    "prevencao",
    "nao_discriminacao",
    "responsabilizacao",  # accountability — art. 37
]

# --- Correspondência de base legal LGPD -> GDPR (Doc 04, §2, §5) --------------
LEGAL_BASIS_GDPR_MAP: dict[LegalBasis, str] = {
    LegalBasis.CONSENT: "GDPR art. 6(1)(a) — consent",
    LegalBasis.CONTRACT: "GDPR art. 6(1)(b) — contract",
    LegalBasis.LEGAL_OBLIGATION: "GDPR art. 6(1)(c) — legal obligation",
    LegalBasis.VITAL_INTEREST: "GDPR art. 6(1)(d) — vital interests",
    LegalBasis.PUBLIC_INTEREST: "GDPR art. 6(1)(e) — public task",
    LegalBasis.LEGITIMATE_INTEREST: "GDPR art. 6(1)(f) — legitimate interests",
    LegalBasis.CREDIT_PROTECTION: "(sem equivalente direto no GDPR)",
}

# --- Direito do titular -> artigo (LGPD) / equivalente GDPR (Doc 04, §3) ------
DATA_SUBJECT_RIGHTS: dict[DataSubjectRight, dict[str, str]] = {
    DataSubjectRight.CONFIRMATION_ACCESS: {
        "lgpd": "art. 18, I-II",
        "gdpr": "art. 15",
        "desc": "Confirmação e acesso aos dados.",
    },
    DataSubjectRight.CORRECTION: {
        "lgpd": "art. 18, III",
        "gdpr": "art. 16",
        "desc": "Correção de dados incompletos.",
    },
    DataSubjectRight.DELETION: {
        "lgpd": "art. 18, VI",
        "gdpr": "art. 17",
        "desc": "Eliminação (direito ao esquecimento).",
    },
    DataSubjectRight.PORTABILITY: {
        "lgpd": "art. 18, V",
        "gdpr": "art. 20",
        "desc": "Portabilidade dos dados.",
    },
    DataSubjectRight.INFORMATION_SHARING: {
        "lgpd": "art. 18, VII",
        "gdpr": "art. 19",
        "desc": "Info sobre compartilhamentos.",
    },
    DataSubjectRight.CONSENT_REVOCATION: {
        "lgpd": "art. 18, IX",
        "gdpr": "art. 7(3)",
        "desc": "Revogação do consentimento.",
    },
    DataSubjectRight.AUTOMATED_DECISION_REVIEW: {
        "lgpd": "art. 20",
        "gdpr": "art. 22",
        "desc": "Revisão de decisão automatizada.",
    },
}

# --- Cadeia de responsabilidade (Doc 04, §3) ---------------------------------
RESPONSIBILITY_CHAIN: dict[str, str] = {
    "controlador": "Decide sobre o tratamento e responde por ele (o Banco Aurora).",
    "operador": "Processa dados em nome do controlador (nuvem / provedor do modelo).",
    "encarregado_dpo": "Canal entre empresa, titulares e ANPD (Data Protection Officer).",
}

# --- Dados sensíveis (LGPD art. 11) — exigem base reforçada -------------------
SPECIAL_CATEGORY_HINTS: tuple[str, ...] = (
    "saude",
    "biometria",
    "genetic",
    "religia",
    "conviccao",
    "orientacao sexual",
    "filiacao sindical",
    "origem racial",
    "opiniao politica",
)

# --- Mapeamento cruzado de obrigações por framework (Doc 04, §8) --------------
FRAMEWORK_CROSSWALK: dict[str, dict[str, str]] = {
    "registro_de_tratamento": {
        "lgpd": "art. 37",
        "gdpr": "art. 30",
        "eu_ai_act": "logs automáticos (alto risco)",
        "nist_ai_rmf": "MEASURE/MANAGE",
    },
    "avaliacao_de_impacto": {
        "lgpd": "RIPD (art. 38)",
        "gdpr": "DPIA (art. 35)",
        "eu_ai_act": "sistema de gestão de risco",
        "nist_ai_rmf": "MAP",
    },
    "privacy_by_design": {
        "lgpd": "art. 46 (segurança)",
        "gdpr": "art. 25",
        "eu_ai_act": "data governance",
        "nist_ai_rmf": "GOVERN",
    },
    "decisao_automatizada": {
        "lgpd": "art. 20",
        "gdpr": "art. 22",
        "eu_ai_act": "supervisão humana",
        "nist_ai_rmf": "human-AI configuration",
    },
    "transparencia": {
        "lgpd": "art. 6, VI",
        "gdpr": "arts. 13-14",
        "eu_ai_act": "art. 50 (informar que é IA)",
        "nist_ai_rmf": "GOVERN/MAP",
    },
}

# --- Multas máximas (Doc 04, §1) ---------------------------------------------
MAX_FINES: dict[str, str] = {
    "lgpd": "2% do faturamento, limitado a R$ 50 milhões por infração (art. 52).",
    "gdpr": "até 4% do faturamento global anual (art. 83).",
    "eu_ai_act": "até 7% do faturamento global para práticas proibidas.",
}

# --- Obrigações por nível de risco EU AI Act (Doc 04, §6) --------------------
AI_ACT_OBLIGATIONS: dict[RiskTier, list[str]] = {
    RiskTier.UNACCEPTABLE: ["proibicao_total"],
    RiskTier.HIGH: [
        "sistema_gestao_de_risco",
        "documentacao_tecnica_extensa",
        "supervisao_humana_significativa",
        "registro_automatico_de_logs",
        "avaliacao_de_conformidade",
        "dpia_obrigatoria",
    ],
    RiskTier.LIMITED: ["transparencia_ao_usuario", "documentacao_minima"],
    RiskTier.MINIMAL: [],
}


def is_special_category(text: str) -> bool:
    """Heurística: o texto sugere dado sensível (art. 11)? — Doc 04, §2."""
    low = text.lower()
    return any(hint in low for hint in SPECIAL_CATEGORY_HINTS)
