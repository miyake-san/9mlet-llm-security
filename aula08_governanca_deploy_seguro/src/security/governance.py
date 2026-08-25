"""Frameworks de governança como código: NIST AI RMF, ISO/IEC 42001, EU AI Act.

Materializa o conteúdo conceitual da Videoaula 1 (Doc 04, §§1-5) em estruturas
consultáveis: o **crosswalk** que conecta cada função/controle de governança aos
controles técnicos construídos nas Aulas 1-7, e o **modelo de maturidade** de IA
responsável. Governança deixa de ser documento na gaveta e vira artefato
verificável (Doc 04, §10).

Frameworks cobertos:
    * NIST AI RMF 1.0 (AI 100-1): funções Govern, Map, Measure, Manage
      (+ Generative AI Profile, NIST AI 600-1).
    * ISO/IEC 42001:2023 (AIMS): ciclo PDCA + controles do Anexo A.
    * EU AI Act (Reg. (UE) 2024/1689): obrigações por papel (provider/deployer/GPAI).

Referência:
    NIST (2023). AI Risk Management Framework 1.0. · NIST (2024). AI 600-1 (GenAI Profile).
    ISO/IEC (2023). 42001:2023 (AI Management System).
    União Europeia (2024). Regulation (EU) 2024/1689 (AI Act).
    Williams, B. (2024). AI Strategy and Security (modelos de maturidade).
    Doc 04, §§1-5.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# --------------------------------------------------------------------------- #
# NIST AI RMF — 4 funções e o mapeamento para as aulas (Doc 04, §2)            #
# --------------------------------------------------------------------------- #
@dataclass
class NISTFunction:
    fid: str
    name: str
    description: str
    course_lessons: list[str] = field(default_factory=list)
    controls: list[str] = field(default_factory=list)


NIST_AI_RMF: dict[str, NISTFunction] = {
    "GOVERN": NISTFunction(
        "GOVERN",
        "Govern",
        "Cultura e políticas de risco; transversal às demais funções (Doc 04, §2).",
        course_lessons=["Aula 05", "Aula 08"],
        controls=[
            "políticas de IA",
            "papéis e responsabilidades",
            "apetite de risco",
            "comitê de risco",
        ],
    ),
    "MAP": NISTFunction(
        "MAP",
        "Map",
        "Contextualiza e identifica riscos do sistema de IA (Doc 04, §2).",
        course_lessons=["Aula 01"],
        controls=["modelagem de ameaças STRIDE/LINDDUN", "OWASP Top 10 LLM", "MITRE ATLAS"],
    ),
    "MEASURE": NISTFunction(
        "MEASURE",
        "Measure",
        "Avalia e quantifica os riscos identificados (Doc 04, §2).",
        course_lessons=["Aula 04", "Aula 07"],
        controls=[
            "red teaming (PyRIT/Garak)",
            "avaliação de viés (Fairlearn)",
            "RAGAS/quality gates",
        ],
    ),
    "MANAGE": NISTFunction(
        "MANAGE",
        "Manage",
        "Prioriza e trata os riscos (Doc 04, §2).",
        course_lessons=["Aula 02", "Aula 03", "Aula 06"],
        controls=[
            "guardrails multi-camada",
            "proteção de dados / MCP isolado",
            "observabilidade / SLO",
        ],
    ),
}

# Generative AI Profile (NIST AI 600-1) — riscos generativos tratados no curso.
NIST_GENAI_PROFILE_RISKS = (
    "prompt injection (LLM01)",
    "vazamento de informação sensível (LLM06)",
    "alucinação / desinformação (LLM09)",
    "viés e representação",
)


# --------------------------------------------------------------------------- #
# ISO/IEC 42001 — ciclo PDCA aplicado ao Aurora Assist (Doc 04, §3)            #
# --------------------------------------------------------------------------- #
ISO42001_PDCA: dict[str, dict] = {
    "PLAN": {
        "description": "Política de IA, apetite de risco, escopo e critérios de aprovação.",
        "lessons": ["Aula 05", "Aula 08"],
    },
    "DO": {
        "description": "Implementa guardrails, AIBOM, proteção de dados e pipeline DevSecOps.",
        "lessons": ["Aula 02", "Aula 03", "Aula 08"],
    },
    "CHECK": {
        "description": "Auditoria, red teaming, avaliação de qualidade e revisão de incidentes.",
        "lessons": ["Aula 04", "Aula 07"],
    },
    "ACT": {
        "description": "Corrige lacunas, atualiza políticas e reabre avaliações de risco.",
        "lessons": ["Aula 06", "Aula 08"],
    },
}

# Anexo A (subconjunto didático) — controles certificáveis (Doc 04, §3).
ISO42001_ANNEX_A = (
    "A.2 Políticas de IA",
    "A.4 Recursos para sistemas de IA",
    "A.6 Ciclo de vida do sistema de IA",
    "A.7 Dados para sistemas de IA",
    "A.8 Informação para partes interessadas",
    "A.9 Uso responsável do sistema de IA",
)


# --------------------------------------------------------------------------- #
# EU AI Act — obrigações por papel (Doc 04, §4)                                #
# --------------------------------------------------------------------------- #
EU_AI_ACT_ROLES: dict[str, dict] = {
    "provider": {
        "description": "Desenvolve/coloca o sistema no mercado; maior fardo de obrigações.",
        "obligations": [
            "documentação técnica",
            "avaliação de conformidade",
            "registro",
            "gestão de risco",
        ],
        "aurora_when": "se o Banco Aurora fizer fine-tuning que modifique o sistema.",
    },
    "deployer": {
        "description": "Usa o sistema em contexto profissional; deveres de uso adequado.",
        "obligations": [
            "supervisão humana",
            "transparência ao cliente",
            "uso conforme a finalidade",
        ],
        "aurora_when": "se o Banco Aurora apenas utiliza um modelo fundacional de terceiro.",
    },
    "gpai": {
        "description": "GPAI (fundacionais); obrigações reforçadas se risco sistêmico.",
        "obligations": [
            "documentação do modelo",
            "sumário de dados de treino",
            "avaliação de risco sistêmico",
        ],
        "aurora_when": "aplica-se ao fornecedor do modelo base usado pelo Aurora Assist.",
    },
}


# --------------------------------------------------------------------------- #
# Modelo de maturidade de IA responsável (Doc 04, §5)                          #
# --------------------------------------------------------------------------- #
MATURITY_LEVELS = ("ad-hoc", "repetível", "definido", "gerenciado", "otimizado")


def assess_maturity(signals: dict[str, bool]) -> dict:
    """Diagnóstico simples de maturidade (Microsoft RAI / BCG — Doc 04, §5).

    ``signals`` indica evidências presentes (política, inventário/AIBOM, papéis,
    SLOs/auditoria, automação/aprendizado contínuo). O nível é o maior patamar
    cujas evidências acumuladas estão satisfeitas — refletindo que maturidade não
    é só tecnologia, mas processos e pessoas.
    """
    ladder = [
        ("ad-hoc", []),
        ("repetível", ["checklists"]),
        ("definido", ["checklists", "policy", "roles"]),
        ("gerenciado", ["checklists", "policy", "roles", "slos", "audit"]),
        (
            "otimizado",
            ["checklists", "policy", "roles", "slos", "audit", "automation", "continuous_learning"],
        ),
    ]
    level = "ad-hoc"
    for name, required in ladder:
        if all(signals.get(key, False) for key in required):
            level = name
    missing = {
        name: [k for k in required if not signals.get(k, False)]
        for name, required in ladder
        if name in MATURITY_LEVELS
    }
    return {"level": level, "levels": list(MATURITY_LEVELS), "gaps": missing.get("otimizado", [])}


def build_crosswalk() -> dict:
    """Crosswalk consolidado: frameworks ↔ controles do curso (Doc 04, §§2-4, 10)."""
    return {
        "nist_ai_rmf": {
            fid: {
                "name": fn.name,
                "description": fn.description,
                "course_lessons": fn.course_lessons,
                "controls": fn.controls,
            }
            for fid, fn in NIST_AI_RMF.items()
        },
        "nist_genai_profile_risks": list(NIST_GENAI_PROFILE_RISKS),
        "iso_42001_pdca": ISO42001_PDCA,
        "iso_42001_annex_a": list(ISO42001_ANNEX_A),
        "eu_ai_act_roles": EU_AI_ACT_ROLES,
        "maturity_levels": list(MATURITY_LEVELS),
    }


def coverage_report() -> dict:
    """Verifica se as 4 funções do NIST AI RMF têm cobertura de controles/aulas.

    Usado pelo *deploy gate* (Doc 04, §9): nenhuma promoção sem governança
    demonstrável — todas as funções precisam mapear ao menos um controle e uma aula.
    """
    covered = {
        fid: bool(fn.controls) and bool(fn.course_lessons) for fid, fn in NIST_AI_RMF.items()
    }
    return {
        "functions": covered,
        "complete": all(covered.values()),
        "uncovered": [fid for fid, ok in covered.items() if not ok],
    }
