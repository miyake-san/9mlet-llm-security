"""Biblioteca reutilizável de conformidade — Aula 05 (LGPD/GDPR/EU AI Act).

Reúne os controles que traduzem requisitos jurídicos em engenharia verificável
(Documento 04): minimização de PII (§2), consentimento granular e versionado
(§3, Hands On), registro de tratamento WORM (§4 — art. 37), classificação de
risco EU AI Act e DPIA com R = Σ Pj·Ij (§6-8), e purga seletiva em vector store
para o direito ao esquecimento (§10). Tudo *offline-first* e determinístico por
padrão, com adaptadores de PRODUÇÃO (Presidio, PostgreSQL, Qdrant, Azure) opcionais.
"""

from __future__ import annotations

from src.security.consent import (
    ConsentStore,
    FileConsentStore,
    InMemoryConsentStore,
    PostgresConsentStore,
    build_consent_store,
)
from src.security.dpia import (
    aggregate_risk,
    classify_ai_system,
    decide,
    default_scenarios,
    dpia_to_markdown,
    run_dpia,
)
from src.security.minimization import (
    DeterministicMinimizer,
    Minimizer,
    PresidioHttpMinimizer,
    detect_pii,
    is_valid_cnpj,
    is_valid_cpf,
)
from src.security.regulations import (
    AI_ACT_OBLIGATIONS,
    DATA_SUBJECT_RIGHTS,
    FRAMEWORK_CROSSWALK,
    LEGAL_BASIS_GDPR_MAP,
    LGPD_PRINCIPLES,
    MAX_FINES,
    RESPONSIBILITY_CHAIN,
    is_special_category,
)
from src.security.schemas import (
    ConsentRecord,
    DataSubjectRequest,
    DataSubjectRight,
    DPIAResult,
    DSRStatus,
    DSRType,
    ImpactCategory,
    LegalBasis,
    MinimizationResult,
    PIIEntity,
    PIIMatch,
    PurgeResult,
    RiskScenario,
    RiskTier,
    TreatmentRecord,
    utc_now_iso,
)
from src.security.treatment import (
    TreatmentRegistry,
    build_treatment_record,
    load_treatment_policies,
    pseudonymize,
)
from src.security.vector_store import (
    InMemoryVectorStore,
    QdrantVectorStore,
    VectorRecord,
    VectorStore,
    build_vector_store,
    embed,
)

__all__ = [
    # schemas / enums
    "ConsentRecord",
    "DataSubjectRequest",
    "DataSubjectRight",
    "DPIAResult",
    "DSRStatus",
    "DSRType",
    "ImpactCategory",
    "LegalBasis",
    "MinimizationResult",
    "PIIEntity",
    "PIIMatch",
    "PurgeResult",
    "RiskScenario",
    "RiskTier",
    "TreatmentRecord",
    "utc_now_iso",
    # regulations
    "AI_ACT_OBLIGATIONS",
    "DATA_SUBJECT_RIGHTS",
    "FRAMEWORK_CROSSWALK",
    "LEGAL_BASIS_GDPR_MAP",
    "LGPD_PRINCIPLES",
    "MAX_FINES",
    "RESPONSIBILITY_CHAIN",
    "is_special_category",
    # minimization
    "DeterministicMinimizer",
    "Minimizer",
    "PresidioHttpMinimizer",
    "detect_pii",
    "is_valid_cpf",
    "is_valid_cnpj",
    # consent
    "ConsentStore",
    "InMemoryConsentStore",
    "FileConsentStore",
    "PostgresConsentStore",
    "build_consent_store",
    # treatment (RoPA / WORM)
    "TreatmentRegistry",
    "build_treatment_record",
    "load_treatment_policies",
    "pseudonymize",
    # dpia
    "run_dpia",
    "classify_ai_system",
    "aggregate_risk",
    "decide",
    "default_scenarios",
    "dpia_to_markdown",
    # vector store
    "VectorStore",
    "InMemoryVectorStore",
    "QdrantVectorStore",
    "VectorRecord",
    "build_vector_store",
    "embed",
]
