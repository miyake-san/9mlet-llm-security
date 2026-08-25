"""Biblioteca reutilizável de LLMOps — Aula 06 (observabilidade e drift).

Reúne os controles que transformam o Documento 04 em engenharia verificável:
detecção estatística de drift (§Drift — KS/PSI/MMD/Wasserstein), observabilidade
com convenções gen_ai.* e token economics (§Observabilidade — spans, custo, cache
semântico, model routing), SLIs/SLOs/Data SLOs com error budget (§SLOs) e o
detector de PII que sustenta o Data SLO de segurança. Tudo *offline-first* e
determinístico; adaptadores de PRODUÇÃO (scipy/sklearn, OTel SDK, Langfuse,
Azure Monitor, Evidently) são opcionais.
"""

from __future__ import annotations

from src.security.drift import (
    DRIFT_DEFAULTS,
    DriftDetector,
    assess,
    detect_prompt_drift,
    detect_scalar_drift,
    embed,
    embed_matrix,
    ks_2samp,
    mmd2_rbf,
    mmd_permutation_test,
    psi,
    wasserstein_1d,
)
from src.security.metrics import (
    aggregate_slis,
    estimate_tokens,
    lexical_overlap,
    percentile,
    tokenize,
)
from src.security.observability import (
    CostModel,
    InMemoryTraceStore,
    SemanticCache,
    new_span,
    pseudonymize,
    redact_preview,
    route_model,
)
from src.security.pii import contains_pii, detect_pii, is_valid_cpf
from src.security.schemas import (
    DriftMethod,
    DriftResult,
    DriftSeverity,
    DriftType,
    FeedbackRecord,
    GenAIOperation,
    GenAISpan,
    LLMResponse,
    MaturityLevel,
    RequestMetric,
    SLODefinition,
    SLOEvaluation,
    SLOKind,
    SLOReport,
    SLOStatus,
    utc_now_iso,
)
from src.security.slo import (
    error_budget_status,
    evaluate_all,
    evaluate_slo,
    load_slo_definitions,
)

__all__ = [
    "DRIFT_DEFAULTS",
    "CostModel",
    "DriftDetector",
    "DriftMethod",
    "DriftResult",
    "DriftSeverity",
    "DriftType",
    "FeedbackRecord",
    "GenAIOperation",
    "GenAISpan",
    "InMemoryTraceStore",
    "LLMResponse",
    "MaturityLevel",
    "RequestMetric",
    "SLODefinition",
    "SLOEvaluation",
    "SLOKind",
    "SLOReport",
    "SLOStatus",
    "SemanticCache",
    "aggregate_slis",
    "assess",
    "contains_pii",
    "detect_pii",
    "detect_prompt_drift",
    "detect_scalar_drift",
    "embed",
    "embed_matrix",
    "error_budget_status",
    "estimate_tokens",
    "evaluate_all",
    "evaluate_slo",
    "is_valid_cpf",
    "ks_2samp",
    "lexical_overlap",
    "load_slo_definitions",
    "mmd2_rbf",
    "mmd_permutation_test",
    "new_span",
    "percentile",
    "psi",
    "pseudonymize",
    "redact_preview",
    "route_model",
    "tokenize",
    "utc_now_iso",
    "wasserstein_1d",
]
