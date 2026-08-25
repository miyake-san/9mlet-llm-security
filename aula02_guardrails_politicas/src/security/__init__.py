"""Biblioteca reutilizável de segurança — Aula 02 (Guardrails multi-camada).

Reúne as camadas de *defense-in-depth* do Documento 04 (Sutton, 2025):
entrada (injection/jailbreak, Llama Guard), comportamento (política Colang),
moderação (Azure AI Content Safety) e saída (Rail Spec, PII, toxicidade), além
das métricas de trade-off (FP/FN, ROC, F1).
"""

from __future__ import annotations

from .behavior_policy import BehaviorPolicy, check_behavior
from .content_safety import (
    CATEGORIES,
    AzureContentSafety,
    StubContentSafety,
    check_content_safety,
    get_content_safety,
)
from .input_guardrails import JailbreakDetector, check_input_injection
from .llama_guard import LlamaGuardClient, check_llama_guard
from .metrics import (
    ConfusionMatrix,
    auc,
    best_threshold,
    confusion_from_scores,
    roc_points,
)
from .output_guardrails import (
    BalanceResponse,
    check_output_pii,
    check_output_schema,
    check_output_toxicity,
)
from .pii import detect_pii, is_valid_cnpj, is_valid_cpf, redact_pii
from .schemas import GuardDecision, Layer, LayerResult, Verdict

__all__ = [
    # schemas
    "GuardDecision",
    "Layer",
    "LayerResult",
    "Verdict",
    # input
    "JailbreakDetector",
    "check_input_injection",
    # behavior
    "BehaviorPolicy",
    "check_behavior",
    # llama guard
    "LlamaGuardClient",
    "check_llama_guard",
    # content safety
    "CATEGORIES",
    "AzureContentSafety",
    "StubContentSafety",
    "check_content_safety",
    "get_content_safety",
    # output
    "BalanceResponse",
    "check_output_pii",
    "check_output_schema",
    "check_output_toxicity",
    # pii
    "detect_pii",
    "redact_pii",
    "is_valid_cpf",
    "is_valid_cnpj",
    # metrics
    "ConfusionMatrix",
    "confusion_from_scores",
    "roc_points",
    "auc",
    "best_threshold",
]
