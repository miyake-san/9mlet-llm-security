"""Utilitários de segurança reutilizáveis da Aula 04.

Módulos:
    detectors    — guardrail de superfície (heurística) + de-ofuscação (mitigação).
    hash_chain   — trilha de auditoria imutável (h_i = H(h_{i-1} ‖ log_i)).
    merkle       — raiz de Merkle para verificação de integridade em lote.
    metrics      — ASR, taxa de bloqueio e efetividade de mitigação (E = 1 - R1/R0).
    redteam      — harness de campanha single-turn + crescendo + wrappers Garak/PyRIT/promptfoo.

Referência transversal:
    Microsoft (2024). PyRIT / Lessons from Red Teaming 100 GenAI Products.
    Merkle, R. C. (1988). CRYPTO '87.
    ISO/IEC 27001:2022 · ISO/IEC 42001:2023 · NIST AI RMF 1.0 (2023).
"""

from src.security.detectors import (
    detect_injection,
    detect_pii,
    is_injection,
    is_injection_normalized,
    normalize_obfuscation,
)
from src.security.hash_chain import ChainEntry, HashChain, VerifyResult, compute_hash, genesis_hash
from src.security.merkle import merkle_root
from src.security.metrics import (
    attack_success_rate,
    block_rate,
    mitigation_effectiveness,
    summarize_latency,
)
from src.security.redteam import (
    SYSTEM_PROMPT_CANARY,
    Attack,
    CampaignResult,
    CrescendoAttack,
    HttpTarget,
    judge_success,
    load_attacks,
    load_benign,
    load_crescendo,
    run_campaign,
)

__all__ = [
    # detectors
    "detect_injection",
    "detect_pii",
    "is_injection",
    "is_injection_normalized",
    "normalize_obfuscation",
    # audit
    "ChainEntry",
    "HashChain",
    "VerifyResult",
    "compute_hash",
    "genesis_hash",
    "merkle_root",
    # metrics
    "attack_success_rate",
    "block_rate",
    "mitigation_effectiveness",
    "summarize_latency",
    # redteam
    "SYSTEM_PROMPT_CANARY",
    "Attack",
    "CampaignResult",
    "CrescendoAttack",
    "HttpTarget",
    "judge_success",
    "load_attacks",
    "load_benign",
    "load_crescendo",
    "run_campaign",
]
