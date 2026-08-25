"""Utilitários de segurança reutilizáveis da Aula 01.

Módulos:
    owasp         — catálogo OWASP Top 10 for LLM Applications (2025).
    threat_model  — modelagem STRIDE→OWASP e escore de risco R = P·I.
    detectors     — heurísticas de detecção de prompt injection e PII BR
                    (precursoras dos guardrails da Aula 02 e do Presidio da Aula 03).
    redteam       — harness de replay adversarial + wrappers Garak/PyRIT.

Referência transversal:
    OWASP Foundation (2025). Top 10 for LLM Applications, v2025.
    NIST (2024). Adversarial Machine Learning — NIST AI 100-2 E2023.
"""

from src.security.owasp import OWASP_LLM_TOP10, OwaspRisk
from src.security.threat_model import STRIDE, ThreatEntry, aurora_threat_model, risk_score

__all__ = [
    "OWASP_LLM_TOP10",
    "OwaspRisk",
    "STRIDE",
    "ThreatEntry",
    "aurora_threat_model",
    "risk_score",
]
