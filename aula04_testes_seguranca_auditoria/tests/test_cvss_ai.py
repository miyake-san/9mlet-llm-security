"""Testes de severidade CVSS-AI (Aula 04, vídeo 3; Doc 04, seção 13)."""

from __future__ import annotations

import pytest

from app.cvss_ai import (
    cvss_ai_score,
    impact_weight,
    mitigation_effectiveness,
    risk_score,
    score_finding,
    severity_band,
)


def test_risk_score_e_produto_probabilidade_impacto():
    assert risk_score(0.5, 0.8) == pytest.approx(0.4)
    assert risk_score(1.0, 1.0) == pytest.approx(1.0)
    # clamp em [0,1]
    assert risk_score(2.0, 0.5) == pytest.approx(0.5)
    assert risk_score(-1.0, 0.5) == 0.0


def test_severity_band_por_faixa():
    assert severity_band(0.0) == "none"
    assert severity_band(2.0) == "low"
    assert severity_band(5.0) == "medium"
    assert severity_band(7.5) == "high"
    assert severity_band(9.5) == "critical"


def test_impact_weight_por_classe():
    assert impact_weight("LLM06") == 1.0  # vazamento de PII é crítico
    assert impact_weight("LLM99") == 0.5  # classe desconhecida -> default


def test_cvss_ai_score_e_severidade():
    assert cvss_ai_score("LLM06", 1.0) == 10.0
    assert severity_band(cvss_ai_score("LLM06", 1.0)) == "critical"
    assert cvss_ai_score("LLM06", 0.0) == 0.0


def test_mitigation_effectiveness():
    """E = 1 - R1/R0 (Doc 04, seção 13)."""
    assert mitigation_effectiveness(0.30, 0.0) == pytest.approx(1.0)
    assert mitigation_effectiveness(0.30, 0.15) == pytest.approx(0.5)
    assert mitigation_effectiveness(0.0, 0.0) == 0.0  # sem risco inicial


def test_score_finding_tem_esquema_estavel():
    f = score_finding("LLM01", 0.4, description="teste")
    for key in ("owasp", "asr", "impact", "score", "severity", "vector", "description"):
        assert key in f
