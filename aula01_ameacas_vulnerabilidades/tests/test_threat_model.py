"""Testa o catálogo OWASP, o mapeamento STRIDE→OWASP e o escore de risco R = P·I."""

from __future__ import annotations

import pytest

from src.security.owasp import OWASP_LLM_TOP10, get_risk
from src.security.threat_model import (
    STRIDE,
    aurora_threat_model,
    risk_score,
    stride_to_owasp,
    validate_owasp_ids,
)


def test_catalogo_tem_dez_classes():
    assert len(OWASP_LLM_TOP10) == 10
    assert set(OWASP_LLM_TOP10) == {f"LLM{n:02d}" for n in range(1, 11)}


def test_get_risk_normaliza_e_valida():
    assert get_risk("llm01").id == "LLM01"
    assert get_risk("LLM06").name_pt.startswith("Divulgação")
    with pytest.raises(KeyError):
        get_risk("LLM99")


def test_risk_score_faixas():
    # R = P·I (Doc 04, seção 10); faixas de configs/thresholds.yaml.
    assert risk_score("alto", "alto").value == 9
    assert risk_score("alto", "alto").band == "alto"
    assert risk_score("baixo", "baixo").band == "baixo"
    assert risk_score("medio", "medio").value == 4
    assert risk_score("medio", "medio").band == "medio"


def test_risk_score_nivel_invalido():
    with pytest.raises(ValueError):
        risk_score("altíssimo", "alto")


def test_modelo_mapeia_para_owasp_valido():
    validate_owasp_ids()  # não deve levantar
    modelo = aurora_threat_model()
    assert any(e.owasp == "LLM06" for e in modelo)
    assert STRIDE.INFORMATION_DISCLOSURE in stride_to_owasp()


def test_quadrante_alto_alto_pii_e_injecao_indireta():
    # Figura 4 do Doc 04: vazamento de PII e injeção indireta no quadrante alto-alto.
    por_stride = {e.stride: e for e in aurora_threat_model()}
    assert por_stride[STRIDE.INFORMATION_DISCLOSURE].risk.band == "alto"
    assert por_stride[STRIDE.TAMPERING].risk.band == "alto"
