"""Testes de governança (crosswalk NIST/ISO/EU AI Act) e AIBOM (Doc 04, §§2-8)."""

from __future__ import annotations

from src.security.aibom import aibom_completeness, build_aibom
from src.security.governance import (
    NIST_AI_RMF,
    assess_maturity,
    build_crosswalk,
    coverage_report,
)


# --------------------------------------------------------------------------- #
# Crosswalk de governança                                                      #
# --------------------------------------------------------------------------- #
def test_nist_rmf_tem_quatro_funcoes():
    assert set(NIST_AI_RMF) == {"GOVERN", "MAP", "MEASURE", "MANAGE"}


def test_cobertura_de_governanca_completa():
    report = coverage_report()
    assert report["complete"] is True
    assert report["uncovered"] == []


def test_crosswalk_conecta_frameworks_e_aulas():
    crosswalk = build_crosswalk()
    assert "nist_ai_rmf" in crosswalk
    assert "iso_42001_pdca" in crosswalk
    assert "eu_ai_act_roles" in crosswalk
    # Cada função do NIST mapeia ao menos uma aula do curso.
    for fn in crosswalk["nist_ai_rmf"].values():
        assert fn["course_lessons"]


def test_maturidade_progride_com_evidencias():
    ad_hoc = assess_maturity({})
    otimizado = assess_maturity(
        {
            "checklists": True,
            "policy": True,
            "roles": True,
            "slos": True,
            "audit": True,
            "automation": True,
            "continuous_learning": True,
        }
    )
    assert ad_hoc["level"] == "ad-hoc"
    assert otimizado["level"] == "otimizado"


# --------------------------------------------------------------------------- #
# AIBOM (CycloneDX ML-BOM)                                                     #
# --------------------------------------------------------------------------- #
def test_aibom_formato_cyclonedx():
    aibom = build_aibom()
    assert aibom["bomFormat"] == "CycloneDX"
    assert aibom["specVersion"]
    assert aibom["components"]


def test_aibom_completo_tem_modelo_dados_e_deps():
    check = aibom_completeness(build_aibom())
    assert check["complete"] is True
    assert check["checks"]["has_base_model"] is True
    assert check["checks"]["has_datasets"] is True
    assert check["checks"]["has_dependencies"] is True


def test_aibom_incompleto_e_detectado():
    incompleto = {"components": [{"type": "library", "name": "fastapi"}]}
    check = aibom_completeness(incompleto)
    assert check["complete"] is False
