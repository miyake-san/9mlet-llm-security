"""Testes de classificação de risco EU AI Act e DPIA (Aula 05).

Valida a bifurcação central do §7 do Documento 04: *informar* mantém o Aurora
Assist em risco LIMITADO; incluir *decisão de crédito* o eleva a ALTO RISCO. Também
valida o cálculo de risco agregado R = Σ Pj·Ij (§7-8).
"""

from __future__ import annotations

from src.security.dpia import aggregate_risk, classify_ai_system, run_dpia
from src.security.schemas import ImpactCategory, RiskScenario, RiskTier


def test_aurora_informativo_e_risco_limitado():
    tier, obligations, _ = classify_ai_system(
        ["conversational", "informational_assistant", "balance_inquiry"]
    )
    assert tier is RiskTier.LIMITED
    assert "transparencia_ao_usuario" in obligations


def test_decisao_de_credito_eleva_para_alto_risco():
    tier, obligations, _ = classify_ai_system(["conversational", "credit_decision"])
    assert tier is RiskTier.HIGH
    assert "supervisao_humana_significativa" in obligations
    assert "dpia_obrigatoria" in obligations


def test_pratica_proibida_e_inaceitavel():
    tier, _, _ = classify_ai_system(["social_scoring"])
    assert tier is RiskTier.UNACCEPTABLE


def test_risco_agregado_normalizado_entre_0_e_1():
    scenarios = [
        RiskScenario("a", 0.1, ImpactCategory.PII_LEAK),
        RiskScenario("b", 1.0, ImpactCategory.SENSITIVE_DATA),
    ]
    r = aggregate_risk(scenarios)
    assert 0.0 <= r <= 1.0


def test_mais_probabilidade_aumenta_o_risco():
    baixo = aggregate_risk([RiskScenario("x", 0.05, ImpactCategory.PII_LEAK)])
    alto = aggregate_risk([RiskScenario("x", 0.95, ImpactCategory.PII_LEAK)])
    assert alto > baixo


def test_dpia_do_aurora_e_aceitavel_ou_mitigavel():
    result = run_dpia()
    assert result.risk_tier is RiskTier.LIMITED
    assert result.decision in {"accept", "mitigate"}
    assert result.scenarios  # cenários documentados
    assert any("unlearning" in n.lower() for n in result.residual_notes)


def test_dpia_alto_risco_com_credito():
    result = run_dpia(capabilities=["conversational", "credit_decision"])
    assert result.risk_tier is RiskTier.HIGH
    assert "dpia_obrigatoria" in result.obligations
