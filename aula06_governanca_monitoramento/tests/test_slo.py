"""Testes de SLIs/SLOs/Data SLOs e error budget (Aula 06 — Doc 04, §SLOs).

Valida a leitura das definições (configs/slo.yaml), a avaliação contra valores
medidos (HEALTHY/AT_RISK/VIOLATED), o Data SLO de segurança (PII) e a mecânica de
error budget que transforma confiabilidade em grandeza gerenciável.
"""

from __future__ import annotations

from src.security.metrics import aggregate_slis
from src.security.schemas import RequestMetric, SLOStatus
from src.security.slo import (
    error_budget_status,
    evaluate_all,
    load_slo_definitions,
)

_HEALTHY = {
    "latency_ms_p95": 850.0,
    "groundedness_ratio_regulated": 0.97,
    "jailbreak_block_rate": 0.99,
    "cost_usd_avg": 0.012,
    "knowledge_age_seconds": 3600.0,
    "pii_leak_rate": 0.0,
}
_VIOLATED = {
    "latency_ms_p95": 2600.0,
    "groundedness_ratio_regulated": 0.80,
    "jailbreak_block_rate": 0.90,
    "cost_usd_avg": 0.11,
    "knowledge_age_seconds": 90000.0,
    "pii_leak_rate": 0.03,
}


def test_carrega_definicoes_de_slo():
    defs = load_slo_definitions()
    ids = {d.id for d in defs}
    assert {"latency_p95", "pii_leak_rate", "knowledge_freshness"} <= ids
    assert len(defs) >= 6


def test_cenario_saudavel_sem_violacoes():
    report = evaluate_all(load_slo_definitions(), _HEALTHY)
    assert report.all_healthy is True
    assert report.violated == []


def test_cenario_violado_sinaliza_latencia_e_pii():
    report = evaluate_all(load_slo_definitions(), _VIOLATED)
    violated_ids = {e.slo_id for e in report.violated}
    assert "latency_p95" in violated_ids
    assert "pii_leak_rate" in violated_ids


def test_data_slo_de_pii_e_estrito():
    defs = {d.id: d for d in load_slo_definitions()}
    pii = defs["pii_leak_rate"]
    assert pii.is_met(0.0) is True
    assert pii.is_met(0.02) is False  # acima de 1% viola


def test_error_budget_latencia_e_pii():
    defs = {d.id: d for d in load_slo_definitions()}
    latency = error_budget_status(defs["latency_p95"], violation_rate=0.02)
    assert latency["exhausted"] is False  # dentro do orçamento (5%)
    latency_bad = error_budget_status(defs["latency_p95"], violation_rate=0.10)
    assert latency_bad["exhausted"] is True
    # PII tem orçamento zero: qualquer violação esgota.
    pii = error_budget_status(defs["pii_leak_rate"], violation_rate=0.005)
    assert pii["exhausted"] is True


def test_aggregate_slis_from_metrics():
    metrics = [
        RequestMetric(
            latency_ms=100, output_tokens=30, cost_usd=0.001, groundedness=0.9, regulated=True
        ),
        RequestMetric(
            latency_ms=200, output_tokens=40, cost_usd=0.002, groundedness=0.8, regulated=True
        ),
        RequestMetric(latency_ms=150, output_tokens=20, cost_usd=0.001, pii_leak=True),
    ]
    slis = aggregate_slis(metrics)
    assert slis["request_count"] == 3
    assert 0.0 < slis["pii_leak_rate"] <= 1.0
    assert slis["latency_ms_p95"] >= 150


def test_slo_report_endpoint(client):
    for msg in ("Qual a taxa do CDB?", "Como abrir conta?", "Horário da agência?"):
        client.post("/chat", json={"message": msg})
    report = client.get("/slo/report").json()
    assert "slis" in report and "report" in report
    assert "evaluations" in report["report"]
    # O relatório deve avaliar ao menos os SLOs com SLI disponível.
    assert len(report["report"]["evaluations"]) >= 5


def test_status_at_risk_perto_do_limite():
    defs = {d.id: d for d in load_slo_definitions()}
    # latência exatamente na meta (2000ms) -> AT_RISK (dentro da banda de 5%).
    from src.security.slo import evaluate_slo

    ev = evaluate_slo(defs["latency_p95"], 2000.0)
    assert ev.status is SLOStatus.AT_RISK
