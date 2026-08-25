"""Suíte de regressão do quality gate ético (Doc 04, "quality gates éticos").

Fixa a linha de base: (1) o Aurora Assist SEM mitigação **reprova** o gate
(viés/alucinação); (2) a versão mitigada **passa**; (3) o relatório mantém um
esquema estável; (4) os endpoints continuam respondendo. Impede que uma
regressão de fairness/qualidade volte a passar despercebida para produção.
"""

from __future__ import annotations

from app.eval_ragas import InProcessTarget, run_evaluation


def test_gate_reprova_assistente_ingenuo():
    report = run_evaluation(InProcessTarget(mitigate_fairness=False, strict_grounding=False))
    gate = report["quality_gate"]
    assert gate["passed"] is False
    assert gate["violations"], "deveria listar as violações (viés/fidelidade)"


def test_gate_aprova_assistente_mitigado():
    report = run_evaluation(InProcessTarget(mitigate_fairness=True, strict_grounding=True))
    gate = report["quality_gate"]
    assert gate["passed"] is True, f"violações inesperadas: {gate['violations']}"


def test_mitigacao_reduz_disparidade_e_eleva_fidelidade():
    naive = run_evaluation(InProcessTarget(mitigate_fairness=False, strict_grounding=False))
    mitigated = run_evaluation(InProcessTarget(mitigate_fairness=True, strict_grounding=True))
    assert (
        mitigated["fairness"]["equal_opportunity_difference"]
        < naive["fairness"]["equal_opportunity_difference"]
    )
    assert mitigated["ragas"]["faithfulness"] > naive["ragas"]["faithfulness"]


def test_relatorio_tem_esquema_estavel():
    report = run_evaluation(InProcessTarget(mitigate_fairness=True, strict_grounding=True))
    for key in (
        "target",
        "model_version",
        "quality",
        "ragas",
        "fairness",
        "counterfactual",
        "judge",
        "quality_gate",
    ):
        assert key in report


def test_chat_endpoint_responde(client):
    body = client.post("/chat", json={"question": "Qual a taxa do CDB Aurora Prime?"}).json()
    assert "answer" in body
    assert isinstance(body["contexts"], list)


def test_decision_endpoint_responde(client):
    body = client.post(
        "/decision",
        json={"id": "cli-x", "name": "Maria", "group": "A", "qualified": 1, "income": 5000.0},
    ).json()
    assert body["outcome"] in (0, 1)
    assert body["product"]
