"""Testes do LLM-as-Judge (Doc 04, "LLM-as-Judge e seus vieses").

Demonstra e fixa os vieses documentados por Zheng et al. (2023) e suas
mitigações: alternância de posição e agregação por consenso.
"""

from __future__ import annotations

from app.judge import Judge

_Q = "Qual a taxa do CDB Aurora Prime?"
_CTX = ["O CDB Aurora Prime rende 12% ao ano."]


def test_ensemble_score_na_escala():
    judge = Judge(ensemble_size=3)
    score = judge.ensemble_score(_Q, "O CDB Aurora Prime rende 12% ao ano.", _CTX)
    assert 1.0 <= score <= 5.0


def test_score_premia_resposta_fundamentada():
    judge = Judge()
    good = "O CDB Aurora Prime rende 12% ao ano."
    off_topic = "A agência abre às dez horas."
    assert judge.score(_Q, good, _CTX) > judge.score(_Q, off_topic, _CTX)


def test_position_bias_sem_debias_favorece_o_primeiro():
    biased = Judge(position_debias=False)
    answer = "O CDB Aurora Prime rende 12% ao ano."
    # Respostas equivalentes: só a POSIÇÃO deveria decidir (viés).
    verdict = biased.pairwise(_Q, answer, answer)
    assert verdict.winner == "A"
    assert biased.position_bias_delta(_Q, answer, answer) > 0.10


def test_position_bias_com_debias_fica_estavel():
    debiased = Judge(position_debias=True)
    answer = "O CDB Aurora Prime rende 12% ao ano."
    verdict = debiased.pairwise(_Q, answer, answer)
    assert verdict.winner == "tie"
    assert debiased.position_bias_delta(_Q, answer, answer) == 0.0


def test_verbosity_bias_infla_resposta_longa():
    judge = Judge()
    short = "O CDB rende 12% ao ano."
    long = "O CDB Aurora Prime rende 12% ao ano. " * 6
    assert judge.verbosity_bias_delta(_Q, short, long) > 0.0
