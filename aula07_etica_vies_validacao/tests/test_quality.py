"""Testes de qualidade (Doc 04, "das métricas clássicas às neurais").

Demonstra e fixa o ponto central da aula: métricas de **superfície** (BLEU)
penalizam paráfrases corretas, enquanto a medida **semântica** reconhece
equivalência de significado. Também valida a fidelidade RAG (faithfulness).
"""

from __future__ import annotations

from app.eval_ragas import answer_relevancy, faithfulness
from src.security.quality import (
    bertscore_f1,
    bleu,
    rouge_l,
    semantic_similarity,
    token_f1,
)


def test_texto_identico_e_perfeito():
    text = "O CDB Aurora Prime rende 12% ao ano."
    assert bleu(text, text) > 0.99
    assert rouge_l(text, text) == 1.0
    assert semantic_similarity(text, text) == 1.0
    assert token_f1(text, text) == 1.0


def test_semantico_reconhece_parafrase_que_o_bleu_ignora():
    # Exemplo do Documento 04: mesma informação, palavras diferentes.
    candidate = "há cem reais disponíveis"
    reference = "seu saldo é R$ 100"
    assert bleu(candidate, reference) < 0.2, "BLEU deve penalizar a paráfrase"
    assert semantic_similarity(candidate, reference) > 0.6, "semântica deve reconhecê-la"
    assert semantic_similarity(candidate, reference) > bleu(candidate, reference)


def test_faithfulness_abstencao_e_fiel():
    # Abster-se não faz afirmação não sustentada -> faithfulness = 1.0 (RAGAS).
    assert faithfulness("Não encontrei essa informação nos documentos do Aurora.", []) == 1.0


def test_faithfulness_grounded_maior_que_alucinacao():
    contexts = ["O CDB Aurora Prime rende 12% ao ano."]
    grounded = "De acordo com os documentos, o CDB Aurora Prime rende 12% ao ano."
    hallucinated = "O consórcio de imóveis do Aurora rende 30% garantidos com bônus."
    assert faithfulness(grounded, contexts) > faithfulness(hallucinated, contexts)


def test_answer_relevancy_maior_para_resposta_pertinente():
    question = "Qual a taxa do CDB Aurora Prime?"
    on_topic = "O CDB Aurora Prime rende 12% ao ano."
    off_topic = "A agência abre às 10 horas."
    assert answer_relevancy(on_topic, question) > answer_relevancy(off_topic, question)


def test_bertscore_fallback_offline():
    # Sem o grupo `eval`, cai no proxy semântico (0..1) e não quebra o pipeline.
    scores = bertscore_f1(["seu saldo é R$ 100"], ["há cem reais disponíveis"])
    assert len(scores) == 1
    assert 0.0 <= scores[0] <= 1.0
