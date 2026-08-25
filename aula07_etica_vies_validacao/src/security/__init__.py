"""Biblioteca reutilizável de avaliação responsável (fairness + qualidade).

Expõe as implementações **puras e offline** usadas pela app, pelos notebooks e
pelos testes. As bibliotecas de referência (Fairlearn, bert-score, RAGAS) ficam
no grupo opcional ``eval`` e, quando instaladas, são usadas pelo ``eval-runner``.
"""

from src.security.fairness import (
    CounterfactualResult,
    counterfactual_report,
    counterfactual_similarity,
    demographic_parity_difference,
    equal_opportunity_difference,
    equalized_odds_difference,
    selection_rate,
    selection_rate_by_group,
)
from src.security.quality import (
    bertscore_f1,
    bleu,
    rouge_l,
    rouge_n,
    semantic_similarity,
    token_f1,
)

__all__ = [
    "CounterfactualResult",
    "counterfactual_report",
    "counterfactual_similarity",
    "demographic_parity_difference",
    "equal_opportunity_difference",
    "equalized_odds_difference",
    "selection_rate",
    "selection_rate_by_group",
    "bertscore_f1",
    "bleu",
    "rouge_l",
    "rouge_n",
    "semantic_similarity",
    "token_f1",
]
