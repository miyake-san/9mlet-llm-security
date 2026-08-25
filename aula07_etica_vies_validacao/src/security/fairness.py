"""Métricas de *fairness* de grupo e teste contrafactual (Doc 04).

Implementação **pura e offline** das definições estatísticas de justiça
sistematizadas por Hardt, Price e Srebro (2016) e do teste de *counterfactual
fairness* (Kusner et al., 2017). A API espelha deliberadamente a do **Fairlearn**
(``demographic_parity_difference(y_true, y_pred, sensitive_features=...)``) para
que a troca pela biblioteca real (grupo ``eval``) seja transparente.

Nenhuma dessas funções treina modelos: elas medem a **disparidade** entre grupos
sobre decisões já produzidas pelo Aurora Assist, convertendo "parece justo" em
"a disparidade é de X" — a quantificação exigida pela IA Responsável.

Referência:
    Hardt, M.; Price, E.; Srebro, N. (2016). Equality of Opportunity. NeurIPS. arXiv:1610.02413.
    Chouldechova, A. (2017). Fair Prediction with Disparate Impact. Big Data.
    Kusner, M. et al. (2017). Counterfactual Fairness. NeurIPS. arXiv:1703.06856.
    Bird, S. et al. (2020). Fairlearn. Microsoft MSR-TR-2020-32.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from src.security.quality import semantic_similarity

Label = int


def _validate(y_true: Sequence[Label], y_pred: Sequence[Label], groups: Sequence[str]) -> None:
    if not (len(y_true) == len(y_pred) == len(groups)):
        raise ValueError("y_true, y_pred e sensitive_features devem ter o mesmo tamanho.")


def selection_rate(y_pred: Sequence[Label]) -> float:
    """Taxa de resultado positivo P(Ŷ=1). Vazio -> 0.0."""
    return sum(1 for p in y_pred if p == 1) / len(y_pred) if y_pred else 0.0


def selection_rate_by_group(
    y_pred: Sequence[Label], sensitive_features: Sequence[str]
) -> dict[str, float]:
    """Taxa de seleção por grupo protegido (base da paridade demográfica)."""
    buckets: dict[str, list[Label]] = {}
    for pred, group in zip(y_pred, sensitive_features, strict=True):
        buckets.setdefault(group, []).append(pred)
    return {g: round(selection_rate(preds), 4) for g, preds in buckets.items()}


def demographic_parity_difference(
    y_true: Sequence[Label],
    y_pred: Sequence[Label],
    *,
    sensitive_features: Sequence[str],
) -> float:
    """Diferença de paridade demográfica: max - min das taxas de seleção.

    P(Ŷ=1 | A=a) deve ser igual entre grupos (Doc 04). ``y_true`` não é usado —
    mantido na assinatura por paridade com o Fairlearn. 0.0 = paridade perfeita.
    """
    _validate(y_true, y_pred, sensitive_features)
    rates = list(selection_rate_by_group(y_pred, sensitive_features).values())
    return round(max(rates) - min(rates), 4) if rates else 0.0


def _rate_conditioned(
    y_true: Sequence[Label],
    y_pred: Sequence[Label],
    groups: Sequence[str],
    *,
    condition: Label,
) -> dict[str, float]:
    """Taxa de Ŷ=1 por grupo, condicionada a Y=``condition`` (TPR se 1; FPR se 0)."""
    buckets: dict[str, list[Label]] = {}
    for true, pred, group in zip(y_true, y_pred, groups, strict=True):
        if true == condition:
            buckets.setdefault(group, []).append(pred)
    return {g: selection_rate(preds) for g, preds in buckets.items() if preds}


def equal_opportunity_difference(
    y_true: Sequence[Label],
    y_pred: Sequence[Label],
    *,
    sensitive_features: Sequence[str],
) -> float:
    """Diferença de igualdade de oportunidade: max - min do TPR entre grupos.

    P(Ŷ=1 | A=a, Y=1) igual entre grupos (Hardt et al., 2016). É a métrica
    priorizada no ``thresholds.yaml``: não negar benefício a quem qualifica.
    """
    _validate(y_true, y_pred, sensitive_features)
    tpr = list(_rate_conditioned(y_true, y_pred, sensitive_features, condition=1).values())
    return round(max(tpr) - min(tpr), 4) if len(tpr) >= 2 else 0.0


def equalized_odds_difference(
    y_true: Sequence[Label],
    y_pred: Sequence[Label],
    *,
    sensitive_features: Sequence[str],
) -> float:
    """Diferença de chances equalizadas: max(ΔTPR, ΔFPR) entre grupos."""
    _validate(y_true, y_pred, sensitive_features)
    tpr = list(_rate_conditioned(y_true, y_pred, sensitive_features, condition=1).values())
    fpr = list(_rate_conditioned(y_true, y_pred, sensitive_features, condition=0).values())
    d_tpr = (max(tpr) - min(tpr)) if len(tpr) >= 2 else 0.0
    d_fpr = (max(fpr) - min(fpr)) if len(fpr) >= 2 else 0.0
    return round(max(d_tpr, d_fpr), 4)


# --------------------------------------------------------------------------- #
# Teste contrafactual (específico de LLMs generativos)                         #
# --------------------------------------------------------------------------- #
def counterfactual_similarity(response_a: str, response_b: str) -> float:
    """Similaridade semântica entre respostas de perfis idênticos (só o atributo
    protegido muda). Baixa similaridade -> viés contrafactual (Kusner et al., 2017).
    """
    return semantic_similarity(response_a, response_b)


@dataclass
class CounterfactualResult:
    """Resultado agregado de uma auditoria contrafactual (Doc 04, Snippet 1)."""

    threshold: float
    total_pairs: int = 0
    violations: int = 0
    similarities: list[float] = field(default_factory=list)

    @property
    def mean_similarity(self) -> float:
        if not self.similarities:
            return 0.0
        return round(sum(self.similarities) / len(self.similarities), 4)

    @property
    def min_similarity(self) -> float:
        return round(min(self.similarities), 4) if self.similarities else 0.0

    @property
    def violation_rate(self) -> float:
        return round(self.violations / self.total_pairs, 4) if self.total_pairs else 0.0


def counterfactual_report(
    pairs: Sequence[tuple[str, str]], *, threshold: float = 0.90
) -> CounterfactualResult:
    """Audita pares (resp_a, resp_b), contando quantos ficam abaixo do limiar.

    Args:
        pairs: respostas pareadas do assistente para perfis idênticos que diferem
            apenas no atributo protegido (ex.: nome "João" vs "Maria").
        threshold: similaridade mínima aceitável (Doc 04 sugere ~0.95).
    """
    result = CounterfactualResult(threshold=threshold)
    for resp_a, resp_b in pairs:
        sim = counterfactual_similarity(resp_a, resp_b)
        result.similarities.append(sim)
        result.total_pairs += 1
        if sim < threshold:
            result.violations += 1
    return result
