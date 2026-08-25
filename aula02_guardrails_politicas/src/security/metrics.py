"""Métricas de avaliação de guardrails — FP/FN, precisão, revocação, F1, ROC.

Implementa as métricas de trade-off da seção 8 do Documento 04. Em um banco,
o **falso negativo** (ataque que passa) é mais grave que o **falso positivo**
(pedido legítimo bloqueado) em fluxos transacionais; a curva ROC e o F1-score
ajudam a calibrar thresholds com evidência, não intuição.

$$F_1 = 2 \\cdot \\frac{precisão \\cdot revocação}{precisão + revocação}$$

Implementação em Python puro (sem sklearn) para manter o pacote ``src`` leve e
offline. Os notebooks usam matplotlib/sklearn (grupo ``dev``) só para plotar.

Referência:
    Doc 04, seção 8 (trade-off segurança × latência × custo; FP/FN; ROC; F1).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ConfusionMatrix:
    """Matriz de confusão para um classificador binário de segurança.

    Convenção: rótulo "positivo" = ataque; "predição positiva" = bloqueado.
    """

    tp: int = 0  # ataque corretamente bloqueado
    fp: int = 0  # benigno bloqueado (falso positivo)
    tn: int = 0  # benigno corretamente liberado
    fn: int = 0  # ataque que passou (falso negativo — o mais grave)

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        """Revocação = fração de ataques reais bloqueados (prioridade em banco)."""
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def fpr(self) -> float:
        """Taxa de falsos positivos (eixo x da ROC)."""
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0

    @property
    def tpr(self) -> float:
        """Taxa de verdadeiros positivos = revocação (eixo y da ROC)."""
        return self.recall

    def to_dict(self) -> dict:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "fpr": round(self.fpr, 4),
            "tpr": round(self.tpr, 4),
        }


def confusion_from_scores(
    scores: list[float],
    labels: list[int],
    threshold: float,
) -> ConfusionMatrix:
    """Constrói a matriz de confusão dado um ``threshold`` de bloqueio.

    Args:
        scores: score de risco por amostra (0-1). ``>= threshold`` = bloqueado.
        labels: 1 = ataque (deveria bloquear), 0 = benigno (deveria passar).
        threshold: ponto de corte.
    """
    if len(scores) != len(labels):
        raise ValueError("scores e labels devem ter o mesmo tamanho")
    cm = ConfusionMatrix()
    for score, label in zip(scores, labels, strict=True):
        blocked = score >= threshold
        if label == 1 and blocked:
            cm.tp += 1
        elif label == 1 and not blocked:
            cm.fn += 1
        elif label == 0 and blocked:
            cm.fp += 1
        else:
            cm.tn += 1
    return cm


def roc_points(scores: list[float], labels: list[int]) -> list[tuple[float, float]]:
    """Gera pontos ``(fpr, tpr)`` varrendo thresholds — insumo da curva ROC."""
    thresholds = sorted({*scores, 0.0, 1.0, 1.0001}, reverse=True)
    points: list[tuple[float, float]] = []
    for threshold in thresholds:
        cm = confusion_from_scores(scores, labels, threshold)
        points.append((cm.fpr, cm.tpr))
    return points


def auc(points: list[tuple[float, float]]) -> float:
    """Área sob a curva ROC pela regra do trapézio (ordenada por FPR)."""
    ordered = sorted(points)
    area = 0.0
    for (x0, y0), (x1, y1) in zip(ordered, ordered[1:], strict=False):
        area += (x1 - x0) * (y0 + y1) / 2
    return round(area, 4)


def best_threshold(
    scores: list[float],
    labels: list[int],
    beta: float = 1.0,
) -> tuple[float, float]:
    """Retorna ``(threshold, fbeta)`` que maximiza o F-beta.

    ``beta > 1`` favorece revocação (fluxo transacional); ``beta < 1`` favorece
    precisão (fluxo informativo). Doc 04, seção 8.
    """
    best = (0.5, -1.0)
    for threshold in sorted({*scores, 0.0, 1.0}):
        cm = confusion_from_scores(scores, labels, threshold)
        p, r = cm.precision, cm.recall
        denom = (beta * beta * p) + r
        fbeta = (1 + beta * beta) * p * r / denom if denom else 0.0
        if fbeta > best[1]:
            best = (threshold, round(fbeta, 4))
    return best
