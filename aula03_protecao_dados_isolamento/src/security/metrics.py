"""Métricas de avaliação da detecção de PII — precisão, revocação, F1 (Aula 03).

Reaproveita o princípio quantitativo da Aula 02 (trade-off FN/FP), agora aplicado
ao **dado** em vez do fluxo (Doc 04, §6): um detector que erra muito é tão
perigoso quanto a ausência de detector, pois gera falsa sensação de segurança.

- **Falso negativo (FN):** PII real NÃO detectada → vaza o dado (o mais grave).
- **Falso positivo (FP):** trecho inofensivo tarjado → irrita o usuário.

Implementação em Python puro (sem sklearn) para manter ``src`` leve e offline.
Os notebooks usam matplotlib/sklearn (grupo ``dev``) apenas para plotar.

Referência:
    Doc 04, §6 (equilíbrio FN/FP na detecção de PII).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from src.security.schemas import PIIEntity


@dataclass
class ConfusionMatrix:
    """Matriz de confusão da detecção de PII (nível de ENTIDADE, micro-média).

    Convenção: "positivo" = há uma entidade de PII a ser detectada.
    """

    tp: int = 0  # entidade correta detectada
    fp: int = 0  # entidade detectada onde não havia (falso positivo)
    tn: int = 0  # amostra sem PII corretamente sem detecção
    fn: int = 0  # entidade real NÃO detectada (falso negativo — o mais grave)

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        """Revocação = fração de PII real detectada (prioridade em proteção de dados)."""
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def leak_rate(self) -> float:
        """Taxa de vazamento = FN / (TP + FN): PII que escapou da detecção."""
        denom = self.tp + self.fn
        return self.fn / denom if denom else 0.0

    def to_dict(self) -> dict:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "leak_rate": round(self.leak_rate, 4),
        }


def _as_set(entities: Iterable[PIIEntity | str]) -> set[str]:
    return {e.value if isinstance(e, PIIEntity) else str(e) for e in entities}


def detection_confusion(
    expected: list[Iterable[PIIEntity | str]],
    predicted: list[Iterable[PIIEntity | str]],
) -> ConfusionMatrix:
    """Compara entidades esperadas × previstas por amostra (micro-média).

    Args:
        expected: para cada amostra, o conjunto de entidades que DEVERIAM ser detectadas.
        predicted: para cada amostra, o conjunto de entidades efetivamente detectadas.

    Returns:
        :class:`ConfusionMatrix` agregada por ocorrência de entidade.
    """
    if len(expected) != len(predicted):
        raise ValueError("expected e predicted devem ter o mesmo tamanho")
    cm = ConfusionMatrix()
    for exp_raw, pred_raw in zip(expected, predicted, strict=True):
        exp, pred = _as_set(exp_raw), _as_set(pred_raw)
        cm.tp += len(exp & pred)
        cm.fp += len(pred - exp)
        cm.fn += len(exp - pred)
        if not exp and not pred:
            cm.tn += 1  # amostra benigna corretamente sem detecção
    return cm
