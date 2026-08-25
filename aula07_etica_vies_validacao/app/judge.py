"""LLM-as-Judge com mitigação de vieses (Doc 04, "LLM-as-Judge e seus vieses").

O ``Judge`` avalia respostas do Aurora Assist segundo uma rubrica (clareza,
fundamentação e relevância). A implementação é **determinística e offline**
(baseada nos *proxies* de qualidade de ``src/security``), o que permite
**demonstrar** — e mitigar — os três vieses documentados por Zheng et al. (2023):

    * **position bias**: tendência a favorecer a resposta apresentada primeiro.
      Mitigação: alternar as posições e agregar (``position_debias=True``).
    * **verbosity bias**: preferência por respostas mais longas.
      Mitigação: não pontuar volume; a rubrica exige concisão.
    * **self-enhancement bias**: favorecer o próprio estilo (fora de escopo aqui,
      mitigado na prática por múltiplos juízes/consenso).

Em produção, troque o ``Judge`` heurístico por um LLM forte usando a rubrica em
``app/policies/judge_rubric.md`` — a API é a mesma.

Referência:
    Zheng, L. et al. (2023). Judging LLM-as-a-Judge with MT-Bench and Chatbot Arena. NeurIPS.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.security.quality import semantic_similarity
from src.security.text import is_abstention, tokenize

# Vieses simulados (na escala base 0..1) para fins didáticos.
_POSITION_BONUS = 0.15
_VERBOSITY_COEF = 0.10


def _clamp(x: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, x))


def _to_scale(base: float) -> float:
    """Converte qualidade base [0,1] para a escala 1..5 da rubrica."""
    return round(1.0 + 4.0 * _clamp(base), 3)


def _faithfulness(answer: str, contexts: list[str] | None) -> float:
    """Fração dos tokens de conteúdo da resposta presentes no contexto (0..1)."""
    if is_abstention(answer):
        return 1.0
    if not contexts:
        return 0.5  # neutro quando não há contexto para checar
    ans = set(tokenize(answer, canonical=True, remove_stopwords=True))
    if not ans:
        return 0.0
    ctx = set(tokenize(" ".join(contexts), canonical=True, remove_stopwords=True))
    return len(ans & ctx) / len(ans)


@dataclass
class PairwiseVerdict:
    """Resultado de uma comparação pareada entre duas respostas."""

    winner: str  # "A" | "B" | "tie"
    score_a: float
    score_b: float
    position_debiased: bool


class Judge:
    """Juiz determinístico com rubrica; opcionalmente de-enviesado."""

    def __init__(self, *, position_debias: bool = True, ensemble_size: int = 3) -> None:
        self.position_debias = position_debias
        self.ensemble_size = max(1, ensemble_size)

    # --- pontuação individual --------------------------------------------- #
    def _base_quality(self, question: str, answer: str, contexts: list[str] | None) -> float:
        relevance = semantic_similarity(answer, question)
        faithfulness = _faithfulness(answer, contexts)
        return _clamp(0.6 * relevance + 0.4 * faithfulness)

    def score(
        self,
        question: str,
        answer: str,
        contexts: list[str] | None = None,
        *,
        verbosity_bias: bool = False,
    ) -> float:
        """Nota 1..5 da resposta. ``verbosity_bias`` infla por tamanho (didático)."""
        base = self._base_quality(question, answer, contexts)
        if verbosity_bias:
            length_norm = _clamp(len(tokenize(answer)) / 60.0)
            base = _clamp(base + _VERBOSITY_COEF * length_norm)
        return _to_scale(base)

    def ensemble_score(
        self, question: str, answer: str, contexts: list[str] | None = None
    ) -> float:
        """Agrega ``ensemble_size`` juízes (consenso) — reduz ruído de um único juiz."""
        # Perturbações determinísticas simulam juízes ligeiramente distintos.
        base = self._base_quality(question, answer, contexts)
        offsets = [(-1) ** i * (0.02 * ((i + 1) // 2)) for i in range(self.ensemble_size)]
        scores = [_to_scale(_clamp(base + off)) for off in offsets]
        return round(sum(scores) / len(scores), 3)

    # --- comparação pareada (position bias) ------------------------------- #
    def _raw_pairwise(self, question: str, first: str, second: str) -> tuple[float, float]:
        """Pontua (first, second) COM viés de posição a favor do 'first'."""
        s_first = self._base_quality(question, first, None) + _POSITION_BONUS
        s_second = self._base_quality(question, second, None)
        return s_first, s_second

    def pairwise(self, question: str, answer_a: str, answer_b: str) -> PairwiseVerdict:
        """Compara A vs B. Se ``position_debias``, alterna a ordem e agrega."""
        if not self.position_debias:
            s_a, s_b = self._raw_pairwise(question, answer_a, answer_b)
        else:
            # Ordem 1: (A, B). Ordem 2: (B, A). Média cancela o bônus de posição.
            a1, b1 = self._raw_pairwise(question, answer_a, answer_b)
            b2, a2 = self._raw_pairwise(question, answer_b, answer_a)
            s_a, s_b = (a1 + a2) / 2, (b1 + b2) / 2
        winner = "A" if s_a > s_b else "B" if s_b > s_a else "tie"
        return PairwiseVerdict(winner, round(s_a, 4), round(s_b, 4), self.position_debias)

    def position_bias_delta(self, question: str, answer_a: str, answer_b: str) -> float:
        """Viés de posição RESIDUAL sob a política atual do juiz.

        Com ``position_debias=True``, a alternância de ordem cancela o bônus de
        posição -> residual ~0. Sem de-viés, retorna a assimetria (magnitude com
        que a mesma resposta é favorecida por aparecer primeiro).
        """
        if self.position_debias:
            return 0.0
        a_first, b_when_a_first = self._raw_pairwise(question, answer_a, answer_b)
        b_first, a_when_a_second = self._raw_pairwise(question, answer_b, answer_a)
        adv_a_first = a_first - b_when_a_first
        adv_a_second = a_when_a_second - b_first
        return round(abs(adv_a_first - adv_a_second) / 2.0, 4)

    def verbosity_bias_delta(
        self, question: str, short_answer: str, long_answer: str
    ) -> float:
        """Ganho indevido de nota por volume (short vs long de mesmo sentido)."""
        biased = self.score(question, long_answer, verbosity_bias=True) - self.score(
            question, short_answer, verbosity_bias=True
        )
        return round(biased, 4)
