"""Métricas de validação de qualidade de texto (Doc 04, "Validação de qualidade").

Implementa, de forma **pura e offline**, as três camadas discutidas no Documento
04: métricas de **superfície** (BLEU, ROUGE), um **proxy semântico** para o
BERTScore e um F1 de tokens. O objetivo pedagógico é demonstrar por que métricas
de superfície penalizam paráfrases corretas, enquanto a medida semântica
reconhece equivalência de significado.

    * BLEU (Papineni et al., 2002): precisão de n-gramas + brevity penalty.
    * ROUGE (Lin, 2004): recall de n-gramas (ROUGE-N) e LCS (ROUGE-L).
    * BERTScore (Zhang et al., 2020): similaridade semântica. Aqui, um *proxy*
      offline por cosseno sobre tokens canônicos; o BERTScore real (que usa
      embeddings do BERT) fica no grupo opcional ``eval`` via ``bertscore_f1``.

⚠️ O ``semantic_similarity`` é um *proxy didático* — NÃO substitui o BERTScore
real em produção. Ele torna o pipeline reprodutível sem baixar modelos pesados.

Referência:
    Papineni, K. et al. (2002). BLEU. ACL.
    Lin, C.-Y. (2004). ROUGE. ACL Workshop.
    Zhang, T. et al. (2020). BERTScore. ICLR. arXiv:1904.09675.
    Sellam, T. et al. (2020). BLEURT. ACL. arXiv:2004.04696.
"""

from __future__ import annotations

import logging
import math
from collections import Counter

from src.security.text import ngrams, surface_tokens, tokenize

logger = logging.getLogger(__name__)


def _modified_precision(cand: list[str], ref: list[str], n: int) -> tuple[int, int]:
    """Contagem de n-gramas do candidato "clipada" pela referência (BLEU)."""
    cand_ngrams = Counter(ngrams(cand, n))
    ref_ngrams = Counter(ngrams(ref, n))
    if not cand_ngrams:
        return 0, 0
    clipped = sum(min(c, ref_ngrams[g]) for g, c in cand_ngrams.items())
    total = sum(cand_ngrams.values())
    return clipped, total


def bleu(candidate: str, reference: str, max_n: int = 4) -> float:
    """BLEU (0..1) com brevity penalty e suavização de n-gramas ausentes.

    Usa tokens de **superfície**: por isso paráfrases corretas recebem nota
    baixa (limitação central discutida no Documento 04).
    """
    cand = surface_tokens(candidate)
    ref = surface_tokens(reference)
    if not cand or not ref:
        return 0.0
    precisions: list[float] = []
    for n in range(1, max_n + 1):
        clipped, total = _modified_precision(cand, ref, n)
        # Suavização "add-1" (Chen & Cherry, 2014) para n-gramas de ordem alta.
        precisions.append((clipped + 1e-9) / (total + 1e-9) if total else 0.0)
    if min(precisions) <= 0:
        geo_mean = 0.0
    else:
        geo_mean = math.exp(sum(math.log(p) for p in precisions) / len(precisions))
    brevity = 1.0 if len(cand) > len(ref) else math.exp(1 - len(ref) / len(cand))
    return round(brevity * geo_mean, 4)


def rouge_n(candidate: str, reference: str, n: int = 1) -> float:
    """ROUGE-N (0..1): recall de n-gramas da referência recuperados pelo candidato."""
    cand = Counter(ngrams(surface_tokens(candidate), n))
    ref = Counter(ngrams(surface_tokens(reference), n))
    ref_total = sum(ref.values())
    if not ref_total:
        return 0.0
    overlap = sum(min(cand[g], c) for g, c in ref.items())
    return round(overlap / ref_total, 4)


def _lcs_length(a: list[str], b: list[str]) -> int:
    """Comprimento da maior subsequência comum (base do ROUGE-L)."""
    if not a or not b:
        return 0
    prev = [0] * (len(b) + 1)
    for token_a in a:
        curr = [0]
        for j, token_b in enumerate(b, 1):
            if token_a == token_b:
                curr.append(prev[j - 1] + 1)
            else:
                curr.append(max(prev[j], curr[j - 1]))
        prev = curr
    return prev[-1]


def rouge_l(candidate: str, reference: str) -> float:
    """ROUGE-L (0..1): F1 baseado na maior subsequência comum (LCS)."""
    cand = surface_tokens(candidate)
    ref = surface_tokens(reference)
    lcs = _lcs_length(cand, ref)
    if lcs == 0:
        return 0.0
    precision = lcs / len(cand)
    recall = lcs / len(ref)
    return round(2 * precision * recall / (precision + recall), 4)


def _cosine(a: Counter[str], b: Counter[str]) -> float:
    """Similaridade de cosseno entre dois sacos de tokens (multiset)."""
    if not a or not b:
        return 0.0
    common = set(a) & set(b)
    dot = sum(a[t] * b[t] for t in common)
    norm_a = math.sqrt(sum(v * v for v in a.values()))
    norm_b = math.sqrt(sum(v * v for v in b.values()))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def semantic_similarity(candidate: str, reference: str) -> float:
    """*Proxy* offline de similaridade semântica (0..1) — didático.

    Aproxima o BERTScore por cosseno sobre tokens **canônicos** (numerais por
    extenso e sinônimos financeiros unificados; stopwords removidas). Reconhece
    equivalências que o BLEU ignora, ex.: "seu saldo é R$ 100" ≡ "há cem reais
    disponíveis" (exemplo do Documento 04).
    """
    a = Counter(tokenize(candidate, canonical=True, remove_stopwords=True))
    b = Counter(tokenize(reference, canonical=True, remove_stopwords=True))
    return round(_cosine(a, b), 4)


def token_f1(candidate: str, reference: str) -> float:
    """F1 de sobreposição de tokens canônicos (0..1)."""
    a = Counter(tokenize(candidate, canonical=True, remove_stopwords=True))
    b = Counter(tokenize(reference, canonical=True, remove_stopwords=True))
    common = sum((a & b).values())
    if common == 0:
        return 0.0
    precision = common / sum(a.values())
    recall = common / sum(b.values())
    return round(2 * precision * recall / (precision + recall), 4)


def bertscore_f1(candidates: list[str], references: list[str], lang: str = "pt") -> list[float]:
    """BERTScore F1 real (grupo ``eval``) com fallback para o *proxy* offline.

    Tenta usar ``bert_score`` (embeddings contextuais do BERT — Zhang et al.,
    2020). Se a biblioteca não estiver instalada (``uv sync --group eval``),
    registra um aviso e retorna o ``semantic_similarity`` para manter o pipeline
    executável offline.
    """
    try:
        from bert_score import score  # type: ignore

        _, _, f1 = score(candidates, references, lang=lang, verbose=False)
        return [round(float(v), 4) for v in f1.tolist()]
    except ImportError:
        logger.warning(
            "bert_score indisponível — usando proxy semântico offline. "
            "Instale com `uv sync --group eval` para o BERTScore real."
        )
        return [semantic_similarity(c, r) for c, r in zip(candidates, references, strict=True)]
