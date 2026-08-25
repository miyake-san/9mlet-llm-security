"""Utilidades de texto puras e offline (tokenização, normalização, abstenção).

Base leve para os guardrails, o *grounding* e as métricas de qualidade do agente,
sem dependências pesadas de NLP (mantém o lab *offline-first*). Espelha o utilitário
homônimo das Aulas 06-07 para preservar a coerência do curso.
"""

from __future__ import annotations

import re
import unicodedata

# Stopwords PT-BR mínimas (suficientes para sobreposição de conteúdo).
_STOPWORDS = {
    "a",
    "o",
    "os",
    "as",
    "de",
    "do",
    "da",
    "dos",
    "das",
    "e",
    "em",
    "no",
    "na",
    "um",
    "uma",
    "para",
    "por",
    "com",
    "que",
    "qual",
    "quais",
    "é",
    "ao",
    "à",
    "se",
    "the",
    "of",
    "to",
    "is",
    "and",
}

# Frases de abstenção honesta (grounding estrito -> não inventa fato ausente).
_ABSTENTION_MARKERS = (
    "não encontrei",
    "nao encontrei",
    "não consta",
    "não posso ajudar",
    "nao posso ajudar",
    "não tenho essa informação",
)


def strip_accents(text: str) -> str:
    """Remove acentos preservando as letras base (comparação robusta)."""
    nfkd = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in nfkd if not unicodedata.combining(ch))


def normalize(text: str) -> str:
    """Normaliza para minúsculas sem acento; converte 'R$' em 'reais'."""
    lowered = text.lower().replace("r$", " reais ")
    return strip_accents(lowered)


def tokenize(text: str, *, remove_stopwords: bool = False) -> list[str]:
    """Tokeniza em termos alfanuméricos (mín. 2 chars), opcionalmente sem stopwords."""
    tokens = re.findall(r"[a-z0-9]{2,}", normalize(text))
    if remove_stopwords:
        tokens = [t for t in tokens if t not in _STOPWORDS]
    return tokens


def content_tokens(text: str) -> set[str]:
    """Conjunto de tokens de conteúdo (sem stopwords) — base de sobreposição."""
    return set(tokenize(text, remove_stopwords=True))


def is_abstention(text: str) -> bool:
    """True se a resposta é uma abstenção honesta (não faz afirmação factual)."""
    low = normalize(text)
    return any(marker in low for marker in (strip_accents(m) for m in _ABSTENTION_MARKERS))


def jaccard(a: str, b: str) -> float:
    """Similaridade de Jaccard entre os conjuntos de tokens de conteúdo."""
    ta, tb = content_tokens(a), content_tokens(b)
    if not ta and not tb:
        return 1.0
    if not ta or not tb:
        return 0.0
    return round(len(ta & tb) / len(ta | tb), 4)
