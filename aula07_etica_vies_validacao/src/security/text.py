"""Normalização e tokenização de texto PT-BR para métricas de avaliação.

Funções puras, determinísticas e sem I/O — a base sobre a qual as métricas
clássicas (BLEU/ROUGE) e o *proxy* semântico (BERTScore didático) são calculados
em ``src/security/quality.py``.

O objetivo NÃO é competir com um tokenizador neural, mas oferecer uma base
reprodutível e offline. A normalização inclui um mapa mínimo de **numerais por
extenso** e de **sinônimos financeiros** para que o exemplo do Documento 04
("seu saldo é R$ 100" ≡ "há cem reais disponíveis") seja reconhecido como
equivalente — algo impossível para métricas de superfície como o BLEU.
"""

from __future__ import annotations

import re
import unicodedata

# Numerais por extenso (mínimo, PT-BR) mapeados ao dígito canônico. Cobre o
# exemplo do Doc 04 e casos comuns em respostas bancárias.
_NUMBER_WORDS: dict[str, str] = {
    "zero": "0",
    "um": "1",
    "uma": "1",
    "dois": "2",
    "duas": "2",
    "tres": "3",
    "quatro": "4",
    "cinco": "5",
    "seis": "6",
    "sete": "7",
    "oito": "8",
    "nove": "9",
    "dez": "10",
    "cem": "100",
    "cento": "100",
    "mil": "1000",
}

# Sinônimos financeiros canônicos (didático). Aproxima significado sem embeddings:
# reconhece que "saldo", "dinheiro" e "reais" pertencem ao mesmo campo semântico.
_SYNONYMS: dict[str, str] = {
    "real": "reais",
    "saldo": "dinheiro",
    "disponivel": "dinheiro",
    "disponiveis": "dinheiro",
    "rende": "rendimento",
    "rendem": "rendimento",
    "rentabilidade": "rendimento",
    "juros": "taxa",
    "anual": "ano",
    "ao": "ano",
}

_STOPWORDS: frozenset[str] = frozenset(
    {"a", "o", "os", "as", "de", "do", "da", "dos", "das", "e", "em", "no", "na", "ha"}
)

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def strip_accents(text: str) -> str:
    """Remove acentos preservando as letras base (á -> a, ç -> c)."""
    nfkd = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in nfkd if not unicodedata.combining(ch))


def normalize(text: str) -> str:
    """Minúsculas + sem acentos; ``R$`` vira o token "reais" (moeda canônica)."""
    lowered = strip_accents(text).lower()
    # "R$" perderia o "$" no tokenizador (regex [a-z0-9]+); mapeia para "reais".
    return lowered.replace("r$", " reais ")


def surface_tokens(text: str) -> list[str]:
    """Tokens de SUPERFÍCIE (só normalização), sem numerais/sinônimos.

    É a base do BLEU/ROUGE: mede sobreposição literal, e por isso penaliza
    paráfrases válidas — exatamente a limitação que o Documento 04 descreve.
    """
    return _TOKEN_RE.findall(normalize(text))


def tokenize(
    text: str, *, canonical: bool = True, remove_stopwords: bool = False
) -> list[str]:
    """Tokeniza o texto, opcionalmente canonicalizando numerais/sinônimos.

    Args:
        text: texto de entrada.
        canonical: se ``True``, mapeia numerais por extenso e sinônimos
            financeiros ao token canônico (base do *proxy* semântico). Se
            ``False``, retorna tokens de superfície (base do BLEU/ROUGE).
        remove_stopwords: se ``True``, descarta artigos/preposições comuns.

    Returns:
        Lista de tokens.
    """
    raw = surface_tokens(text)
    if not canonical and not remove_stopwords:
        return raw
    out: list[str] = []
    for tok in raw:
        canon = tok
        if canonical:
            canon = _NUMBER_WORDS.get(canon, canon)
            canon = _SYNONYMS.get(canon, canon)
        if remove_stopwords and canon in _STOPWORDS:
            continue
        out.append(canon)
    return out


def ngrams(tokens: list[str], n: int) -> list[tuple[str, ...]]:
    """Gera os ``n``-gramas (contíguos) de uma lista de tokens."""
    if n <= 0 or len(tokens) < n:
        return []
    return [tuple(tokens[i : i + n]) for i in range(len(tokens) - n + 1)]


# Marcadores de abstenção/recusa. Uma resposta que se abstém NÃO faz afirmação
# não sustentada — logo é considerada FIEL ao contexto (RAGAS faithfulness=1.0).
_ABSTENTION_MARKERS: tuple[str, ...] = (
    "nao encontrei",
    "nao consta",
    "nao esta disponivel",
    "nao estao disponiveis",
    "nao ha essa informacao",
    "nao possuo essa informacao",
    "informacao nao disponivel",
)


def is_abstention(text: str) -> bool:
    """Indica se o texto é uma abstenção ("não encontrei nos documentos")."""
    flat = strip_accents(text).lower()
    return any(marker in flat for marker in _ABSTENTION_MARKERS)
