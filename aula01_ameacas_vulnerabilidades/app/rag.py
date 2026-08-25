"""RAG ingênuo e VULNERÁVEL a injeção indireta (Doc 04, seção 4; Figura 2).

O recuperador não faz qualquer sanitização ou isolamento das instruções
contidas nos documentos: o texto recuperado é concatenado cru no contexto do
modelo. É exatamente a cadeia de confiança quebrada descrita por Greshake et
al. (2023) — 'quem autorizou aquele documento a emitir comandos?'.

Referência:
    Greshake, K. et al. (2023). Indirect Prompt Injection. AISec'23.
    OWASP Foundation (2025). Top 10 for LLM Applications — LLM01.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_CORPUS_DIR = Path(__file__).resolve().parents[1] / "data" / "rag_corpus"
_TOKEN_RE = re.compile(r"[a-zà-ú0-9]+", re.IGNORECASE)


@dataclass(frozen=True)
class Document:
    """Documento do corpus de RAG do Aurora."""

    id: str
    title: str
    text: str


def load_corpus(corpus_dir: Path = _CORPUS_DIR) -> list[Document]:
    """Carrega documentos ``.md`` do corpus (título = primeira linha/heading)."""
    docs: list[Document] = []
    if not corpus_dir.exists():
        return docs
    for path in sorted(corpus_dir.glob("*.md")):
        raw = path.read_text(encoding="utf-8").strip()
        lines = raw.splitlines()
        title = lines[0].lstrip("# ").strip() if lines else path.stem
        text = "\n".join(lines[1:]).strip() if len(lines) > 1 else raw
        docs.append(Document(id=path.stem, title=title, text=text))
    return docs


def _tokens(text: str) -> set[str]:
    return {t.lower() for t in _TOKEN_RE.findall(text)}


def naive_retrieve(query: str, corpus: list[Document], k: int = 3) -> list[Document]:
    """Recuperação ingênua por sobreposição de palavras (sem ranking robusto).

    Deliberadamente simples: qualquer documento com sobreposição de termos é
    candidato — inclusive os que carregam injeção indireta oculta.
    """
    q = _tokens(query)
    if not q or not corpus:
        return corpus[:k]
    scored = sorted(
        corpus,
        key=lambda d: len(q & _tokens(f"{d.title} {d.text}")),
        reverse=True,
    )
    return [d for d in scored if len(q & _tokens(f"{d.title} {d.text}"))][:k] or corpus[:k]


def build_context(docs: list[Document]) -> str:
    """Concatena o texto recuperado CRU no contexto (VULNERÁVEL, sem isolamento)."""
    return "\n\n".join(f"[{d.id}] {d.title}\n{d.text}" for d in docs)
