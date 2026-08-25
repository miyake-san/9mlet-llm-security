"""Camada de moderação de conteúdo — Azure AI Content Safety (Aula 02).

Implementa a moderação com **severidade graduada** (0-6) discutida na seção 7 e
ilustrada na Figura 3 do Documento 04: o mesmo conteúdo recebe tratamentos
distintos conforme o fluxo (FAQ × autenticado × transacional). A política
gradual evita a visão binária de segurança.

Dois back-ends:
- :class:`StubContentSafety` (padrão, OFFLINE): classificador heurístico
  determinístico por categoria. Suficiente para o lab e para CI.
- :class:`AzureContentSafety` (opcional): usa o serviço gerenciado
  ``azure-ai-contentsafety`` quando ``AACS_ENDPOINT``/``AACS_KEY`` existem
  (grupo ``azure``). Este é o caminho de produção.

Referência:
    Microsoft (2024a). Azure AI Content Safety Documentation.
    Doc 04, seção 7 e Figura 3 (severidade graduada).
"""

from __future__ import annotations

import os
import re
import time
from typing import Protocol

from .schemas import Layer, LayerResult, Verdict

CATEGORIES = ("hate", "sexual", "violence", "self_harm")

# Assinaturas DIDÁTICAS por categoria (PT-BR/EN). Mantidas curtas e defensivas:
# o objetivo é demonstrar severidade graduada, não catalogar conteúdo nocivo.
_CATEGORY_SIGNS: dict[str, list[str]] = {
    "hate": [r"\bódio\b", r"\bhate\b", r"raça inferior", r"inferior race", r"\bslurs?\b"],
    "sexual": [r"\bconteúdo sexual\b", r"\bsexual\b", r"\bpornogr", r"\bnudez\b"],
    "violence": [r"\bmatar\b", r"\bkill\b", r"\bataque\b", r"\bbomba\b", r"\bexplo(dir|sive)"],
    "self_harm": [r"\bsuic[íi]dio\b", r"\bself[- ]?harm\b", r"me machucar", r"\bcortar-me\b"],
}


class ContentSafety(Protocol):
    """Contrato de um moderador de conteúdo."""

    def analyze(self, text: str) -> dict[str, int]:
        """Retorna a severidade (0-6) por categoria."""
        ...


class StubContentSafety:
    """Moderador heurístico offline — determinístico e sem rede."""

    def analyze(self, text: str) -> dict[str, int]:
        severities: dict[str, int] = {}
        for category, signs in _CATEGORY_SIGNS.items():
            hits = sum(1 for pattern in signs if re.search(pattern, text, re.IGNORECASE))
            # Mapeia contagem de sinais para a escala 0-6 do AACS (passos de 2).
            severities[category] = min(6, hits * 2)
        return severities


class AzureContentSafety:
    """Adaptador para o Azure AI Content Safety (produção; grupo ``azure``)."""

    def __init__(self, endpoint: str, key: str) -> None:
        # Import tardio: só exigido quando o back-end Azure é selecionado.
        from azure.ai.contentsafety import ContentSafetyClient
        from azure.core.credentials import AzureKeyCredential

        self._client = ContentSafetyClient(endpoint, AzureKeyCredential(key))

    def analyze(self, text: str) -> dict[str, int]:
        from azure.ai.contentsafety.models import AnalyzeTextOptions

        response = self._client.analyze_text(AnalyzeTextOptions(text=text))
        mapping = {
            "Hate": "hate",
            "Sexual": "sexual",
            "Violence": "violence",
            "SelfHarm": "self_harm",
        }
        severities = {category: 0 for category in CATEGORIES}
        for item in response.categories_analysis:
            key = mapping.get(item.category)
            if key:
                severities[key] = int(item.severity or 0)
        return severities


def get_content_safety() -> ContentSafety:
    """Fábrica: escolhe Azure se houver credenciais; senão, o stub offline."""
    endpoint = os.getenv("AACS_ENDPOINT", "").strip()
    key = os.getenv("AACS_KEY", "").strip()
    if endpoint and key:
        try:
            return AzureContentSafety(endpoint, key)
        except Exception:  # noqa: BLE001 — degrada para stub se SDK ausente/erro
            return StubContentSafety()
    return StubContentSafety()


def check_content_safety(
    text: str,
    moderator: ContentSafety | None = None,
    block_at: int = 4,
) -> LayerResult:
    """Modera ``text`` e bloqueia se alguma categoria atingir ``block_at``.

    ``block_at`` vem do perfil de fluxo (``configs/thresholds.yaml``): fluxos
    transacionais usam um corte mais baixo (revocação alta) — Doc 04, Tabela 2.
    """
    moderator = moderator or get_content_safety()
    start = time.perf_counter()
    severities = moderator.analyze(text)
    latency_ms = (time.perf_counter() - start) * 1000
    worst_category = max(severities, key=lambda category: severities[category])
    worst = severities[worst_category]
    blocked = worst >= block_at
    return LayerResult(
        layer=Layer.CONTENT_SAFETY,
        verdict=Verdict.BLOCK if blocked else Verdict.ALLOW,
        score=worst / 6.0,
        reason=(
            f"Severidade {worst}/6 em '{worst_category}' >= corte {block_at}"
            if blocked
            else f"Severidade máxima {worst}/6 abaixo do corte {block_at}"
        ),
        details={"severities": severities, "block_at": block_at},
        latency_ms=latency_ms,
    )
