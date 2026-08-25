"""Avaliação de SLIs, SLOs e Data SLOs com error budget (Aula 06).

Carrega as definições de ``configs/slo.yaml`` e as avalia contra os SLIs medidos,
produzindo um :class:`SLOReport` semaforizado (HEALTHY / AT_RISK / VIOLATED). É a
tradução operacional do Doc 04 (§"SLIs, SLOs e Data SLOs"): metas numéricas
verificáveis, com **error budget** como margem de falha tolerada antes de ação
corretiva obrigatória (Beyer et al., 2016).

Referência:
    Beyer et al. (2016). Site Reliability Engineering.
    DAMA International (2017). DAMA-DMBOK (Data SLOs). · Doc 04, §SLOs.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from pathlib import Path

import yaml

from src.security.schemas import (
    SLODefinition,
    SLOEvaluation,
    SLOKind,
    SLOReport,
    SLOStatus,
)

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_SLO_PATH = _REPO_ROOT / "configs" / "slo.yaml"

# Banda relativa (1%) para o estado AT_RISK: perto de estourar, mas ainda dentro.
# Mantida estreita para que metas `gte` próximas de 1.0 (ex.: bloqueio de
# jailbreak >= 0.98) ainda possam ser classificadas como saudáveis.
_AT_RISK_FRACTION = 0.01


def load_slo_definitions(path: str | Path | None = None) -> list[SLODefinition]:
    """Lê as definições de SLO de ``configs/slo.yaml`` (Doc 04, Tabela 3)."""
    slo_path = Path(path) if path else _DEFAULT_SLO_PATH
    raw = yaml.safe_load(slo_path.read_text(encoding="utf-8"))
    defs: list[SLODefinition] = []
    for item in raw.get("slos", []):
        defs.append(
            SLODefinition(
                id=item["id"],
                name=item["name"],
                kind=SLOKind(item.get("kind", "slo")),
                sli=item["sli"],
                objective=float(item["objective"]),
                unit=item.get("unit", ""),
                comparator=item.get("comparator", "lte"),
                source=item.get("source", ""),
                window=item.get("window", ""),
                error_budget=float(item.get("error_budget", 0.0)),
                action=item.get("action", ""),
            )
        )
    return defs


def _status(defn: SLODefinition, value: float) -> SLOStatus:
    """Semáforo do SLO: VIOLATED, AT_RISK (perto do limite) ou HEALTHY."""
    if not defn.is_met(value):
        return SLOStatus.VIOLATED
    band = abs(defn.objective) * _AT_RISK_FRACTION
    if defn.comparator == "lte":
        # Bom = menor; risco quando o valor se aproxima da meta por baixo.
        return SLOStatus.AT_RISK if value >= defn.objective - band else SLOStatus.HEALTHY
    # comparator "gte": bom = maior; risco quando o valor se aproxima da meta por cima.
    return SLOStatus.AT_RISK if value <= defn.objective + band else SLOStatus.HEALTHY


def evaluate_slo(defn: SLODefinition, value: float) -> SLOEvaluation:
    """Avalia um SLO contra o valor medido do seu SLI."""
    met = defn.is_met(value)
    return SLOEvaluation(
        slo_id=defn.id,
        name=defn.name,
        kind=defn.kind,
        sli_value=round(value, 6),
        objective=defn.objective,
        unit=defn.unit,
        comparator=defn.comparator,
        met=met,
        status=_status(defn, value),
        error_budget=defn.error_budget,
        action=defn.action if not met else "",
    )


def evaluate_all(
    defs: Sequence[SLODefinition], sli_values: Mapping[str, float]
) -> SLOReport:
    """Avalia todos os SLOs cujos SLIs estão presentes em ``sli_values``."""
    evaluations: list[SLOEvaluation] = []
    for defn in defs:
        if defn.sli not in sli_values:
            logger.debug("SLI ausente para %s (%s) — pulando.", defn.id, defn.sli)
            continue
        evaluations.append(evaluate_slo(defn, float(sli_values[defn.sli])))
    return SLOReport(evaluations=evaluations)


def error_budget_status(defn: SLODefinition, violation_rate: float) -> dict:
    """Consumo do error budget dado o % de janelas/requests que violaram a meta.

    O error budget transforma confiabilidade em grandeza gerenciável (Doc 04):
    enquanto houver orçamento, tolera-se falha; ao esgotar, a ação é obrigatória.
    """
    budget = defn.error_budget
    if budget <= 0:
        # SLOs sem orçamento (ex.: PII leak, frescor) exigem conformidade estrita.
        return {
            "slo_id": defn.id,
            "budget": 0.0,
            "violation_rate": round(violation_rate, 4),
            "consumed_fraction": 1.0 if violation_rate > 0 else 0.0,
            "exhausted": violation_rate > 0,
        }
    consumed = min(1.0, violation_rate / budget)
    return {
        "slo_id": defn.id,
        "budget": budget,
        "violation_rate": round(violation_rate, 4),
        "consumed_fraction": round(consumed, 4),
        "exhausted": violation_rate > budget,
    }


def _self_test() -> None:  # pragma: no cover - utilitário de linha de comando
    """Carrega os SLOs e avalia um cenário saudável e um cenário violado."""
    from rich import print as rprint

    defs = load_slo_definitions()
    rprint(f"[bold]Definições de SLO carregadas:[/bold] {len(defs)}")

    healthy = {
        "latency_ms_p95": 850.0,
        "groundedness_ratio_regulated": 0.97,
        "jailbreak_block_rate": 0.99,
        "cost_usd_avg": 0.012,
        "knowledge_age_seconds": 3600.0,
        "pii_leak_rate": 0.0,
    }
    violated = {
        "latency_ms_p95": 2600.0,
        "groundedness_ratio_regulated": 0.80,
        "jailbreak_block_rate": 0.90,
        "cost_usd_avg": 0.11,
        "knowledge_age_seconds": 90000.0,
        "pii_leak_rate": 0.03,
    }
    for label, values in (("SAUDÁVEL", healthy), ("VIOLADO", violated)):
        report = evaluate_all(defs, values)
        rprint(
            f"\n[bold]{label}[/bold] — all_healthy={report.all_healthy} "
            f"violados={len(report.violated)}"
        )
        for ev in report.evaluations:
            rprint(f"  {ev.status.value:9s} {ev.name} = {ev.sli_value}{ev.unit}")


if __name__ == "__main__":  # pragma: no cover
    import sys

    if "--self-test" in sys.argv:
        _self_test()
    else:
        print("uso: python -m src.security.slo --self-test")
