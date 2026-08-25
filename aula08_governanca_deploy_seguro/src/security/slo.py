"""SLOs, error budget e gatilho de rollback automatizado (Doc 04, §6-7).

Traduz a engenharia de confiabilidade (SRE) do Documento 04 para o deploy seguro:
carrega as definições de ``configs/slo.yaml`` (latência P95, groundedness,
jailbreak rate, taxa de bloqueio de PII, drift, custo), avalia-as contra os SLIs
medidos e materializa o **rollback automatizado orientado por qualidade e safety**.

O :func:`should_rollback` implementa o **Snippet 2** do Doc 04; :func:`rollback_decision`
generaliza-o para a fórmula da disjunção lógica da §6:

    Rollback = ⋁ᵢ [ v(mᵢ) ▷ θᵢ ]

onde basta UMA métrica crítica violar o seu limiar (▷) para reverter.

Referência:
    Beyer et al. (2016). Site Reliability Engineering (SLO/error budget/postmortem).
    Doc 04, §6 (deploy seguro + rollback) e §7 (SRE para IA).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

import yaml

from src.security.schemas import SLODefinition, SLOEvaluation, SLOReport, SLOStatus

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_SLO_PATH = _REPO_ROOT / "configs" / "slo.yaml"

# Banda relativa (1%) para o estado AT_RISK: perto do limite, mas ainda dentro.
_AT_RISK_FRACTION = 0.01


def load_slo_definitions(path: str | Path | None = None) -> list[SLODefinition]:
    """Lê as definições de SLO de ``configs/slo.yaml`` (Doc 04, §7)."""
    slo_path = Path(path) if path else _DEFAULT_SLO_PATH
    raw = yaml.safe_load(slo_path.read_text(encoding="utf-8"))
    defs: list[SLODefinition] = []
    for item in raw.get("slos", []):
        defs.append(
            SLODefinition(
                id=item["id"],
                name=item["name"],
                sli=item["sli"],
                objective=float(item["objective"]),
                comparator=item.get("comparator", "lte"),
                unit=item.get("unit", ""),
                error_budget=float(item.get("error_budget", 0.0)),
                critical=bool(item.get("critical", False)),
                action=item.get("action", ""),
            )
        )
    return defs


def _status(defn: SLODefinition, value: float) -> SLOStatus:
    if defn.violates(value):
        return SLOStatus.VIOLATED
    band = abs(defn.objective) * _AT_RISK_FRACTION
    if defn.comparator == "lte":
        return SLOStatus.AT_RISK if value >= defn.objective - band else SLOStatus.HEALTHY
    return SLOStatus.AT_RISK if value <= defn.objective + band else SLOStatus.HEALTHY


def evaluate_slo(defn: SLODefinition, value: float) -> SLOEvaluation:
    """Avalia um SLO contra o valor medido do seu SLI."""
    met = defn.is_met(value)
    return SLOEvaluation(
        slo_id=defn.id,
        name=defn.name,
        sli_value=round(value, 6),
        objective=defn.objective,
        comparator=defn.comparator,
        unit=defn.unit,
        met=met,
        status=_status(defn, value),
        critical=defn.critical,
        action=defn.action if not met else "",
    )


def evaluate_all(defs: Sequence[SLODefinition], sli_values: Mapping[str, float]) -> SLOReport:
    """Avalia todos os SLOs cujos SLIs estão presentes em ``sli_values``."""
    evaluations = [
        evaluate_slo(defn, float(sli_values[defn.sli])) for defn in defs if defn.sli in sli_values
    ]
    return SLOReport(evaluations=evaluations)


def error_budget_status(defn: SLODefinition, violation_rate: float) -> dict:
    """Consumo do error budget dado o % de janelas/requests que violaram a meta.

    O error budget transforma confiabilidade em grandeza gerenciável (Doc 04,
    §7): enquanto houver orçamento, tolera-se falha; ao esgotar, congela-se o
    release e a equipe foca em estabilidade.
    """
    budget = defn.error_budget
    if budget <= 0:
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


# --------------------------------------------------------------------------- #
# Gatilho de rollback (Snippet 2 do Doc 04) + fórmula da disjunção (§6)         #
# --------------------------------------------------------------------------- #
def should_rollback(metrics: dict, slo: dict) -> bool:
    """Gatilho de rollback baseado em SLO — **Snippet 2** do Documento 04 (§6).

    Reverte a versão candidata se qualquer condição crítica for violada: a
    *groundedness* caiu abaixo do mínimo, o *jailbreak rate* subiu acima do
    máximo, ou o *drift* disparou. É a conexão direta entre o monitoramento da
    Aula 6, o red team da Aula 4 e o deploy seguro desta aula.
    """
    return (
        metrics["groundedness"] < slo["min_groundedness"]
        or metrics["jailbreak_rate"] > slo["max_jailbreak"]
        or metrics["drift_score"] > slo["max_drift"]
    )


def rollback_decision(defs: Sequence[SLODefinition], sli_values: Mapping[str, float]) -> dict:
    """Fórmula da §6: Rollback = ⋁ᵢ [ v(mᵢ) ▷ θᵢ ] sobre os SLOs CRÍTICOS.

    Avalia todos os SLOs marcados como ``critical`` e dispara a reversão se
    qualquer um deles for violado (disjunção lógica). Retorna a decisão e a lista
    de gatilhos, para o postmortem e a trilha de auditoria (Doc 04, §7).
    """
    triggers: list[dict] = []
    for defn in defs:
        if not defn.critical or defn.sli not in sli_values:
            continue
        value = float(sli_values[defn.sli])
        if defn.violates(value):
            triggers.append(
                {
                    "slo_id": defn.id,
                    "sli": defn.sli,
                    "observed": round(value, 6),
                    "objective": defn.objective,
                    "comparator": defn.comparator,
                }
            )
    return {"rollback": bool(triggers), "triggers": triggers}
