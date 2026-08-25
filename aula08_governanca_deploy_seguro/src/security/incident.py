"""Resposta a incidentes de IA e postmortems blameless (Doc 04, §7).

Implementa o *playbook* de resposta a incidentes específico de LLMs (Figura 4 do
Doc 04): classifica o incidente por tipo e severidade, executa as fases de
**contenção → erradicação → recuperação** e registra cada passo na trilha de
auditoria imutável (Aula 04). Cobre os três cenários do Doc 04:

    * ``jailbreak_escape`` — um ataque atravessou os guardrails (Aula 4).
    * ``data_leak``        — vazamento de PII (Aula 3/5).
    * ``drift_critico``    — degradação severa de desempenho/qualidade (Aula 6/7).

Ao final, produz um **postmortem blameless** — foco em processo, não em pessoas —
para transformar o erro em melhoria contínua (Doc 04, §7; Beyer et al., 2016).

Referência:
    Beyer et al. (2016). Site Reliability Engineering (incident response/postmortem).
    Microsoft (2025). Azure Sentinel (SIEM/SOAR). · Doc 04, §7 (Figura 4).
"""

from __future__ import annotations

from src.security.audit import HashChain
from src.security.schemas import Incident, IncidentSeverity

# Cenário -> severidade e ação de contenção imediata (Doc 04, Figura 4).
_PLAYBOOK: dict[str, dict] = {
    "jailbreak_escape": {
        "severity": IncidentSeverity.SEV1,
        "containment": "bloquear a versão afetada e reverter para a última estável (rollback)",
        "eradication": "endurecer guardrails (Aula 2) e adicionar o payload à regressão (Aula 4)",
        "recovery": "reimplantar via canary monitorando jailbreak_rate até estabilizar",
    },
    "data_leak": {
        "severity": IncidentSeverity.SEV1,
        "containment": "suspender o fluxo e revogar tokens de ferramenta (Aula 3)",
        "eradication": "corrigir redação de PII (Aula 3/5) e notificar o encarregado (LGPD)",
        "recovery": "purga seletiva e reprocessamento com anonimização reforçada",
    },
    "drift_critico": {
        "severity": IncidentSeverity.SEV2,
        "containment": "congelar promoções e ativar rollback por SLO (Aula 6)",
        "eradication": "recalibrar retrieval/grounding e revisar dados (Aula 6/7)",
        "recovery": "reavaliar quality gate (Aula 7) antes de nova promoção",
    },
}


def classify_incident(kind: str, signals: dict) -> Incident:
    """Classifica o incidente e define a severidade a partir do playbook (Doc 04, §7)."""
    entry = _PLAYBOOK.get(kind)
    incident_id = f"INC-{abs(hash((kind, tuple(sorted(signals.items()))))) % 100000:05d}"
    if entry is None:
        return Incident(
            incident_id=incident_id,
            kind=kind,
            severity=IncidentSeverity.SEV3,
            summary=f"Incidente não catalogado: {kind}",
            triggered_by=str(signals),
        )
    return Incident(
        incident_id=incident_id,
        kind=kind,
        severity=entry["severity"],
        summary=f"{kind} detectado — contenção: {entry['containment']}",
        triggered_by=str(signals),
        containment=entry["containment"],
    )


def run_playbook(incident: Incident, *, chain: HashChain | None = None) -> dict:
    """Executa as fases do playbook e registra a trilha de evidências (WORM lógico)."""
    chain = chain or HashChain()
    entry = _PLAYBOOK.get(incident.kind, {})
    phases = [
        ("deteccao", incident.triggered_by),
        ("triagem", f"severidade {incident.severity.value}"),
        ("contencao", entry.get("containment", "isolar e bloquear")),
        ("erradicacao", entry.get("eradication", "corrigir controles")),
        ("recuperacao", entry.get("recovery", "reimplantar monitorando")),
    ]
    steps: list[dict] = []
    for phase, action in phases:
        rec = chain.append({"incident_id": incident.incident_id, "phase": phase, "action": action})
        steps.append({"phase": phase, "action": action, "audit_hash": rec.hash})
    return {
        "incident": incident.to_dict(),
        "steps": steps,
        "merkle_root": chain.merkle_root(),
        "chain_verified": chain.verify(),
    }


def blameless_postmortem(incident: Incident, *, root_cause: str, lessons: list[str]) -> dict:
    """Gera um postmortem blameless (foco em processo, não em pessoas — Doc 04, §7)."""
    return {
        "incident_id": incident.incident_id,
        "kind": incident.kind,
        "severity": incident.severity.value,
        "blameless": True,
        "root_cause": root_cause,
        "what_went_well": [
            "detecção automatizada por SLO",
            "rollback conteve o impacto em minutos",
        ],
        "lessons_learned": lessons,
        "action_items": [
            "atualizar política de governança (ISO 42001 — Act)",
            "adicionar cenário à suíte de regressão de segurança",
            "revisar thresholds de SLO no configs/slo.yaml",
        ],
    }
