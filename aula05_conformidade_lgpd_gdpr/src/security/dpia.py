"""Classificação de risco EU AI Act e DPIA — cálculo de risco (Aula 05).

Implementa duas peças centrais do Documento 04:

1. **Classificação por nível de risco** (§6-7): aplica a "pirâmide" do EU AI Act
   (Regulation EU 2024/1689) às *capabilities* declaradas do sistema. A bifurcação
   do Aurora Assist é reveladora — *informar* = risco LIMITADO; *decidir crédito*
   = ALTO RISCO. As escolhas de produto definem o fardo regulatório.

2. **Cálculo de risco da DPIA** (§7-8): formaliza o risco agregado como
   $R = \\sum_j P_j \\cdot I_j$ (mesma estrutura R = P·I da Aula 1), onde $P_j$ é a
   probabilidade do cenário e $I_j$ o impacto ponderado por gravidade jurídica e
   reputacional. Permite priorizar mitigações de forma objetiva.

Referência:
    UNIÃO EUROPEIA (2024). EU AI Act. · GDPR art. 35 (DPIA).
    VEALE & BORGESIUS (2021). Demystifying the Draft EU AI Act.
    CAVOUKIAN (2009). Privacy by Design. · Doc 04, §6-8.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from src.security.regulations import AI_ACT_OBLIGATIONS
from src.security.schemas import DPIAResult, ImpactCategory, RiskScenario, RiskTier

_CONFIGS = Path(__file__).resolve().parents[2] / "configs"


def load_risk_config(path: str | Path | None = None) -> dict[str, Any]:
    """Carrega ``configs/eu_ai_act_risk.yaml`` (árvore de decisão)."""
    target = Path(path) if path else _CONFIGS / "eu_ai_act_risk.yaml"
    return yaml.safe_load(target.read_text(encoding="utf-8"))


def load_thresholds(path: str | Path | None = None) -> dict[str, Any]:
    """Carrega ``configs/thresholds.yaml`` (pesos de impacto e faixas de decisão)."""
    target = Path(path) if path else _CONFIGS / "thresholds.yaml"
    return yaml.safe_load(target.read_text(encoding="utf-8"))


def classify_ai_system(
    capabilities: list[str], config: dict[str, Any] | None = None
) -> tuple[RiskTier, list[str], str]:
    """Classifica o sistema pela pirâmide do EU AI Act (Doc 04, §6-7).

    Avalia as regras EM ORDEM; a primeira cujo ``when_any`` casar com alguma
    *capability* declarada vence. Retorna (tier, obrigações, justificativa).
    """
    config = config or load_risk_config()
    caps = {c.lower() for c in capabilities}
    for rule in config.get("rules", []):
        triggers = {t.lower() for t in rule.get("when_any", [])}
        if caps & triggers:
            tier = RiskTier(rule["tier"])
            return tier, list(AI_ACT_OBLIGATIONS[tier]), rule.get("rationale", "")
    tier = RiskTier(config.get("default_tier", "limited"))
    return tier, list(AI_ACT_OBLIGATIONS[tier]), "Fallback conservador (nenhuma regra casou)."


def aggregate_risk(
    scenarios: list[RiskScenario], thresholds: dict[str, Any] | None = None
) -> float:
    r"""Calcula R = Σ Pj·Ij normalizado em [0, 1] (Doc 04, §7).

    Ij é o peso de impacto da categoria (``thresholds.yaml`` → risk.impact_weights).
    A normalização divide pela soma máxima possível (todos Pj = 1), tornando R
    comparável entre tratamentos.
    """
    thresholds = thresholds or load_thresholds()
    weights: dict[str, float] = thresholds.get("risk", {}).get("impact_weights", {})
    if not scenarios:
        return 0.0
    numerator = sum(s.probability * float(weights.get(s.impact.value, 0.5)) for s in scenarios)
    denominator = sum(float(weights.get(s.impact.value, 0.5)) for s in scenarios) or 1.0
    return round(numerator / denominator, 4)


def decide(aggregate: float, thresholds: dict[str, Any] | None = None) -> str:
    """Traduz o risco agregado em decisão (accept | mitigate | high_risk_review)."""
    thresholds = thresholds or load_thresholds()
    faixas = thresholds.get("risk", {}).get("thresholds", {})
    if aggregate < float(faixas.get("accept_below", 0.15)):
        return "accept"
    if aggregate < float(faixas.get("mitigate_below", 0.45)):
        return "mitigate"
    return "high_risk_review"


def default_scenarios() -> list[RiskScenario]:
    """Cenários de risco do Aurora Assist (evidência das defesas das Aulas 2-4).

    Cada cenário lista a mitigação concreta já construída — é exatamente onde a
    engenharia das aulas anteriores se converte em evidência jurídica (Doc 04, §8).
    """
    return [
        RiskScenario(
            name="vazamento_de_pii",
            probability=0.10,
            impact=ImpactCategory.PII_LEAK,
            description="Resposta do assistente expõe CPF/conta de um titular.",
            mitigation="Guardrail de saída (Aula 2) + minimização com Presidio (Aula 3).",
        ),
        RiskScenario(
            name="tratamento_sem_base_legal",
            probability=0.05,
            impact=ImpactCategory.UNLAWFUL_BASIS,
            description="Uso de conversas para treino sem consentimento explícito.",
            mitigation="Consentimento granular versionado + enforcement na rag-api.",
        ),
        RiskScenario(
            name="decisao_automatizada_de_credito",
            probability=0.08,
            impact=ImpactCategory.AUTOMATED_DECISION,
            description="Assistente decide concessão de crédito sem revisão humana.",
            mitigation="Recusa de decisão automatizada (GDPR art. 22) + human-in-the-loop.",
        ),
        RiskScenario(
            name="retencao_excessiva",
            probability=0.20,
            impact=ImpactCategory.RETENTION_EXCESS,
            description="Logs de tratamento retidos além do necessário.",
            mitigation="Política de retenção por finalidade + purga programada.",
        ),
        RiskScenario(
            name="transferencia_internacional",
            probability=0.15,
            impact=ImpactCategory.CROSS_BORDER,
            description="Dado de brasileiro processado fora do território nacional.",
            mitigation="Residência em Azure Brazil South + Customer-Managed Keys (Aula 3).",
        ),
    ]


def run_dpia(
    system_name: str = "Aurora Assist",
    capabilities: list[str] | None = None,
    scenarios: list[RiskScenario] | None = None,
) -> DPIAResult:
    """Executa a DPIA/RIPD (GDPR art. 35): classifica risco, agrega e decide."""
    risk_cfg = load_risk_config()
    thresholds = load_thresholds()
    caps = (
        capabilities if capabilities is not None else risk_cfg.get("aurora_assist_capabilities", [])
    )
    scen = scenarios if scenarios is not None else default_scenarios()

    tier, obligations, rationale = classify_ai_system(caps, risk_cfg)
    aggregate = aggregate_risk(scen, thresholds)
    decision = decide(aggregate, thresholds)

    residual = [
        "Direito à explicação: LLM é caixa-preta; explicação ex-post é limite técnico "
        "em aberto (Doc 04, §9 — Wachter et al., 2017).",
        "Machine unlearning: purga de vetores cobre o RAG, mas não o conhecimento de "
        "fine-tuning (Doc 04, §10 — Bourtoule et al., 2021). Decisão arquitetural: "
        "evitar treinar com dados pessoais.",
        f"Classificação EU AI Act: {tier.value} — {rationale}",
    ]
    return DPIAResult(
        system_name=system_name,
        risk_tier=tier,
        obligations=obligations,
        scenarios=scen,
        aggregate_risk=aggregate,
        decision=decision,
        residual_notes=residual,
    )


def dpia_to_markdown(result: DPIAResult) -> str:
    """Renderiza a DPIA como documento Markdown (evidência para o DPO)."""
    obligation_lines = [f"- {ob}" for ob in result.obligations] or ["- (nenhuma)"]
    scenario_lines = [
        f"| {s.name} | {s.probability:.2f} | {s.impact.value} | {s.mitigation} |"
        for s in result.scenarios
    ]
    residual_lines = [f"- {note}" for note in result.residual_notes]
    lines = [
        f"# DPIA / RIPD — {result.system_name}",
        "",
        "> Data Protection Impact Assessment (GDPR art. 35 / LGPD art. 38).",
        "> Gerado por `app/dpia.py` a partir de `configs/` — Doc 04, §7-8.",
        "",
        "## 1. Classificação de risco (EU AI Act)",
        f"- **Nível:** `{result.risk_tier.value}`",
        f"- **Decisão sobre o risco agregado:** `{result.decision}`",
        f"- **Risco agregado R = Σ Pj·Ij (normalizado):** `{result.aggregate_risk}`",
        "",
        "### Obrigações herdadas",
        *obligation_lines,
        "",
        "## 2. Cenários de risco e mitigações",
        "| Cenário | P | Impacto | Mitigação |",
        "|---|---|---|---|",
        *scenario_lines,
        "",
        "## 3. Riscos residuais e limites técnicos (honestidade intelectual)",
        *residual_lines,
        "",
        "## 4. Privacy by Design (GDPR art. 25)",
        "- Minimização e anonimização desde a concepção (Aula 3 — Presidio).",
        "- Privacidade como configuração padrão (proativo, não reativo).",
        "- Residência de dados e Customer-Managed Keys (soberania — Schrems II).",
        "",
    ]
    return "\n".join(lines)
