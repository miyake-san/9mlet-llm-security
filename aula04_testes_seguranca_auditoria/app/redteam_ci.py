"""redteam-ci — orquestra a campanha, aplica quality gates e gera o relatório.

É a fase **Report** do ciclo PAIR (Doc 04, seções 3, 9, 13-14). Consome o harness
(`src.security.redteam`), calcula severidade **CVSS-AI** por classe OWASP, avalia
os **quality gates** de CI/CD (``configs/thresholds.yaml``), mede *time-to-detect*
e produz dois artefatos em ``reports/``:

    * ``redteam_report.json``   — evidência estruturada (para SIEM/automação).
    * ``executive_summary.md``  — relatório executivo (para decisão de negócio).

Uso:
    python -m app.redteam_ci --target http://target-api:8000 --report reports/redteam_report.json

Referência:
    Microsoft (2024). PyRIT / Lessons from Red Teaming 100 GenAI Products.
    promptfoo (2026). CI/CD security gates. · FIRST (2024). CVSS v4.0.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

import yaml

from app.cvss_ai import cvss_ai_score, mitigation_effectiveness, score_finding, severity_band
from src.security.metrics import block_rate, severity_distribution, summarize_latency
from src.security.redteam import (
    CampaignResult,
    HttpTarget,
    Target,
    load_attacks,
    load_benign,
    load_crescendo,
    run_campaign,
)

logger = logging.getLogger(__name__)

_CONFIG_PATH = Path(__file__).resolve().parents[1] / "configs" / "thresholds.yaml"
_JAILBREAK_TECHNIQUES = {
    "dan_jailbreak",
    "role_play_jailbreak",
    "policy_stripping",
    "jailbreak",
    "crescendo",
}


@lru_cache
def load_thresholds() -> dict:
    """Carrega ``configs/thresholds.yaml`` (com fallback vazio se ausente)."""
    try:
        return yaml.safe_load(_CONFIG_PATH.read_text(encoding="utf-8")) or {}
    except OSError:
        return {}


# --------------------------------------------------------------------------- #
# Construção do relatório                                                      #
# --------------------------------------------------------------------------- #
def _jailbreak_asr(result: CampaignResult) -> float:
    jb = [o for o in result.outcomes if o.technique in _JAILBREAK_TECHNIQUES]
    if not jb:
        return 0.0
    return sum(o.success for o in jb) / len(jb)


def _findings(result: CampaignResult) -> list[dict]:
    """Um achado CVSS-AI por classe OWASP observada (Doc 04, seção 13)."""
    findings = []
    for owasp, stats in sorted(result.by_owasp.items()):
        findings.append(
            score_finding(owasp, stats["rate"], description=f"ASR observada em {owasp}")
        )
    return sorted(findings, key=lambda f: f["score"], reverse=True)


def _evaluate_gate(result: CampaignResult, thresholds: dict) -> dict:
    """Avalia os quality gates adversariais (Doc 04, seção 9 e Tabela 2)."""
    gate = thresholds.get("quality_gate", {})
    checks: list[dict] = []

    # 1) Bloqueio mínimo por classe OWASP (B = 1 - ASR).
    for owasp, min_block in gate.get("block_rate_min", {}).items():
        stats = result.by_owasp.get(owasp)
        if stats is None:
            continue
        observed = round(block_rate(stats["rate"]), 4)
        checks.append(
            {
                "check": f"block_rate[{owasp}] >= {min_block}",
                "observed": observed,
                "threshold": min_block,
                "passed": observed >= min_block,
            }
        )

    # 2) ASR de jailbreak abaixo do teto.
    jb_max = gate.get("jailbreak_asr_max")
    if jb_max is not None:
        observed = round(_jailbreak_asr(result), 4)
        checks.append(
            {
                "check": f"jailbreak_asr <= {jb_max}",
                "observed": observed,
                "threshold": jb_max,
                "passed": observed <= jb_max,
            }
        )

    # 3) Bloqueio médio agregado.
    overall_min = gate.get("overall_block_rate_min")
    if overall_min is not None:
        observed = round(block_rate(result.attack_success_rate), 4)
        checks.append(
            {
                "check": f"overall_block_rate >= {overall_min}",
                "observed": observed,
                "threshold": overall_min,
                "passed": observed >= overall_min,
            }
        )

    # 4) Falso positivo máximo.
    fp_max = gate.get("false_positive_max")
    if fp_max is not None:
        observed = round(result.false_positive_rate, 4)
        checks.append(
            {
                "check": f"false_positive_rate <= {fp_max}",
                "observed": observed,
                "threshold": fp_max,
                "passed": observed <= fp_max,
            }
        )

    # 5) Time-to-detect (P95 da latência de decisão).
    lat = summarize_latency(result.latencies_ms)
    ttd_max = gate.get("time_to_detect_p95_ms_max")
    if ttd_max is not None:
        checks.append(
            {
                "check": f"time_to_detect_p95_ms <= {ttd_max}",
                "observed": lat["p95_ms"],
                "threshold": ttd_max,
                "passed": lat["p95_ms"] <= ttd_max,
            }
        )

    return {"passed": all(c["passed"] for c in checks) if checks else True, "checks": checks}


def _mitigation_roadmap(findings: list[dict], thresholds: dict) -> list[dict]:
    """Backlog priorizado por severidade e prioridade OWASP (Doc 04, seção 14)."""
    priority = thresholds.get("owasp_priority", {})
    actions = {
        "LLM01": "Normalizar entrada (de-ofuscar) antes do filtro; validar conversa multi-turno.",
        "LLM02": "Reforçar guardrail de saída e política de conteúdo (harms de conteúdo).",
        "LLM06": "Bloquear vazamento de PII/canário; aplicar Presidio no egress (Aula 03).",
        "LLM08": "Exigir autorização por ferramenta; menor privilégio (Aula 03).",
    }
    roadmap = []
    for f in findings:
        if f["severity"] in ("none", "low"):
            continue
        roadmap.append(
            {
                "owasp": f["owasp"],
                "severity": f["severity"],
                "score": f["score"],
                "priority": priority.get(f["owasp"], "medium"),
                "action": actions.get(f["owasp"], "Investigar e adicionar caso de regressão."),
            }
        )
    return roadmap


def build_report(result: CampaignResult, thresholds: dict | None = None) -> dict:
    """Monta o relatório completo (evidência + severidade + gate + roadmap)."""
    thresholds = thresholds or load_thresholds()
    findings = _findings(result)
    gate = _evaluate_gate(result, thresholds)
    baseline = thresholds.get("attack_success_rate", {}).get("baseline_reference", 0.30)
    lat = summarize_latency(result.latencies_ms)

    by_owasp = {}
    for owasp, stats in result.by_owasp.items():
        by_owasp[owasp] = {
            **stats,
            "block_rate": round(block_rate(stats["rate"]), 4),
            "cvss_ai_score": cvss_ai_score(owasp, stats["rate"]),
            "severity": severity_band(cvss_ai_score(owasp, stats["rate"])),
        }

    return {
        "target": result.target,
        "generated_at": datetime.now(UTC).isoformat(),
        "summary": {
            "total_attacks": result.total_attacks,
            "successes": result.successes,
            "attack_success_rate": round(result.attack_success_rate, 4),
            "overall_block_rate": round(block_rate(result.attack_success_rate), 4),
            "false_positive_rate": round(result.false_positive_rate, 4),
            "jailbreak_asr": round(_jailbreak_asr(result), 4),
            "baseline_reference_asr": baseline,
            "mitigation_effectiveness_vs_baseline": round(
                mitigation_effectiveness(baseline, result.attack_success_rate), 4
            ),
        },
        "by_owasp": by_owasp,
        "findings": findings,
        "severity_distribution": severity_distribution(f["severity"] for f in findings),
        "time_to_detect": lat,
        "quality_gate": gate,
        "mitigation_roadmap": _mitigation_roadmap(findings, thresholds),
    }


# --------------------------------------------------------------------------- #
# Relatório executivo (Markdown)                                               #
# --------------------------------------------------------------------------- #
def executive_summary_md(report: dict) -> str:
    """Gera o relatório executivo em Markdown (Doc 04, seção 14)."""
    s = report["summary"]
    gate = report["quality_gate"]
    verdict = "✅ APROVADO" if gate["passed"] else "❌ REPROVADO"
    lines = [
        "# Relatório Executivo — Red Team do Aurora Assist (Aula 04)",
        "",
        f"- **Alvo:** `{report['target']}`",
        f"- **Data:** {report['generated_at']}",
        f"- **Quality gate de deploy:** {verdict}",
        "",
        "## 1. Sumário executivo",
        "",
        f"Foram executados **{s['total_attacks']}** ataques. A **taxa de sucesso (ASR)** foi de "
        f"**{s['attack_success_rate']:.1%}** (B = {s['overall_block_rate']:.1%}). O ASR de "
        f"*jailbreak* ficou em **{s['jailbreak_asr']:.1%}** e o falso positivo em "
        f"**{s['false_positive_rate']:.1%}**. Ante a linha de base de referência "
        f"({s['baseline_reference_asr']:.0%}), a efetividade da mitigação é "
        f"**E = {s['mitigation_effectiveness_vs_baseline']:.1%}** (Doc 04, seção 13).",
        "",
        "## 2. Severidade por classe (CVSS-AI)",
        "",
        "| OWASP | ASR | Bloqueio | CVSS-AI | Severidade |",
        "|---|---|---|---|---|",
    ]
    for owasp, st in sorted(report["by_owasp"].items()):
        lines.append(
            f"| {owasp} | {st['rate']:.1%} | {st['block_rate']:.1%} | "
            f"{st['cvss_ai_score']} | {st['severity']} |"
        )
    lines += [
        "",
        "## 3. Quality gate (Doc 04, seção 9)",
        "",
        "| Verificação | Observado | Limiar | Resultado |",
        "|---|---|---|---|",
    ]
    for c in gate["checks"]:
        lines.append(
            f"| {c['check']} | {c['observed']} | {c['threshold']} | "
            f"{'✅' if c['passed'] else '❌'} |"
        )
    lines += ["", "## 4. Roadmap de mitigação priorizado", ""]
    if report["mitigation_roadmap"]:
        lines += ["| OWASP | Severidade | Prioridade | Ação recomendada |", "|---|---|---|---|"]
        for m in report["mitigation_roadmap"]:
            lines.append(f"| {m['owasp']} | {m['severity']} | {m['priority']} | {m['action']} |")
    else:
        lines.append("Nenhum achado de severidade média ou superior. 🎉")
    lines += [
        "",
        "## 5. Time-to-detect",
        "",
        f"- Latência de decisão P95: **{report['time_to_detect']['p95_ms']} ms** "
        f"(média {report['time_to_detect']['mean_ms']} ms).",
        "",
        "> ⚠️ Campanha executada em laboratório controlado, com dados sintéticos "
        "e autorização explícita (Doc 04, seção 14). Próximo passo: "
        "**Aula 05 — Conformidade (LGPD/GDPR/EU AI Act)**.",
        "",
    ]
    return "\n".join(lines)


def write_reports(report: dict, report_dir: str | Path) -> tuple[Path, Path]:
    """Escreve ``redteam_report.json`` e ``executive_summary.md`` em ``report_dir``."""
    out = Path(report_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / "redteam_report.json"
    md_path = out / "executive_summary.md"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(executive_summary_md(report), encoding="utf-8")
    return json_path, md_path


def run_ci(target: Target) -> dict:
    """Executa a campanha completa contra ``target`` e retorna o relatório."""
    attacks = load_attacks()
    benign = load_benign()
    crescendo = load_crescendo()
    result = run_campaign(target, attacks, benign, crescendo)
    return build_report(result)


def main() -> int:
    parser = argparse.ArgumentParser(description="Red team CI do Aurora Assist (Aula 04).")
    parser.add_argument("--target", default="http://target-api:8000", help="URL da target-api")
    parser.add_argument("--report", default="reports/redteam_report.json", help="caminho do JSON")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    target = HttpTarget(args.target)
    try:
        report = run_ci(target)
    finally:
        target.close()

    report_dir = Path(args.report).parent
    write_reports(report, report_dir)
    s = report["summary"]
    print(f"[redteam-ci] alvo={report['target']}")
    print(
        f"[redteam-ci] ASR={s['attack_success_rate']:.2%} | bloqueio={s['overall_block_rate']:.2%}"
    )
    verdict = "APROVADO" if report["quality_gate"]["passed"] else "REPROVADO"
    print(f"[redteam-ci] quality gate: {verdict}")
    print(f"[redteam-ci] relatórios em {report_dir}/")
    # Código de saída != 0 reprova o pipeline (shift-left security — Doc 04, seção 9).
    return 0 if report["quality_gate"]["passed"] else 2


if __name__ == "__main__":
    sys.exit(main())
