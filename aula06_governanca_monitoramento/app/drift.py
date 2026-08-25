"""CLI de detecção de drift sobre janelas de tráfego (Aula 06 — `task drift`).

Compara uma janela de REFERÊNCIA (baseline) com a janela de PRODUÇÃO e roda os
quatro testes do Doc 04 (§"Detecção estatística de drift"): MMD nos embeddings
de prompts (prompt drift), KS no comprimento das respostas e Wasserstein na
groundedness (response drift), e PSI na latência (estabilidade populacional).
Escreve um relatório JSON em ``reports/`` e faz a leitura INTEGRADA dos sinais
(observar vs abrir incidente). Opcionalmente gera um relatório Evidently (HTML).

Uso:
    uv run task drift
    python -m app.drift --reference data/traffic/reference.jsonl \
        --production data/traffic/production.jsonl --report reports/drift_report.json

Referência:
    Gretton et al. (2012). MMD. · Gama et al. (2014). · Doc 04, §Drift.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

import yaml

from src.security.drift import DriftDetector
from src.security.schemas import DriftMethod, utc_now_iso

logger = logging.getLogger(__name__)

_ROOT = Path(__file__).resolve().parent.parent
_THRESHOLDS = _ROOT / "configs" / "thresholds.yaml"


def _load_traffic(path: Path) -> dict[str, list]:
    """Lê tráfego JSONL: {prompt, latency_ms, response_len, groundedness}."""
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    return {
        "prompts": [r.get("prompt", "") for r in rows],
        "latency_ms": [float(r.get("latency_ms", 0.0)) for r in rows],
        "response_len": [float(r.get("response_len", 0.0)) for r in rows],
        "groundedness": [float(r.get("groundedness", 0.0)) for r in rows],
    }


def _thresholds() -> dict:
    if _THRESHOLDS.exists():
        return yaml.safe_load(_THRESHOLDS.read_text(encoding="utf-8")).get("drift", {})
    return {}


def run(reference: Path, production: Path, report: Path, use_evidently: bool = False) -> dict:
    """Executa a detecção de drift e grava o relatório JSON."""
    ref = _load_traffic(reference)
    now = _load_traffic(production)
    detector = DriftDetector(_thresholds())

    results = [
        detector.prompt_drift(ref["prompts"], now["prompts"]),
        detector.response_drift(ref["response_len"], now["response_len"], method=DriftMethod.KS),
        detector.response_drift(ref["groundedness"], now["groundedness"]),
        detector.credit_stability(ref["latency_ms"], now["latency_ms"]),
    ]
    assessment = detector.assess(results)
    payload = {
        "generated_at": utc_now_iso(),
        "reference": str(reference),
        "production": str(production),
        "assessment": assessment,
        "results": [r.to_dict() for r in results],
    }

    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    if use_evidently:
        _maybe_evidently(ref, now, report.parent / "evidently_drift.html")

    return payload


def _maybe_evidently(ref: dict, now: dict, out: Path) -> None:  # pragma: no cover
    """Gera relatório Evidently (opcional; grupo `evidently`)."""
    try:
        import pandas as pd
        from evidently.metric_preset import DataDriftPreset
        from evidently.report import Report
    except ImportError:
        logger.warning("Evidently indisponível (instale o grupo `evidently`).")
        return
    ref_df = pd.DataFrame(
        {"response_len": ref["response_len"], "groundedness": ref["groundedness"]}
    )
    now_df = pd.DataFrame(
        {"response_len": now["response_len"], "groundedness": now["groundedness"]}
    )
    rpt = Report(metrics=[DataDriftPreset()])
    rpt.run(reference_data=ref_df, current_data=now_df)
    rpt.save_html(str(out))
    logger.info("Relatório Evidently salvo em %s", out)


def main() -> None:  # pragma: no cover - linha de comando
    from rich import print as rprint

    parser = argparse.ArgumentParser(description="Detecção de drift (Aula 06).")
    parser.add_argument("--reference", default=str(_ROOT / "data/traffic/reference.jsonl"))
    parser.add_argument("--production", default=str(_ROOT / "data/traffic/production.jsonl"))
    parser.add_argument("--report", default=str(_ROOT / "reports/drift_report.json"))
    parser.add_argument("--evidently", action="store_true", help="gera HTML (grupo evidently)")
    args = parser.parse_args()

    ref, prod, rep = Path(args.reference), Path(args.production), Path(args.report)
    if not ref.exists() or not prod.exists():
        rprint("[red]Tráfego não encontrado.[/red] Rode `uv run task seed-data` primeiro.")
        raise SystemExit(1)

    payload = run(ref, prod, rep, use_evidently=args.evidently)
    rprint(f"[bold]Decisão de drift:[/bold] {payload['assessment']['decision'].upper()}")
    for res in payload["results"]:
        flag = "DRIFT" if res["drifted"] else "ok"
        rprint(
            f"  [{flag}] {res['method']:11s} {res['drift_type']:14s} "
            f"stat={res['statistic']:.4f} sev={res['severity']}"
        )
    rprint(f"Relatório salvo em: {rep}")


if __name__ == "__main__":
    main()
