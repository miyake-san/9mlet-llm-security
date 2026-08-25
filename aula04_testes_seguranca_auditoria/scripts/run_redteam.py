#!/usr/bin/env python
"""Campanha de red team executada pelo container `redteam-ci` (vídeo 4).

Fluxo (Doc 04, ciclo PAIR + seções 6-13):
    1. Campanha (replay single-turn + crescendo) contra a target-api -> métricas.
    2. Severidade CVSS-AI + quality gate + relatório executivo em reports/.
    3. Garak (probes) — não-fatal se ausente.
    4. PyRIT (converters) — não-fatal se ausente.
    5. promptfoo (gate is-refusal) — não-fatal se ausente.
    6. Verificação da trilha de auditoria (audit-log) — evidência de integridade.

Código de saída != 0 quando o quality gate reprova (shift-left security).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx  # noqa: E402

from app.redteam_ci import run_ci, write_reports  # noqa: E402
from src.security.redteam import (  # noqa: E402
    HttpTarget,
    run_garak,
    run_promptfoo,
    run_pyrit_demo,
)


def _verify_audit(audit_url: str, report_dir: Path) -> None:
    """Consulta /verify do audit-log e salva a evidência de integridade."""
    try:
        resp = httpx.get(f"{audit_url.rstrip('/')}/verify", timeout=5.0)
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPError as exc:  # limite: serviço externo
        data = {"status": "unavailable", "reason": str(exc)}
    (report_dir / "audit_verify.json").write_text(
        json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"[audit] integridade da trilha: {data}")


def main() -> int:
    api_url = os.getenv("TARGET_API_URL", "http://target-api:8000")
    audit_url = os.getenv("AUDIT_LOG_URL", "http://audit-log:8091")
    report_dir = Path(os.getenv("REPORT_DIR", "reports"))
    report_dir.mkdir(parents=True, exist_ok=True)

    print(f"[redteam-ci] alvo={api_url}")
    target = HttpTarget(api_url)
    try:
        report = run_ci(target)
    finally:
        target.close()

    write_reports(report, report_dir)
    s = report["summary"]
    gate = report["quality_gate"]["passed"]
    print(f"[campaign] ASR={s['attack_success_rate']:.2%} | bloqueio={s['overall_block_rate']:.2%}")
    print(f"[campaign] jailbreak ASR={s['jailbreak_asr']:.2%} | FP={s['false_positive_rate']:.2%}")
    print(f"[gate] quality gate: {'APROVADO' if gate else 'REPROVADO'}")

    # Ferramentas externas (não-fatais se ausentes).
    for name, result in (
        ("garak", run_garak(report_dir=str(report_dir))),
        ("pyrit", run_pyrit_demo()),
        ("promptfoo", run_promptfoo()),
    ):
        (report_dir / f"{name}_status.json").write_text(
            json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"[{name}] status={result['status']}")

    _verify_audit(audit_url, report_dir)
    print(f"[redteam-ci] relatórios em {report_dir}/")
    return 0 if gate else 2


if __name__ == "__main__":
    raise SystemExit(main())
