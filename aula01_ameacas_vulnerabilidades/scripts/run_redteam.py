#!/usr/bin/env python
"""Campanha de red team executada pelo container `redteam-runner` (vídeo 4).

Fluxo (Doc 04, HANDS ON + seção 10):
    1. Replay offline dos ataques rotulados contra a API vulnerável -> métricas.
    2. Garak (probes dan/encoding/leakreplay) — não-fatal se ausente.
    3. PyRIT (demo de Base64Converter) — não-fatal se ausente.

Todos os relatórios são escritos em REPORT_DIR (montado em ./reports no host).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.security.redteam import (  # noqa: E402
    HttpTarget,
    load_attacks,
    load_benign,
    run_garak,
    run_pyrit_demo,
    run_replay,
)


def main() -> int:
    api_url = os.getenv("AURORA_API_URL", "http://vulnerable-rag-api:8000")
    report_dir = Path(os.getenv("REPORT_DIR", "reports"))
    report_dir.mkdir(parents=True, exist_ok=True)
    data_dir = Path(__file__).resolve().parents[1] / "data"

    attacks = load_attacks(data_dir)
    benign = load_benign(data_dir)

    print(f"[redteam] alvo={api_url} | ataques={len(attacks)} | benignos={len(benign)}")
    target = HttpTarget(api_url)
    try:
        result = run_replay(target, attacks, benign)
    finally:
        target.close()

    (report_dir / "attack_replay.json").write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"[replay] attack_success_rate={result.attack_success_rate:.2%}")
    print(f"[replay] false_positive_rate={result.false_positive_rate:.2%}")

    garak = run_garak(report_dir=str(report_dir))
    (report_dir / "garak_status.json").write_text(
        json.dumps(garak, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"[garak] status={garak['status']}")

    pyrit = run_pyrit_demo()
    (report_dir / "pyrit_status.json").write_text(
        json.dumps(pyrit, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"[pyrit] status={pyrit['status']}")

    print(f"[redteam] relatórios em {report_dir}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
