"""CLI de geração do AIBOM (AI Bill of Materials) — Snippet 1 do Doc 04 (§8).

Equivalente offline do ``cyclonedx-py environment --output-file aibom.cdx.json``:
gera o inventário CycloneDX ML-BOM do Aurora Assist (modelo base, datasets,
fine-tunes e dependências) e o persiste. No container ``aibom-gen`` do compose,
o mesmo passo roda no pipeline DevSecOps (governança como código).

Uso:
    python -m app.aibom --output reports/aibom.cdx.json
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from src.security.aibom import aibom_completeness, write_aibom

logger = logging.getLogger(__name__)
_ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Gera o AIBOM (CycloneDX ML-BOM) do Aurora Assist."
    )
    parser.add_argument("--output", default="reports/aibom.cdx.json", help="Arquivo de saída JSON.")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO)
    out_path = _ROOT / args.output
    aibom = write_aibom(out_path, _ROOT)
    check = aibom_completeness(aibom)

    logger.info("AIBOM gerado: %s (%d componentes)", out_path, check["component_count"])
    logger.info("Completude: %s | checks=%s", check["complete"], check["checks"])
    print(json.dumps({"output": str(out_path), **check}, ensure_ascii=False, indent=2))
    return 0 if check["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
