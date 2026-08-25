"""app.dpia — CLI de classificação de risco e geração de DPIA (Aula 05).

Executa a DPIA/RIPD do Aurora Assist (GDPR art. 35; Doc 04, §7-8): classifica o
sistema pela pirâmide do EU AI Act, calcula o risco agregado R = Σ Pj·Ij e emite
o documento Markdown para aprovação do DPO.

Uso:
    uv run task dpia                          # classifica + escreve reports/dpia_*.md
    python -m app.dpia --classify
    python -m app.dpia --report reports/dpia_aurora_assist.md
    python -m app.dpia --capabilities credit_decision   # simula migração p/ alto risco

Referência:
    UNIÃO EUROPEIA (2024). EU AI Act. · GDPR art. 35. · Doc 04, §7-8.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from src.security.dpia import dpia_to_markdown, run_dpia


def main() -> None:
    parser = argparse.ArgumentParser(description="DPIA / classificação de risco — Aula 05.")
    parser.add_argument("--classify", action="store_true", help="imprime a classificação")
    parser.add_argument("--report", default=None, help="escreve a DPIA em Markdown no caminho")
    parser.add_argument(
        "--capabilities",
        nargs="*",
        default=None,
        help="capabilities do sistema (ex.: credit_decision para simular alto risco)",
    )
    parser.add_argument("--system", default="Aurora Assist", help="nome do sistema")
    args = parser.parse_args()

    result = run_dpia(system_name=args.system, capabilities=args.capabilities)

    if args.classify or not args.report:
        print(f"Sistema:        {result.system_name}")
        print(f"Nível EU AI Act: {result.risk_tier.value}")
        print(f"Risco agregado:  R = {result.aggregate_risk}  ->  decisão: {result.decision}")
        print("Obrigações:     " + (", ".join(result.obligations) or "(nenhuma)"))
        print("\nCenários (P × impacto):")
        for s in result.scenarios:
            print(f"  - {s.name:32s} P={s.probability:.2f}  impacto={s.impact.value}")

    if args.report:
        path = Path(args.report)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dpia_to_markdown(result), encoding="utf-8")
        print(f"\n[dpia] documento escrito em {path}")


if __name__ == "__main__":
    main()
