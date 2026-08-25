"""Pipeline de proteção de dados do Aurora Assist + CLI de avaliação (Aula 03).

Este módulo orquestra o **ingress/egress** de PII (Doc 04, §7) parametrizado por
PERFIL DE FLUXO (``configs/thresholds.yaml`` — minimização por criticidade, §12).
É consumido pelo :mod:`app.main` (papel rag) e expõe um CLI de avaliação da
DETECÇÃO de PII (``python -m app.pii --evaluate``) que mede precisão, revocação,
F1 e **taxa de vazamento** contra ``data/pii_samples`` — o mesmo raciocínio
quantitativo da Aula 02, agora aplicado ao DADO (§6).

Referência:
    Microsoft (2024b). Presidio. · Doc 04, §6 (FN/FP), §7 (reversível), §12 (minimização).
"""

from __future__ import annotations

import argparse
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import yaml

from src.security import (
    ReversibleAnonymizer,
    detection_confusion,
    get_analyzer,
    get_token_vault,
    operators_from_config,
)
from src.security.anonymizer import _DEFAULT_OPERATORS  # operadores base

_APP_DIR = Path(__file__).resolve().parent
_PROJECT_DIR = _APP_DIR.parent
_CONFIGS_DIR = _PROJECT_DIR / "configs"


@dataclass
class FlowProfile:
    """Perfil de minimização por criticidade de fluxo (Doc 04, §12)."""

    name: str
    allowed_pii: list[str] = field(default_factory=list)
    rehydrate_on_egress: bool = False
    required_tool_scopes: list[str] = field(default_factory=list)


def load_thresholds(path: str | Path | None = None) -> dict[str, Any]:
    """Carrega ``configs/thresholds.yaml``."""
    target = Path(path) if path else _CONFIGS_DIR / "thresholds.yaml"
    return yaml.safe_load(target.read_text(encoding="utf-8"))


def load_flow_profiles(thresholds: dict[str, Any]) -> dict[str, FlowProfile]:
    profiles: dict[str, FlowProfile] = {}
    for name, cfg in (thresholds.get("flows") or {}).items():
        profiles[name] = FlowProfile(
            name=name,
            allowed_pii=list(cfg.get("allowed_pii", [])),
            rehydrate_on_egress=bool(cfg.get("rehydrate_on_egress", False)),
            required_tool_scopes=list(cfg.get("required_tool_scopes", [])),
        )
    return profiles


class DataProtectionPipeline:
    """Anonimiza (ingress) e reidrata (egress) conforme o perfil de fluxo."""

    def __init__(
        self,
        thresholds: dict[str, Any] | None = None,
        anonymizer: ReversibleAnonymizer | None = None,
    ) -> None:
        self.thresholds = thresholds or load_thresholds()
        self.profiles = load_flow_profiles(self.thresholds)
        min_score = float(self.thresholds.get("pii", {}).get("min_score", 0.5))
        operators = operators_from_config(self.thresholds) if self.thresholds else dict(
            _DEFAULT_OPERATORS
        )
        self.anonymizer = anonymizer or ReversibleAnonymizer(
            analyzer=get_analyzer(),
            vault=get_token_vault(),
            operators=operators,
            min_score=min_score,
        )

    def profile(self, flow: str) -> FlowProfile:
        return self.profiles.get(flow) or self.profiles.get("faq") or FlowProfile(name=flow)

    def anonymize(self, text: str, flow: str = "faq"):
        """Ingress: remove/tokeniza PII segundo o `allowed_pii` do fluxo."""
        profile = self.profile(flow)
        allowed = profile.allowed_pii if profile.name in self.profiles else None
        return self.anonymizer.anonymize(text, allowed_pii=allowed)

    def deanonymize(self, text: str, flow: str = "faq") -> str:
        """Egress: reidrata tokens SOMENTE se o fluxo autorizar (titular)."""
        if not self.profile(flow).rehydrate_on_egress:
            return text
        return self.anonymizer.deanonymize(text)


# ====================================================================== #
# CLI de avaliação da detecção de PII (Doc 04, §6)
# ====================================================================== #
def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def _evaluate_offline(pipeline: DataProtectionPipeline, data_dir: Path) -> dict[str, Any]:
    rows = _read_jsonl(data_dir / "pii_samples" / "pii_samples.jsonl")
    expected: list[list[str]] = []
    predicted: list[list[str]] = []
    residual_leaks = 0
    latencies: list[float] = []

    analyzer = pipeline.anonymizer.analyzer
    min_score = pipeline.anonymizer.min_score
    for row in rows:
        text = row["text"]
        expected.append(list(row.get("entities", [])))
        started = time.perf_counter()
        matches = analyzer.analyze(text, min_score=min_score)
        latencies.append((time.perf_counter() - started) * 1000)
        predicted.append([m.entity.value for m in matches])

        # Vazamento pós-anonimização: nenhuma PII deve sobrar no texto anonimizado.
        result = pipeline.anonymize(text, flow="authenticated")
        leftover = analyzer.analyze(result.text, min_score=min_score)
        residual_leaks += len(leftover)

    cm = detection_confusion(expected, predicted)
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
    return {
        "mode": "offline",
        "samples": len(rows),
        "detection": cm.to_dict(),
        "post_anonymization_residual_pii": residual_leaks,
        "avg_detection_latency_ms": round(avg_latency, 3),
    }


def _evaluate_live(api_url: str, data_dir: Path, flow: str) -> dict[str, Any]:
    rows = _read_jsonl(data_dir / "pii_samples" / "pii_samples.jsonl")
    expected: list[list[str]] = []
    predicted: list[list[str]] = []
    latencies: list[float] = []
    with httpx.Client(timeout=60.0) as client:
        for row in rows:
            expected.append(list(row.get("entities", [])))
            started = time.perf_counter()
            response = client.post(
                f"{api_url.rstrip('/')}/anonymize",
                json={"message": row["text"], "flow": flow},
            )
            response.raise_for_status()
            latencies.append((time.perf_counter() - started) * 1000)
            body = response.json()
            predicted.append(list(body.get("entities_found", {}).keys()))

    cm = detection_confusion(expected, predicted)
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
    return {
        "mode": "live",
        "api": api_url,
        "flow": flow,
        "samples": len(rows),
        "detection": cm.to_dict(),
        "avg_api_latency_ms": round(avg_latency, 3),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Avaliação de detecção de PII da Aula 03")
    parser.add_argument("--evaluate", action="store_true", help="roda a avaliação de PII")
    parser.add_argument("--live", action="store_true", help="avalia contra o rag-api em execução")
    parser.add_argument("--flow", default="authenticated", help="perfil de fluxo (live)")
    parser.add_argument("--data-dir", default="data", help="diretório de datasets")
    parser.add_argument("--report", default="reports/pii_eval.json", help="saída JSON")
    args = parser.parse_args(argv)

    if not args.evaluate:
        parser.print_help()
        return 0

    data_dir = Path(args.data_dir)
    if args.live:
        api_url = os.getenv("AURORA_API_URL", "http://localhost:8000")
        report = _evaluate_live(api_url, data_dir, args.flow)
    else:
        report = _evaluate_offline(DataProtectionPipeline(), data_dir)

    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"\n[ok] relatório salvo em {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
