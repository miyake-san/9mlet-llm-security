"""Pipeline de guardrails multi-camada — orquestra o *defense-in-depth*.

Este módulo é o coração da Aula 02: compõe as muralhas concêntricas da Figura 1
do Documento 04 (entrada → comportamento → moderação → modelo → saída) em um
único :class:`GuardrailPipeline`, parametrizado por PERFIL DE FLUXO
(``configs/thresholds.yaml`` — Tabela 2 do Doc 04).

Também expõe um CLI de AVALIAÇÃO ADVERSARIAL (``python -m app.guardrails
--evaluate``) que mede taxa de bloqueio, FP/FN e F1 contra os datasets
``data/attacks`` (HarmBench/AdvBench-style) e ``data/benign`` — Doc 04, seção 9.

Referência:
    Sutton, S. (2025). AI-Native LLM Security (defense-in-depth).
    Mazeika et al. (2024) HarmBench; Zou et al. (2023) AdvBench.
    Doc 04, seções 1, 8 e 9.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import yaml

from src.security import (
    BehaviorPolicy,
    GuardDecision,
    Layer,
    Verdict,
    check_behavior,
    check_content_safety,
    check_input_injection,
    check_llama_guard,
    check_output_pii,
    check_output_toxicity,
    confusion_from_scores,
    get_content_safety,
)
from src.security.content_safety import ContentSafety
from src.security.llama_guard import LlamaGuardClient

# --- Localização robusta de políticas/thresholds (funciona local e no container) ---
_APP_DIR = Path(__file__).resolve().parent
_POLICIES_DIR = _APP_DIR / "policies"
_PROJECT_DIR = _APP_DIR.parent
_CONFIGS_DIR = _PROJECT_DIR / "configs"


@dataclass
class FlowProfile:
    """Perfil de bloqueio por criticidade de fluxo (Doc 04, Tabela 2)."""

    name: str
    content_safety_block_at: int = 4
    require_behavior_policy: bool = True
    require_llama_guard: bool = False
    require_output_schema: bool = False
    require_output_pii: bool = True
    jailbreak_block: bool = True


def load_thresholds(path: str | Path | None = None) -> dict[str, Any]:
    """Carrega ``configs/thresholds.yaml``."""
    target = Path(path) if path else _CONFIGS_DIR / "thresholds.yaml"
    return yaml.safe_load(target.read_text(encoding="utf-8"))


def load_flow_profiles(thresholds: dict[str, Any]) -> dict[str, FlowProfile]:
    """Constrói os :class:`FlowProfile` a partir do dicionário de thresholds."""
    profiles: dict[str, FlowProfile] = {}
    for name, cfg in (thresholds.get("flows") or {}).items():
        profiles[name] = FlowProfile(
            name=name,
            content_safety_block_at=int(cfg.get("content_safety_block_at", 4)),
            require_behavior_policy=bool(cfg.get("require_behavior_policy", True)),
            require_llama_guard=bool(cfg.get("require_llama_guard", False)),
            require_output_schema=bool(cfg.get("require_output_schema", False)),
            require_output_pii=bool(cfg.get("require_output_pii", True)),
            jailbreak_block=bool(cfg.get("jailbreak_block", True)),
        )
    return profiles


class GuardrailPipeline:
    """Compõe as camadas de guardrail conforme o perfil de fluxo."""

    def __init__(
        self,
        policy: BehaviorPolicy | None = None,
        thresholds: dict[str, Any] | None = None,
        llama_guard: LlamaGuardClient | None = None,
        content_safety: ContentSafety | None = None,
    ) -> None:
        self.thresholds = thresholds or load_thresholds()
        self.profiles = load_flow_profiles(self.thresholds)
        self.policy = policy or BehaviorPolicy.from_colang(_POLICIES_DIR / "rails.co")
        self.llama_guard = llama_guard or LlamaGuardClient()
        self.content_safety = content_safety or get_content_safety()

        input_cfg = self.thresholds.get("input_guardrail", {})
        self.injection_block_score = float(input_cfg.get("injection_block_score", 0.5))
        output_cfg = self.thresholds.get("output_guardrail", {})
        self.block_pii_entities = output_cfg.get("block_pii_entities")
        self.redact_token = output_cfg.get("redact_token", "[REDACTED_{entity}]")

    def profile(self, flow: str) -> FlowProfile:
        """Retorna o perfil do fluxo (default: ``faq``)."""
        return self.profiles.get(flow) or self.profiles.get("faq") or FlowProfile(name=flow)

    # ------------------------------------------------------------------ #
    # Guardrails de ENTRADA (antes da inferência)
    # ------------------------------------------------------------------ #
    def run_input(self, text: str, flow: str = "faq", short_circuit: bool = True) -> GuardDecision:
        """Executa as camadas de entrada. Ordem = muralhas da Figura 1."""
        profile = self.profile(flow)
        decision = GuardDecision(flow=flow)

        decision.add(check_input_injection(text, block_score=self.injection_block_score))
        if short_circuit and not decision.allowed:
            return decision

        if profile.require_behavior_policy:
            decision.add(check_behavior(text, self.policy))
            if short_circuit and not decision.allowed:
                return decision

        if profile.require_llama_guard:
            decision.add(check_llama_guard(text, client=self.llama_guard, role="user"))
            if short_circuit and not decision.allowed:
                return decision

        decision.add(
            check_content_safety(
                text,
                moderator=self.content_safety,
                block_at=profile.content_safety_block_at,
            )
        )
        return decision

    # ------------------------------------------------------------------ #
    # Guardrails de SAÍDA (antes de entregar ao cliente)
    # ------------------------------------------------------------------ #
    def run_output(self, text: str, flow: str = "faq") -> GuardDecision:
        """Executa as camadas de saída; corrige PII e valida contrato/toxicidade."""
        profile = self.profile(flow)
        decision = GuardDecision(flow=flow)
        current_text = text

        # Moderação de conteúdo na saída (severidade graduada).
        decision.add(
            check_content_safety(
                current_text,
                moderator=self.content_safety,
                block_at=profile.content_safety_block_at,
            )
        )
        if not decision.allowed:
            return decision

        # Toxicidade da resposta.
        decision.add(check_output_toxicity(current_text))
        if not decision.allowed:
            return decision

        # Redação de PII (corrige em vez de bloquear — Snippet 2 do Doc 04).
        if profile.require_output_pii:
            pii_result = check_output_pii(
                current_text,
                entities=self.block_pii_entities,
                token=self.redact_token,
            )
            decision.add(pii_result)
            if pii_result.verdict == Verdict.REDACT:
                current_text = pii_result.details["redacted_text"]

        decision.final_text = current_text
        return decision

    # ------------------------------------------------------------------ #
    # Fluxo completo guardrailado (usado pelo gateway)
    # ------------------------------------------------------------------ #
    def guard_chat(
        self,
        text: str,
        upstream: Callable[[str], str],
        flow: str = "faq",
    ) -> dict[str, Any]:
        """Entrada → (upstream LLM/RAG) → saída, com bloqueio em cada muralha."""
        refusal = "Desculpe, não posso ajudar com essa solicitação por motivos de segurança."
        started = time.perf_counter()

        input_decision = self.run_input(text, flow=flow)
        if not input_decision.allowed:
            return {
                "answer": refusal,
                "blocked": True,
                "stage": "input",
                "decision": input_decision.to_dict(),
                "total_latency_ms": round((time.perf_counter() - started) * 1000, 3),
            }

        raw_answer = upstream(text)

        output_decision = self.run_output(raw_answer, flow=flow)
        if not output_decision.allowed:
            return {
                "answer": refusal,
                "blocked": True,
                "stage": "output",
                "decision": output_decision.to_dict(),
                "total_latency_ms": round((time.perf_counter() - started) * 1000, 3),
            }

        return {
            "answer": output_decision.final_text or raw_answer,
            "blocked": False,
            "stage": "delivered",
            "input_decision": input_decision.to_dict(),
            "output_decision": output_decision.to_dict(),
            "total_latency_ms": round((time.perf_counter() - started) * 1000, 3),
        }


# ====================================================================== #
# CLI de avaliação adversarial (Doc 04, seção 9)
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


def _input_risk_score(decision: GuardDecision) -> float:
    """Score contínuo agregado das camadas de entrada (insumo da ROC)."""
    input_layers = {
        Layer.INPUT_INJECTION,
        Layer.BEHAVIOR,
        Layer.LLAMA_GUARD,
        Layer.CONTENT_SAFETY,
    }
    scores = [r.score for r in decision.layers if r.layer in input_layers]
    return max(scores) if scores else 0.0


def _evaluate_offline(pipeline: GuardrailPipeline, data_dir: Path, flow: str) -> dict[str, Any]:
    attacks = _read_jsonl(data_dir / "attacks" / "attacks.jsonl")
    benign = _read_jsonl(data_dir / "benign" / "benign.jsonl")
    samples = [(row["prompt"], 1) for row in attacks] + [(row["prompt"], 0) for row in benign]

    scores: list[float] = []
    labels: list[int] = []
    per_layer_blocks: dict[str, int] = {}
    latencies: list[float] = []

    for prompt, label in samples:
        decision = pipeline.run_input(prompt, flow=flow, short_circuit=False)
        scores.append(_input_risk_score(decision))
        labels.append(label)
        latencies.append(decision.total_latency_ms)
        if not decision.allowed and decision.blocked_by:
            per_layer_blocks[decision.blocked_by.value] = (
                per_layer_blocks.get(decision.blocked_by.value, 0) + 1
            )

    cm = confusion_from_scores(scores, labels, threshold=0.5)
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
    return {
        "mode": "offline",
        "flow": flow,
        "samples": len(samples),
        "attacks": len(attacks),
        "benign": len(benign),
        "confusion_matrix": cm.to_dict(),
        "blocks_by_layer": per_layer_blocks,
        "avg_input_latency_ms": round(avg_latency, 3),
    }


def _evaluate_live(gateway_url: str, data_dir: Path, flow: str) -> dict[str, Any]:
    attacks = _read_jsonl(data_dir / "attacks" / "attacks.jsonl")
    benign = _read_jsonl(data_dir / "benign" / "benign.jsonl")
    samples = [(row["prompt"], 1) for row in attacks] + [(row["prompt"], 0) for row in benign]

    tp = fp = tn = fn = 0
    latencies: list[float] = []
    with httpx.Client(timeout=60.0) as client:
        for prompt, label in samples:
            response = client.post(
                f"{gateway_url.rstrip('/')}/guardrail",
                json={"message": prompt, "flow": flow},
            )
            response.raise_for_status()
            body = response.json()
            blocked = bool(body.get("blocked"))
            latencies.append(float(body.get("total_latency_ms", 0.0)))
            if label == 1 and blocked:
                tp += 1
            elif label == 1 and not blocked:
                fn += 1
            elif label == 0 and blocked:
                fp += 1
            else:
                tn += 1

    from src.security import ConfusionMatrix

    cm = ConfusionMatrix(tp=tp, fp=fp, tn=tn, fn=fn)
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
    return {
        "mode": "live",
        "gateway": gateway_url,
        "flow": flow,
        "samples": len(samples),
        "confusion_matrix": cm.to_dict(),
        "avg_gateway_latency_ms": round(avg_latency, 3),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Avaliação de guardrails da Aula 02")
    parser.add_argument("--evaluate", action="store_true", help="roda a avaliação adversarial")
    parser.add_argument("--live", action="store_true", help="ataca o gateway em execução")
    parser.add_argument(
        "--backend",
        default="stub",
        help="LLM backend (stub|groq|ollama|azure); stub evita chamadas",
    )
    parser.add_argument("--flow", default="authenticated", help="perfil de fluxo")
    parser.add_argument("--data-dir", default="data", help="diretório de datasets")
    parser.add_argument("--report", default="reports/guardrail_eval.json", help="saída JSON")
    args = parser.parse_args(argv)

    if not args.evaluate:
        parser.print_help()
        return 0

    os.environ.setdefault("LLM_BACKEND", args.backend)
    data_dir = Path(args.data_dir)

    if args.live:
        gateway_url = os.getenv("AURORA_GATEWAY_URL", "http://localhost:8080")
        report = _evaluate_live(gateway_url, data_dir, args.flow)
    else:
        pipeline = GuardrailPipeline()
        report = _evaluate_offline(pipeline, data_dir, args.flow)

    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"\n[ok] relatório salvo em {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
