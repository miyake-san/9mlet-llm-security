"""Avaliação responsável contínua: RAGAS + qualidade + fairness + juiz + gate.

Este módulo é o **eval-runner** da Aula 07 (Doc 04, "Avaliação de RAG, RAGAS" e
"quality gates éticos no CI/CD"). Ele NÃO treina modelos: consome o Aurora Assist
(alvo) e produz evidência mensurável e um **quality gate** que reprova a promoção
de versões que aumentem viés ou reduzam fidelidade/qualidade.

Métricas RAGAS (implementação offline; RAGAS real fica no grupo ``eval``):
    * faithfulness       — a resposta é sustentada pelo contexto recuperado?
    * answer_relevancy   — a resposta de fato responde à pergunta?
    * context_precision  — os documentos recuperados são relevantes?
    * context_recall     — a recuperação cobriu a resposta de referência?

Uso:
    python -m app.eval_ragas --report reports/eval_report.json          # offline (stub)
    python -m app.eval_ragas --report reports/eval_report.json --gate    # falha se violar
    python -m app.eval_ragas --target http://localhost:8000 --report ... # alvo ao vivo

Referência:
    Es, S. et al. (2024). RAGAS. EACL. arXiv:2309.15217.
    Microsoft (2026). Azure AI Evaluation SDK.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Protocol

import httpx
import yaml

from app.config import get_settings
from app.judge import Judge
from app.llm import Decision, Profile, StubBackend
from app.rag import Retriever
from src.security.fairness import (
    counterfactual_report,
    demographic_parity_difference,
    equal_opportunity_difference,
    equalized_odds_difference,
    selection_rate_by_group,
)
from src.security.quality import bleu, rouge_l, semantic_similarity
from src.security.text import is_abstention, tokenize

logger = logging.getLogger(__name__)

_ROOT = Path(__file__).resolve().parents[1]
_DATA = _ROOT / "data"


# --------------------------------------------------------------------------- #
# Carga de dados                                                               #
# --------------------------------------------------------------------------- #
def load_jsonl(path: Path) -> list[dict]:
    """Lê um arquivo JSONL (uma linha = um objeto JSON)."""
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def load_golden() -> list[dict]:
    return load_jsonl(_DATA / "golden" / "golden_qa.jsonl")


def load_profiles() -> list[dict]:
    return load_jsonl(_DATA / "fairness" / "profiles.jsonl")


def load_counterfactual_pairs() -> list[dict]:
    return load_jsonl(_DATA / "fairness" / "counterfactual_pairs.jsonl")


def _profile(d: dict) -> Profile:
    return Profile(
        id=d["id"],
        name=d["name"],
        group=d["group"],
        qualified=int(d["qualified"]),
        income=float(d.get("income", 0.0)),
        request=d.get("request", ""),
    )


# --------------------------------------------------------------------------- #
# Alvos (in-process offline OU HTTP ao vivo)                                   #
# --------------------------------------------------------------------------- #
class Target(Protocol):
    name: str

    def answer(self, question: str) -> tuple[str, list[str]]: ...

    def decide(self, profile: Profile) -> Decision: ...


class InProcessTarget:
    """Alvo offline determinístico (StubBackend + retriever), sem rede."""

    def __init__(self, *, mitigate_fairness: bool = False, strict_grounding: bool = False) -> None:
        self.name = "in-process://stub"
        self.mitigate = mitigate_fairness
        self.strict = strict_grounding
        self.top_k = get_settings().rag_top_k
        self._backend = StubBackend()
        self._retriever = Retriever.from_corpus()

    def answer(self, question: str) -> tuple[str, list[str]]:
        contexts = [doc.text for doc, _ in self._retriever.search(question, self.top_k)]
        text = self._backend.generate(question, contexts, strict_grounding=self.strict)
        return text, contexts

    def decide(self, profile: Profile) -> Decision:
        return self._backend.decide(profile, mitigate_fairness=self.mitigate)


class HttpTarget:
    """Alvo ao vivo: consome a target-api (Aurora Assist) por HTTP."""

    def __init__(self, base_url: str, timeout: float = 30.0) -> None:
        self.name = base_url.rstrip("/")
        self._timeout = timeout

    def answer(self, question: str) -> tuple[str, list[str]]:
        r = httpx.post(f"{self.name}/chat", json={"question": question}, timeout=self._timeout)
        r.raise_for_status()
        body = r.json()
        return body.get("answer", ""), body.get("contexts", [])

    def decide(self, profile: Profile) -> Decision:
        payload = {
            "id": profile.id,
            "name": profile.name,
            "group": profile.group,
            "qualified": profile.qualified,
            "income": profile.income,
            "request": profile.request,
        }
        r = httpx.post(f"{self.name}/decision", json=payload, timeout=self._timeout)
        r.raise_for_status()
        body = r.json()
        return Decision(int(body["outcome"]), body.get("product", ""), body.get("answer", ""))


# --------------------------------------------------------------------------- #
# Métricas RAGAS (proxies offline)                                             #
# --------------------------------------------------------------------------- #
def faithfulness(answer: str, contexts: list[str]) -> float:
    """Fração dos tokens de conteúdo da resposta sustentados pelo contexto.

    Uma abstenção ("não encontrei nos documentos") NÃO faz afirmação não
    sustentada, logo é considerada plenamente fiel (RAGAS trata abstenção honesta
    como faithfulness alta). É por isso que o *grounding* estrito eleva a métrica.
    """
    if is_abstention(answer):
        return 1.0
    ans = set(tokenize(answer, canonical=True, remove_stopwords=True))
    if not ans:
        return 0.0
    ctx = set(tokenize(" ".join(contexts), canonical=True, remove_stopwords=True))
    return round(len(ans & ctx) / len(ans), 4)


def answer_relevancy(answer: str, question: str) -> float:
    """Similaridade semântica entre a resposta e a pergunta."""
    return semantic_similarity(answer, question)


def context_precision(contexts: list[str], reference: str) -> float:
    """Fração dos contextos recuperados que são relevantes à referência."""
    if not contexts:
        return 0.0
    ref = set(tokenize(reference, canonical=True, remove_stopwords=True))
    relevant = 0
    for ctx in contexts:
        ctx_tokens = set(tokenize(ctx, canonical=True, remove_stopwords=True))
        if ref and len(ref & ctx_tokens) / len(ref) >= 0.2:
            relevant += 1
    return round(relevant / len(contexts), 4)


def context_recall(contexts: list[str], reference: str) -> float:
    """Fração dos tokens da referência cobertos pelos contextos recuperados."""
    ref = set(tokenize(reference, canonical=True, remove_stopwords=True))
    if not ref:
        return 0.0
    ctx = set(tokenize(" ".join(contexts), canonical=True, remove_stopwords=True))
    return round(len(ref & ctx) / len(ref), 4)


def _mean(values: list[float]) -> float:
    return round(sum(values) / len(values), 4) if values else 0.0


# --------------------------------------------------------------------------- #
# Avaliações                                                                   #
# --------------------------------------------------------------------------- #
def evaluate_quality_and_ragas(target: Target, golden: list[dict]) -> dict:
    """Roda o alvo sobre o golden set e agrega qualidade + RAGAS."""
    bleus, rouges, semantics = [], [], []
    faiths, relevancies, precisions, recalls = [], [], [], []
    judge = Judge(**_judge_kwargs())
    judge_scores: list[float] = []
    per_item: list[dict] = []

    for item in golden:
        question, reference = item["question"], item["reference"]
        answer, contexts = target.answer(question)
        b, r, s = bleu(answer, reference), rouge_l(answer, reference), semantic_similarity(
            answer, reference
        )
        f = faithfulness(answer, contexts)
        rel = answer_relevancy(answer, question)
        cp = context_precision(contexts, reference)
        cr = context_recall(contexts, reference)
        bleus.append(b)
        rouges.append(r)
        semantics.append(s)
        faiths.append(f)
        relevancies.append(rel)
        precisions.append(cp)
        recalls.append(cr)
        judge_scores.append(judge.ensemble_score(question, answer, contexts))
        per_item.append(
            {"id": item["id"], "bleu": b, "semantic": s, "faithfulness": f, "answer_relevancy": rel}
        )

    return {
        "quality": {
            "mean_bleu": _mean(bleus),
            "mean_rouge_l": _mean(rouges),
            "mean_semantic_similarity": _mean(semantics),
            "n": len(golden),
        },
        "ragas": {
            "faithfulness": _mean(faiths),
            "answer_relevancy": _mean(relevancies),
            "context_precision": _mean(precisions),
            "context_recall": _mean(recalls),
        },
        "judge": {"mean_score": _mean(judge_scores)},
        "per_item": per_item,
    }


def evaluate_fairness(target: Target, profiles: list[dict]) -> dict:
    """Coleta decisões por grupo e calcula as métricas de disparidade."""
    y_true, y_pred, groups = [], [], []
    for raw in profiles:
        profile = _profile(raw)
        decision = target.decide(profile)
        y_true.append(profile.qualified)
        y_pred.append(decision.outcome)
        groups.append(profile.group)
    return {
        "n": len(profiles),
        "selection_rate_by_group": selection_rate_by_group(y_pred, groups),
        "demographic_parity_difference": demographic_parity_difference(
            y_true, y_pred, sensitive_features=groups
        ),
        "equal_opportunity_difference": equal_opportunity_difference(
            y_true, y_pred, sensitive_features=groups
        ),
        "equalized_odds_difference": equalized_odds_difference(
            y_true, y_pred, sensitive_features=groups
        ),
    }


def evaluate_counterfactual(target: Target, pairs: list[dict], *, threshold: float) -> dict:
    """Auditoria contrafactual: só o atributo protegido muda entre a/b."""
    responses: list[tuple[str, str]] = []
    for pair in pairs:
        dec_a = target.decide(_profile(pair["a"]))
        dec_b = target.decide(_profile(pair["b"]))
        responses.append((dec_a.answer, dec_b.answer))
    report = counterfactual_report(responses, threshold=threshold)
    return {
        "threshold": threshold,
        "total_pairs": report.total_pairs,
        "violations": report.violations,
        "violation_rate": report.violation_rate,
        "mean_similarity": report.mean_similarity,
        "min_similarity": report.min_similarity,
    }


def evaluate_judge_bias(target: Target, golden: list[dict]) -> dict:
    """Mede o *position bias* residual do juiz sobre um par de respostas reais."""
    judge = Judge(**_judge_kwargs())
    if len(golden) < 2:
        return {"position_bias_delta": 0.0}
    q = golden[0]["question"]
    ans_a, _ = target.answer(golden[0]["question"])
    ans_b, _ = target.answer(golden[1]["question"])
    return {"position_bias_delta": judge.position_bias_delta(q, ans_a, ans_b)}


def _judge_kwargs() -> dict:
    s = get_settings()
    return {"position_debias": s.judge_debias_position, "ensemble_size": s.judge_ensemble_size}


# --------------------------------------------------------------------------- #
# Quality gate                                                                 #
# --------------------------------------------------------------------------- #
def load_thresholds(path: Path | None = None) -> dict:
    p = path or (_ROOT / get_settings().thresholds_path)
    if not p.exists():
        return {}
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


def check_quality_gate(report: dict, thresholds: dict) -> dict:
    """Compara o relatório com os limiares aprovados. Retorna pass/fail + violações."""
    violations: list[str] = []

    fair = thresholds.get("fairness", {})
    f = report["fairness"]
    if f["demographic_parity_difference"] > fair.get("max_demographic_parity_difference", 1.0):
        violations.append(
            f"demographic_parity_difference={f['demographic_parity_difference']} "
            f"> {fair['max_demographic_parity_difference']}"
        )
    if f["equal_opportunity_difference"] > fair.get("max_equal_opportunity_difference", 1.0):
        violations.append(
            f"equal_opportunity_difference={f['equal_opportunity_difference']} "
            f"> {fair['max_equal_opportunity_difference']}"
        )
    if f["equalized_odds_difference"] > fair.get("max_equalized_odds_difference", 1.0):
        violations.append(
            f"equalized_odds_difference={f['equalized_odds_difference']} "
            f"> {fair['max_equalized_odds_difference']}"
        )

    cf = report["counterfactual"]
    if cf["min_similarity"] < fair.get("min_counterfactual_similarity", 0.0):
        violations.append(
            f"counterfactual min_similarity={cf['min_similarity']} "
            f"< {fair['min_counterfactual_similarity']}"
        )
    if cf["violation_rate"] > fair.get("max_counterfactual_violation_rate", 1.0):
        violations.append(
            f"counterfactual violation_rate={cf['violation_rate']} "
            f"> {fair['max_counterfactual_violation_rate']}"
        )

    rag = thresholds.get("ragas", {})
    r = report["ragas"]
    for key, floor_key in (
        ("faithfulness", "min_faithfulness"),
        ("answer_relevancy", "min_answer_relevancy"),
        ("context_precision", "min_context_precision"),
        ("context_recall", "min_context_recall"),
    ):
        if r[key] < rag.get(floor_key, 0.0):
            violations.append(f"ragas {key}={r[key]} < {rag[floor_key]}")

    qual = thresholds.get("quality", {})
    if report["quality"]["mean_semantic_similarity"] < qual.get("min_semantic_similarity", 0.0):
        violations.append(
            f"mean_semantic_similarity={report['quality']['mean_semantic_similarity']} "
            f"< {qual['min_semantic_similarity']}"
        )

    jud = thresholds.get("judge", {})
    if report["judge"]["mean_score"] < jud.get("min_mean_score", 0.0):
        violations.append(
            f"judge mean_score={report['judge']['mean_score']} < {jud['min_mean_score']}"
        )
    if report["judge"]["position_bias_delta"] > jud.get("max_position_bias_delta", 1.0):
        violations.append(
            f"judge position_bias_delta={report['judge']['position_bias_delta']} "
            f"> {jud['max_position_bias_delta']}"
        )

    return {"passed": not violations, "violations": violations}


# --------------------------------------------------------------------------- #
# Orquestração                                                                 #
# --------------------------------------------------------------------------- #
def run_evaluation(target: Target, *, thresholds: dict | None = None) -> dict:
    """Executa todas as avaliações contra ``target`` e monta o relatório + gate."""
    thresholds = thresholds or load_thresholds()
    cf_threshold = thresholds.get("fairness", {}).get("min_counterfactual_similarity", 0.90)

    golden = load_golden()
    profiles = load_profiles()
    pairs = load_counterfactual_pairs()

    quality_ragas = evaluate_quality_and_ragas(target, golden)
    report: dict = {
        "target": target.name,
        "model_version": get_settings().model_version,
        "quality": quality_ragas["quality"],
        "ragas": quality_ragas["ragas"],
        "fairness": evaluate_fairness(target, profiles),
        "counterfactual": evaluate_counterfactual(target, pairs, threshold=cf_threshold),
        "judge": quality_ragas["judge"],
        "per_item": quality_ragas["per_item"],
    }
    report["judge"].update(evaluate_judge_bias(target, golden))
    report["quality_gate"] = check_quality_gate(report, thresholds)
    return report


def _build_target(args: argparse.Namespace) -> Target:
    if args.target:
        return HttpTarget(args.target)
    return InProcessTarget(
        mitigate_fairness=args.mitigate,
        strict_grounding=args.mitigate,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Aula 07 — avaliação responsável contínua.")
    parser.add_argument("--target", default=None, help="URL da target-api ao vivo (senão offline).")
    parser.add_argument("--report", default="reports/eval_report.json", help="Saída JSON.")
    parser.add_argument("--gate", action="store_true", help="Sai !=0 se o gate reprovar.")
    parser.add_argument(
        "--mitigate",
        action="store_true",
        help="(offline) ativa mitigação de fairness e grounding para medir E.",
    )
    args = parser.parse_args(argv)
    logging.basicConfig(level=get_settings().log_level)

    target = _build_target(args)
    report = run_evaluation(target)

    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    gate = report["quality_gate"]
    verdict = "PASS" if gate["passed"] else "FAIL"
    logger.info("Relatório salvo em %s | gate=%s", report_path, verdict)
    for v in gate["violations"]:
        logger.warning("  violação: %s", v)

    if args.gate and not gate["passed"]:
        print(f"QUALITY GATE FAILED — {len(gate['violations'])} violação(ões).", file=sys.stderr)
        return 1
    print(f"quality gate: {'PASS' if gate['passed'] else 'FAIL'} -> {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
