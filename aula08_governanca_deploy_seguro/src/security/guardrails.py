"""Guardrails multi-camada embarcados no agente (reuso da Aula 02).

O agente Aurora Assist do capstone integra a defesa em profundidade da Aula 02
diretamente na orquestração (Doc 04, §9: o **Microsoft Agent Framework** constrói
agentes "com guardrails (Aula 2) e isolamento de ferramentas via MCP (Aula 3)").
Implementação pura e offline (sem chamadas de rede): as camadas cobrem

    * ENTRADA  — detecção de *prompt injection*/jailbreak (LLM01:2025).
    * SAÍDA    — redação de PII (LLM06:2025) e checagem de *grounding* (LLM09).

Quando o agente sobe com ``AGENT_GUARDRAILS_ENABLED=false`` (padrão pedagógico),
estas camadas ficam inertes -> o jailbreak escapa e a PII vaza -> problema
mensurável que o *deploy gate* (Doc 04, §6) reprova. Ligá-las neutraliza o risco.

Referência:
    Sutton, S. (2025). AI-Native LLM Security (defense-in-depth).
    Greshake, K. et al. (2023). Not what you've signed up for (indirect injection).
    OWASP Foundation (2025). Top 10 for LLM Applications — LLM01/LLM06/LLM09.
    Doc 04, §9 (DevSecOps) e §10 (arquitetura integrada).
"""

from __future__ import annotations

import re

from src.security.schemas import GuardDecision, LayerResult, Verdict
from src.security.text import content_tokens, is_abstention, normalize

# --- Padrões de injeção/jailbreak (subconjunto didático da Aula 02) ---------
_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ignore_instructions",
        re.compile(r"ignore (todas|as|previous|all|any).{0,20}(instru|rules|regras)"),
    ),
    (
        "override_system",
        re.compile(r"(desconsidere|esque[cç]a|forget).{0,20}(sistema|system|prompt)"),
    ),
    ("dan_jailbreak", re.compile(r"\b(dan|do anything now|modo desenvolvedor|developer mode)\b")),
    (
        "role_play_bypass",
        re.compile(
            r"(finja|pretenda|aja como|act as|voc[eê] agora [eé]).{0,30}(sem|no|livre|unrestricted)"
        ),
    ),
    (
        "exfiltrate_prompt",
        re.compile(
            r"(revele|mostre|repita|reveal|print)"
            r".{0,20}(system prompt|prompt do sistema|instru[cç][õo]es)"
        ),
    ),
    (
        "encoding_evasion",
        re.compile(r"(base64|rot13|leetspeak|decodifique|decode).{0,20}(execute|run|responda)"),
    ),
)

# --- Padrões de PII PT-BR na SAÍDA (redação, não bloqueio) ------------------
_PII_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("CPF", re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")),
    ("CNPJ", re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b")),
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")),
    ("PHONE", re.compile(r"\(?\d{2}\)?\s?9?\d{4}-?\d{4}\b")),
    ("CARD", re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b")),
)


def detect_injection(text: str) -> LayerResult:
    """Camada de ENTRADA: detecta prompt injection/jailbreak (LLM01:2025)."""
    low = normalize(text)
    for name, pattern in _INJECTION_PATTERNS:
        if pattern.search(low):
            return LayerResult(
                layer="input.injection",
                verdict=Verdict.BLOCK,
                reason=f"padrão de injeção/jailbreak detectado: {name}",
                score=1.0,
                details={"pattern": name},
            )
    return LayerResult(layer="input.injection", verdict=Verdict.ALLOW, score=0.0)


def redact_pii(text: str, *, token: str = "[REDACTED_{entity}]") -> tuple[str, list[str]]:
    """Redige PII PT-BR no texto (corrige em vez de bloquear — Snippet 2 da Aula 02)."""
    found: list[str] = []
    redacted = text
    for entity, pattern in _PII_PATTERNS:
        if pattern.search(redacted):
            found.append(entity)
            redacted = pattern.sub(token.format(entity=entity), redacted)
    return redacted, found


def check_output_pii(text: str) -> LayerResult:
    """Camada de SAÍDA: redige PII vazada pela resposta (LLM06:2025)."""
    redacted, found = redact_pii(text)
    if found:
        return LayerResult(
            layer="output.pii",
            verdict=Verdict.REDACT,
            reason=f"PII redigida: {', '.join(sorted(set(found)))}",
            score=1.0,
            details={"redacted_text": redacted, "entities": sorted(set(found))},
        )
    return LayerResult(layer="output.pii", verdict=Verdict.ALLOW, score=0.0)


def check_grounding(answer: str, contexts: list[str], *, min_overlap: int = 2) -> LayerResult:
    """Camada de SAÍDA: a resposta é sustentada pelo contexto? (LLM09 — alucinação).

    Uma abstenção honesta é considerada fundamentada (não afirma fato não
    sustentado). Caso contrário, exige-se sobreposição mínima de termos de
    conteúdo com o contexto recuperado (Doc 04, §6 — groundedness como gatilho).
    """
    if is_abstention(answer):
        return LayerResult(
            layer="output.grounding", verdict=Verdict.ALLOW, reason="abstenção", score=1.0
        )
    ans = content_tokens(answer)
    ctx = content_tokens(" ".join(contexts))
    overlap = len(ans & ctx)
    grounded = overlap >= min_overlap
    return LayerResult(
        layer="output.grounding",
        verdict=Verdict.ALLOW if grounded else Verdict.BLOCK,
        reason="fundamentada" if grounded else "não sustentada pelo contexto (possível alucinação)",
        score=round(overlap / (len(ans) or 1), 4),
        details={"overlap": overlap},
    )


class GuardrailPipeline:
    """Compõe as camadas de entrada e saída conforme o *flag* de habilitação.

    Reproduz o defense-in-depth da Aula 02 (Figura 1) de forma enxuta para o
    agente do capstone. Quando ``enabled=False``, as camadas passam tudo adiante
    (Aurora Assist ingênuo), expondo problemas mensuráveis para o deploy gate.
    """

    def __init__(self, *, enabled: bool = True, strict_grounding: bool = True) -> None:
        self.enabled = enabled
        self.strict_grounding = strict_grounding

    def run_input(self, text: str) -> GuardDecision:
        decision = GuardDecision(stage="input")
        if not self.enabled:
            decision.add(LayerResult(layer="input.disabled", verdict=Verdict.ALLOW))
            return decision
        decision.add(detect_injection(text))
        return decision

    def run_output(self, answer: str, contexts: list[str]) -> GuardDecision:
        decision = GuardDecision(stage="output")
        current = answer
        if not self.enabled:
            decision.add(LayerResult(layer="output.disabled", verdict=Verdict.ALLOW))
            decision.final_text = current
            return decision

        pii = decision.add(check_output_pii(current))
        if pii.verdict == Verdict.REDACT:
            current = pii.details["redacted_text"]

        if self.strict_grounding:
            decision.add(check_grounding(current, contexts))

        decision.final_text = current
        return decision
