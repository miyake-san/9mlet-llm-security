"""Guardrail de COMPORTAMENTO — política conversacional *policy-as-code*.

Materializa o conceito de *policy-as-code* (Doc 04, seção 5): a política de
escopo do Aurora Assist é um ARTEFATO VERSIONÁVEL, e não instruções soltas em
um prompt frágil. Em produção, o caminho é o **NVIDIA NeMo Guardrails** com a
linguagem **Colang** (grupo opcional ``frameworks``). Para manter o lab
offline e o teste rápido, esta classe é um *interpretador Colang-lite*: lê o
mesmo arquivo ``rails.co`` e aplica os fluxos de recusa por tópico.

O objetivo pedagógico é o da Figura 2 do Doc 04: um "trilho conversacional"
com uma linha principal (assuntos do Banco Aurora) e ramificações de recusa
para três intenções: fora de escopo, dados de terceiros e exfiltração de
instruções internas.

Referência:
    Rebedea, T. et al. (2023). NeMo Guardrails. EMNLP 2023 (System Demos).
    Doc 04, seção 5 (policy-as-code) e Figura 2 (trilho conversacional).
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from .schemas import Layer, LayerResult, Verdict

# Tokens genéricos (verbos/pronomes) que NÃO caracterizam tópico — evitam falso
# positivo em FAQs legítimas ("qual o horário de funcionamento?").
_STOPWORDS = {
    "fale", "sobre", "qual", "quais", "conte", "conto", "escreva", "recomende",
    "sua", "seu", "suas", "seus", "opiniao", "opinião", "favor", "quero",
    "gostaria", "poderia", "para", "como", "isso", "essa", "esse", "voce", "você",
}

# Termos que indicam assunto bancário legítimo (linha principal do trilho).
_BANKING_TERMS = (
    r"saldo", r"extrato", r"\bconta\b", r"\bpix\b", r"\bted\b", r"cart[ãa]o",
    r"empr[eé]stimo", r"fatura", r"investi", r"transfer", r"ag[êe]ncia",
    r"boleto", r"limite", r"financiamento", r"aplica[çc][ãa]o",
)

# Intenções protegidas independentemente de conterem termos bancários:
# pedir dados de OUTRO cliente é violação de privacidade (não é "assunto do banco").
_OTHER_CLIENT = re.compile(
    r"(outro cliente|outra pessoa|de terceiro|do terceiro|de um cliente|"
    r"de outra pessoa|correntista|do cliente\s+\w+|de outro)", re.IGNORECASE
)
_OTHER_CLIENT_DATA = re.compile(
    r"(saldo|dados|cpf|conta|extrato|senha|cart[ãa]o|endere[çc]o|telefone)", re.IGNORECASE
)
_REVEAL_INSTRUCTIONS = re.compile(
    r"(system prompt|prompt do sistema|instru[çc][õo]es internas|suas instru[çc][õo]es|"
    r"regras de seguran[çc]a|como voc[êe] foi (configurad|instru[íi]d))",
    re.IGNORECASE,
)


@dataclass
class BehaviorPolicy:
    """Política de comportamento carregada de um arquivo Colang (``.co``)."""

    refusal_off_topic: str = "Posso ajudar apenas com assuntos do Banco Aurora."
    refusal_other_client: str = "Não posso acessar ou revelar dados de outros clientes."
    refusal_reveal: str = "Não posso compartilhar minhas instruções internas de segurança."
    off_topic_keywords: list[str] = field(default_factory=list)

    @classmethod
    def from_colang(cls, path: str | Path) -> BehaviorPolicy:
        """Carrega a política a partir de um arquivo Colang (``rails.co``).

        Extrai os exemplos dos blocos ``define user ask off topic`` e as
        mensagens canônicas dos blocos ``define bot refuse ...``.
        """
        text = Path(path).read_text(encoding="utf-8")
        policy = cls(off_topic_keywords=[])
        off_topic_examples: list[str] = []
        current_intent: str | None = None
        current_bot: str | None = None

        for raw_line in text.splitlines():
            line = raw_line.strip()
            if line.startswith("define user"):
                current_intent, current_bot = line[len("define user"):].strip(), None
                continue
            if line.startswith("define bot"):
                current_bot, current_intent = line[len("define bot"):].strip(), None
                continue
            if line.startswith("define flow") or line.startswith("#") or not line:
                continue
            quoted = re.findall(r'"([^"]+)"', line)
            if not quoted:
                continue
            if current_intent and "off topic" in current_intent:
                off_topic_examples.extend(quoted)
            elif current_bot == "refuse off topic":
                policy.refusal_off_topic = quoted[0]
            elif current_bot == "refuse other client":
                policy.refusal_other_client = quoted[0]
            elif current_bot == "refuse reveal instructions":
                policy.refusal_reveal = quoted[0]

        # Deriva palavras-chave "fortes" de tópico (filtra stopwords/verbos).
        keywords: set[str] = set()
        for example in off_topic_examples:
            for token in re.findall(r"[A-Za-zÀ-ÿ]{4,}", example.lower()):
                if token not in _STOPWORDS:
                    keywords.add(token)
        policy.off_topic_keywords = sorted(keywords)
        return policy

    def _looks_banking(self, lowered: str) -> bool:
        return any(re.search(term, lowered) for term in _BANKING_TERMS)

    def evaluate(self, text: str) -> tuple[Verdict, str, dict]:
        """Avalia o texto contra os três trilhos de recusa."""
        lowered = text.lower()

        # 1) Exfiltração de instruções internas (bloqueia sempre).
        if _REVEAL_INSTRUCTIONS.search(lowered):
            return Verdict.BLOCK, self.refusal_reveal, {"intent": "reveal_instructions"}

        # 2) Dados de terceiros (privacidade — bloqueia mesmo com termo bancário).
        if _OTHER_CLIENT.search(lowered) and _OTHER_CLIENT_DATA.search(lowered):
            return Verdict.BLOCK, self.refusal_other_client, {"intent": "other_client"}

        # 3) Fora de escopo (só se NÃO parecer assunto bancário — reduz FP).
        hits = [kw for kw in self.off_topic_keywords if re.search(rf"\b{re.escape(kw)}", lowered)]
        if hits and not self._looks_banking(lowered):
            return Verdict.BLOCK, self.refusal_off_topic, {"intent": "off_topic", "keywords": hits}

        return Verdict.ALLOW, "Dentro do escopo do Banco Aurora", {"intent": "in_scope"}


def check_behavior(text: str, policy: BehaviorPolicy) -> LayerResult:
    """Aplica a política de comportamento e devolve um :class:`LayerResult`."""
    start = time.perf_counter()
    verdict, reason, details = policy.evaluate(text)
    latency_ms = (time.perf_counter() - start) * 1000
    return LayerResult(
        layer=Layer.BEHAVIOR,
        verdict=verdict,
        score=1.0 if verdict == Verdict.BLOCK else 0.0,
        reason=reason,
        details=details,
        latency_ms=latency_ms,
    )
