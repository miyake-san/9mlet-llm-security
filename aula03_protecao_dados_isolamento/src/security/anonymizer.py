"""Anonimização reversível e minimização de dados (Aula 03 — Doc 04, §7 e §12).

Orquestra o **ingress** (tokeniza/mascara/remove PII antes de o LLM ver) e o
**egress** (reidrata tokens para o titular autorizado) do pipeline Zero Trust.
Combina o :class:`Analyzer` (detecção — §5-6), o :class:`TokenVault` (cofre —
§7) e os operadores por entidade (``configs/thresholds.yaml``).

Aplica também a **minimização de dados** do §12: entidades fora da lista
permitida do fluxo são REMOVIDAS já na entrada — "o dado mais seguro é aquele
que não existe".

Referência:
    Microsoft (2024b). Presidio — Anonymizer / OperatorConfig.
    Doc 04, §7 (tokenização reversível) e §12 (minimização).
"""

from __future__ import annotations

import hashlib
import os
import re

from src.security.presidio_bridge import Analyzer, get_analyzer
from src.security.schemas import AnonymizationResult, Operator, PIIEntity, PIIMatch
from src.security.tokenvault import TokenVault, get_token_vault

# Padrão de token gerado pelo cofre: usado no egress para localizar o que reverter.
_TOKEN_RE = re.compile(r"\[[A-Z_]+_TOKEN_[0-9a-f]+\]")

# Operadores padrão por entidade (sobrescritos por configs/thresholds.yaml).
_DEFAULT_OPERATORS: dict[PIIEntity, Operator] = {
    PIIEntity.BR_CPF: Operator.TOKENIZE,
    PIIEntity.BR_CNPJ: Operator.TOKENIZE,
    PIIEntity.BR_ACCOUNT: Operator.TOKENIZE,
    PIIEntity.CREDIT_CARD: Operator.TOKENIZE,
    PIIEntity.BR_RG: Operator.MASK,
    PIIEntity.BR_CEP: Operator.MASK,
    PIIEntity.EMAIL_ADDRESS: Operator.MASK,
    PIIEntity.PHONE_NUMBER: Operator.MASK,
    PIIEntity.PERSON: Operator.REDACT,
}


def mask_value(value: str, keep: int = 2) -> str:
    """Mascara alfanuméricos preservando os últimos ``keep`` (irreversível)."""
    kept = 0
    out: list[str] = []
    for ch in reversed(value):
        if ch.isalnum():
            if kept < keep:
                out.append(ch)
                kept += 1
            else:
                out.append("*")
        else:
            out.append(ch)
    return "".join(reversed(out))


def hash_value(value: str, salt: str = "", length: int = 12) -> str:
    """Pseudonimização irreversível (HMAC/salt) — coerente mas não reversível."""
    digest = hashlib.sha256(f"{salt}:{value}".encode()).hexdigest()[:length]
    return f"[HASH_{digest}]"


class ReversibleAnonymizer:
    """Anonimiza (ingress) e reidrata (egress) o texto do Aurora Assist."""

    def __init__(
        self,
        analyzer: Analyzer | None = None,
        vault: TokenVault | None = None,
        operators: dict[PIIEntity, Operator] | None = None,
        min_score: float = 0.5,
    ) -> None:
        self.analyzer = analyzer or get_analyzer()
        self.vault = vault or get_token_vault()
        self.operators = operators or dict(_DEFAULT_OPERATORS)
        self.min_score = min_score
        self._salt = os.getenv("TOKEN_HMAC_SECRET", "dev-secret-change-me")

    # ------------------------------------------------------------------ #
    # INGRESS — antes de o LLM ver o texto (Doc 04, §7)
    # ------------------------------------------------------------------ #
    def anonymize(
        self,
        text: str,
        allowed_pii: list[PIIEntity] | list[str] | None = None,
    ) -> AnonymizationResult:
        """Detecta PII e aplica o operador de cada entidade (com minimização).

        Args:
            text: texto original (prompt do usuário / documento recuperado).
            allowed_pii: entidades que o fluxo pode RECEBER; ``None`` = todas.
                As demais são removidas (minimização — §12) e marcadas em
                ``minimized``. Passe ``[]`` para minimização máxima.
        """
        matches = self.analyzer.analyze(text, min_score=self.min_score)
        allowed = _normalize(allowed_pii) if allowed_pii is not None else None

        result = AnonymizationResult(text=text, matches=matches)
        # Substitui da direita para a esquerda para preservar os offsets.
        for match in sorted(matches, key=lambda m: m.start, reverse=True):
            operator = self.operators.get(match.entity, Operator.REDACT)
            # Minimização: entidade não permitida no fluxo é sempre removida.
            if allowed is not None and match.entity not in allowed:
                operator = Operator.REDACT
                result.minimized.append(match)

            replacement = self._apply(operator, match, result)
            result.text = result.text[: match.start] + replacement + result.text[match.end :]
        return result

    def _apply(self, operator: Operator, match: PIIMatch, result: AnonymizationResult) -> str:
        if operator == Operator.TOKENIZE:
            token = self.vault.tokenize(match.entity, match.text)
            result.reversible_tokens.append(token)
            return token
        if operator == Operator.MASK:
            return mask_value(match.text)
        if operator == Operator.HASH:
            return hash_value(match.text, salt=self._salt)
        return f"[{match.entity.value}_REDACTED]"

    # ------------------------------------------------------------------ #
    # EGRESS — reidratação para o titular autorizado (Doc 04, §7)
    # ------------------------------------------------------------------ #
    def deanonymize(self, text: str) -> str:
        """Substitui tokens reversíveis pelo valor real (via cofre).

        Só deve ser chamada por um serviço AUTORIZADO, fora do alcance do modelo
        (a camada de apresentação autenticada). Tokens sem entrada no cofre são
        mantidos como estão (fail-safe: nunca inventa dado).
        """

        def _resolve(match: re.Match[str]) -> str:
            token = match.group(0)
            value = self.vault.resolve(token)
            return value if value is not None else token

        return _TOKEN_RE.sub(_resolve, text)


def _normalize(entities: list[PIIEntity] | list[str]) -> set[PIIEntity]:
    return {e if isinstance(e, PIIEntity) else PIIEntity(e) for e in entities}


def operators_from_config(config: dict) -> dict[PIIEntity, Operator]:
    """Constrói o mapa de operadores a partir de ``configs/thresholds.yaml`` (pii.operators)."""
    operators = dict(_DEFAULT_OPERATORS)
    for entity_name, op_name in (config.get("pii", {}).get("operators") or {}).items():
        try:
            operators[PIIEntity(entity_name)] = Operator(op_name)
        except ValueError:
            continue
    return operators
