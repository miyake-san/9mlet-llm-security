"""Ferramenta de consulta de saldo — INSEGURA por design (LLM07/LLM08).

Demonstra o padrão 'confused deputy' (Doc 04, seção 8): a ferramenta aceita um
CPF arbitrário em texto livre, sem autenticação nem autorização, e devolve um
dado sensível. Em uma arquitetura segura, a ferramenta deveria aceitar apenas o
identificador do cliente AUTENTICADO, retornar dados mínimos e nunca permitir
consulta arbitrária por CPF (correção prevista para a Aula 03).

Referência:
    OWASP Foundation (2025). Top 10 for LLM Applications — LLM07, LLM08.
"""

from __future__ import annotations

import hashlib

from src.security.detectors import detect_br_pii


def extract_cpf(text: str) -> str | None:
    """Extrai o primeiro CPF encontrado no texto (heurística de formato)."""
    for span in detect_br_pii(text):
        if span.type == "CPF":
            return span.value
    return None


def get_balance(cpf: str) -> float:
    """Retorna um saldo SINTÉTICO determinístico para qualquer CPF (inseguro).

    Não há verificação de propriedade/autorização — é justamente essa ausência
    de controle server-side que a aula quer evidenciar. O valor é derivado de um
    hash do CPF apenas para ser reprodutível; nenhum dado real é usado.
    """
    digits = "".join(ch for ch in cpf if ch.isdigit())
    seed = int(hashlib.sha256(digits.encode("utf-8")).hexdigest(), 16)
    return round((seed % 1_000_000) / 100.0, 2)
