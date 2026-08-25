"""Cofre de tokens e anonimização reversível (Aula 03 — Doc 04, §7).

Valida que o token é DETERMINÍSTICO, não vaza o dado, e que a reversão só
funciona via cofre (o LLM jamais reidrata).
"""

from __future__ import annotations

from src.security import FileTokenVault, InMemoryTokenVault, make_token
from src.security.schemas import PIIEntity


def test_token_is_deterministic():
    # Mesmo valor -> mesmo token (coerência para o LLM — Doc 04, §7).
    t1 = make_token(PIIEntity.BR_CPF, "529.982.247-25", secret="s", digest_len=8)
    t2 = make_token(PIIEntity.BR_CPF, "529.982.247-25", secret="s", digest_len=8)
    assert t1 == t2
    assert t1.startswith("[BR_CPF_TOKEN_")


def test_token_changes_with_value_and_secret():
    a = make_token(PIIEntity.BR_CPF, "529.982.247-25", secret="s")
    b = make_token(PIIEntity.BR_CPF, "111.444.777-35", secret="s")
    c = make_token(PIIEntity.BR_CPF, "529.982.247-25", secret="outro")
    assert a != b  # valores diferentes -> tokens diferentes
    assert a != c  # segredo diferente -> token diferente


def test_token_does_not_leak_value():
    value = "529.982.247-25"
    token = make_token(PIIEntity.BR_CPF, value, secret="s")
    assert value not in token
    assert "529" not in token.split("TOKEN_")[-1]


def test_inmemory_roundtrip():
    vault = InMemoryTokenVault(secret="s")
    token = vault.tokenize(PIIEntity.BR_CPF, "529.982.247-25")
    assert vault.resolve(token) == "529.982.247-25"


def test_unknown_token_resolves_none():
    vault = InMemoryTokenVault(secret="s")
    assert vault.resolve("[BR_CPF_TOKEN_deadbeef]") is None


def test_file_vault_persists(tmp_path):
    path = tmp_path / "vault.json"
    vault = FileTokenVault(path=path, secret="s")
    token = vault.tokenize(PIIEntity.BR_ACCOUNT, "45678-9")
    # Um novo cofre apontando para o mesmo arquivo ainda resolve (persistência).
    reopened = FileTokenVault(path=path, secret="s")
    assert reopened.resolve(token) == "45678-9"
