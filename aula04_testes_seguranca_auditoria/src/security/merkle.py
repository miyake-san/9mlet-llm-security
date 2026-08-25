"""Merkle trees para verificação de integridade em lote (Doc 04, seção 11).

Uma *hash chain* prova a ordem e a imutabilidade sequencial; uma **Merkle tree**
generaliza a verificação para grandes volumes, resumindo N registros em uma
única **raiz criptográfica**. Alterar qualquer folha muda a raiz — permitindo
provar a integridade de toda a trilha de auditoria do Aurora Assist com um único
hash publicável (ex.: em armazenamento WORM).

Referência:
    Merkle, R. C. (1988). A Digital Signature Based on a Conventional Encryption
    Function. In: Advances in Cryptology — CRYPTO '87. Springer.
"""

from __future__ import annotations

import hashlib


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _as_bytes(leaf: str | bytes) -> bytes:
    return leaf.encode("utf-8") if isinstance(leaf, str) else leaf


def merkle_root(leaves: list[str | bytes]) -> str:
    """Calcula a raiz de Merkle (hex) sobre uma lista de folhas.

    Folhas são hasheadas individualmente e combinadas par a par até restar uma
    única raiz. Quando um nível tem número ímpar de nós, o último é duplicado
    (convenção comum). Uma lista vazia retorna o hash do vazio.

    Args:
        leaves: registros (str ou bytes) a resumir.

    Returns:
        Raiz de Merkle em hexadecimal (SHA-256).
    """
    if not leaves:
        return hashlib.sha256(b"").hexdigest()

    level: list[bytes] = [_sha256(_as_bytes(leaf)) for leaf in leaves]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])  # duplica o último nó (nível ímpar)
        level = [_sha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0].hex()
