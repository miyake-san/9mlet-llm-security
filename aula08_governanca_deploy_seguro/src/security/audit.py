"""Trilha de auditoria imutável por encadeamento de hash (reuso da Aula 04).

A resposta a incidentes de IA (Doc 04, §7) depende de evidência confiável: "sem
evidência, não há investigação possível". Este módulo encadeia eventos por hash
(cada elo incorpora o hash do anterior), tornando adulterações retroativas
detectáveis, e expõe uma raiz de Merkle para verificação de integridade. Em
produção, o destino seria o **Azure Blob Immutable Storage** (WORM real).

Referência:
    Merkle, R. C. (1988). CRYPTO '87.
    ISO/IEC 27001:2022 · ISO/IEC 42001:2023 (auditabilidade).
    Microsoft (2026). Azure Blob Immutable Storage (WORM). · Doc 04, §7.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


@dataclass
class AuditEntry:
    seq: int
    timestamp: float
    record: dict
    prev_hash: str
    hash: str

    def to_dict(self) -> dict:
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "record": self.record,
            "prev_hash": self.prev_hash,
            "hash": self.hash,
        }


class HashChain:
    """Cadeia append-only: hᵢ = H(hᵢ₋₁ ‖ logᵢ) — WORM lógico (Doc 04, §7)."""

    GENESIS = "0" * 64

    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def append(self, record: dict) -> AuditEntry:
        prev = self.entries[-1].hash if self.entries else self.GENESIS
        seq = len(self.entries)
        ts = time.time()
        payload = json.dumps(record, sort_keys=True, ensure_ascii=False)
        entry_hash = _sha256(f"{prev}|{seq}|{ts}|{payload}")
        entry = AuditEntry(seq=seq, timestamp=ts, record=record, prev_hash=prev, hash=entry_hash)
        self.entries.append(entry)
        return entry

    def verify(self) -> bool:
        """Reprocessa a cadeia e confirma que nenhum elo foi adulterado."""
        prev = self.GENESIS
        for entry in self.entries:
            payload = json.dumps(entry.record, sort_keys=True, ensure_ascii=False)
            expected = _sha256(f"{prev}|{entry.seq}|{entry.timestamp}|{payload}")
            if expected != entry.hash or entry.prev_hash != prev:
                return False
            prev = entry.hash
        return True

    def merkle_root(self) -> str:
        """Raiz de Merkle das folhas (hashes dos elos) para verificação compacta."""
        if not self.entries:
            return self.GENESIS
        level = [e.hash for e in self.entries]
        while len(level) > 1:
            if len(level) % 2 == 1:
                level.append(level[-1])
            level = [_sha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        return level[0]
