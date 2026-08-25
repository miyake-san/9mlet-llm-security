"""Trilha de auditoria imutável via *hash chain* (Doc 04, seção 11).

Implementa a cadeia de hashes discutida na seção 11 do Documento 04:

    h_i = H(h_{i-1} ‖ log_i)

Cada registro incorpora o hash do anterior. Se qualquer registro antigo for
alterado, seu hash muda e **invalida todos os hashes seguintes** — tornando a
adulteração detectável. É a base técnica da auditabilidade (Doc 04, seção 10) e
da separação de funções: "quem administra a aplicação não deve conseguir apagar
unilateralmente a evidência de um incidente".

Uso (self-test offline):
    python -m src.security.hash_chain --self-test

Referência:
    Merkle, R. C. (1988). CRYPTO '87.
    ISO/IEC 27001:2022 · ISO/IEC 42001:2023 (controles de auditabilidade).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from src.security.merkle import merkle_root

# Semente do bloco gênese (h_0). Pública e fixa: ancora a cadeia.
GENESIS_SEED = "AURORA-AUDIT-GENESIS"


def genesis_hash() -> str:
    """h_0 — hash gênese que ancora a cadeia."""
    return hashlib.sha256(GENESIS_SEED.encode("utf-8")).hexdigest()


def canonical_json(record: dict) -> str:
    """Serialização canônica (determinística) de um registro.

    Chaves ordenadas e separadores fixos garantem que o mesmo conteúdo produza
    sempre os mesmos bytes — pré-requisito para hashes reprodutíveis.
    """
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_hash(prev_hash: str, record: dict) -> str:
    """h_i = H(h_{i-1} ‖ log_i) — SHA-256 sobre (hash anterior ‖ registro)."""
    payload = f"{prev_hash}||{canonical_json(record)}".encode()
    return hashlib.sha256(payload).hexdigest()


@dataclass
class ChainEntry:
    """Um elo da cadeia de auditoria."""

    seq: int
    timestamp: str
    record: dict
    prev_hash: str
    hash: str

    def recompute(self) -> str:
        """Recalcula o hash deste elo a partir de ``prev_hash`` e ``record``."""
        return compute_hash(self.prev_hash, self.record)


@dataclass
class VerifyResult:
    """Resultado da verificação de integridade da cadeia."""

    intact: bool
    count: int
    merkle_root: str
    broken_at: int | None = None
    reason: str = "ok"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HashChain:
    """Cadeia de hashes append-only (WORM lógico) para eventos de auditoria."""

    entries: list[ChainEntry] = field(default_factory=list)

    @property
    def head(self) -> str:
        """Hash do último elo (ou gênese, se vazia)."""
        return self.entries[-1].hash if self.entries else genesis_hash()

    def append(self, record: dict) -> ChainEntry:
        """Anexa um novo evento, encadeando-o ao hash corrente.

        Args:
            record: dicionário do evento de auditoria (Doc 04, seção 12:
                versão do modelo, decisão de guardrail, score de risco,
                identificador pseudonimizado da conversa etc.).

        Returns:
            O elo (``ChainEntry``) recém-criado.
        """
        prev = self.head
        entry = ChainEntry(
            seq=len(self.entries),
            timestamp=datetime.now(UTC).isoformat(),
            record=record,
            prev_hash=prev,
            hash=compute_hash(prev, record),
        )
        self.entries.append(entry)
        return entry

    def verify(self) -> VerifyResult:
        """Verifica a cadeia inteira: linkagem + hash de cada elo.

        Detecta (a) hash recomputado que não bate (registro adulterado) e
        (b) ``prev_hash`` que não aponta para o hash do elo anterior (elo
        removido/reordenado). Retorna o índice do primeiro elo quebrado.
        """
        expected_prev = genesis_hash()
        for entry in self.entries:
            if entry.prev_hash != expected_prev:
                return VerifyResult(
                    intact=False,
                    count=len(self.entries),
                    merkle_root=self.merkle_root(),
                    broken_at=entry.seq,
                    reason=f"prev_hash divergente no elo {entry.seq} (elo removido/reordenado)",
                )
            if entry.recompute() != entry.hash:
                return VerifyResult(
                    intact=False,
                    count=len(self.entries),
                    merkle_root=self.merkle_root(),
                    broken_at=entry.seq,
                    reason=f"registro adulterado no elo {entry.seq} (hash não confere)",
                )
            expected_prev = entry.hash
        return VerifyResult(
            intact=True,
            count=len(self.entries),
            merkle_root=self.merkle_root(),
        )

    def merkle_root(self) -> str:
        """Raiz de Merkle sobre os hashes dos elos (resumo publicável em WORM)."""
        return merkle_root([e.hash for e in self.entries])

    # ----- Persistência (WORM lógico via arquivo append-only) -------------
    def save(self, path: str | Path) -> None:
        """Persiste a cadeia como JSONL (um elo por linha)."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as fh:
            for entry in self.entries:
                fh.write(json.dumps(asdict(entry), ensure_ascii=False) + "\n")

    @classmethod
    def load(cls, path: str | Path) -> HashChain:
        """Carrega uma cadeia previamente persistida (JSONL)."""
        p = Path(path)
        chain = cls()
        if not p.exists():
            return chain
        with p.open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    d = json.loads(line)
                    chain.entries.append(ChainEntry(**d))
        return chain


def _self_test() -> int:
    """Demonstra a detecção de adulteração (Doc 04, seção 11)."""
    chain = HashChain()
    chain.append({"action": "chat", "decision": "allow", "risk": 0.1})
    chain.append({"action": "chat", "decision": "block", "risk": 0.9})
    chain.append({"action": "tool_call", "decision": "block", "risk": 0.8})

    before = chain.verify()
    print(
        f"[hash-chain] elos={before.count} intacta={before.intact} raiz={before.merkle_root[:16]}…"
    )

    # Adultera retroativamente o registro do elo 1 (simula encobrir um incidente).
    chain.entries[1].record["decision"] = "allow"
    after = chain.verify()
    print(f"[hash-chain] após adulteração: intacta={after.intact} quebrou_no_elo={after.broken_at}")
    print(f"[hash-chain] motivo: {after.reason}")

    ok = before.intact and (not after.intact) and after.broken_at == 1
    print("[hash-chain] SELF-TEST:", "PASSOU" if ok else "FALHOU")
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Hash chain de auditoria (Aula 04).")
    parser.add_argument(
        "--self-test", action="store_true", help="roda a demonstração de adulteração"
    )
    args = parser.parse_args()
    if args.self_test:
        return _self_test()
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
