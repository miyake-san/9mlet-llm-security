"""Registro de operações de tratamento — RoPA com trilha WORM (Aula 05).

Materializa o princípio de **accountability** (Doc 04, §4 — LGPD art. 37 /
GDPR art. 30): cada fluxo do Aurora Assist emite um registro estruturado
(finalidade, base legal, categorias de dado, retenção, destino) que herda a
**imutabilidade** da trilha de auditoria da Aula 4. Reaproveitamos a *hash chain*
(cada entrada encadeia o hash da anterior) para tornar a evidência de
conformidade inviolável por construção — sem depender de nuvem no laboratório
(WORM real: Azure Blob Immutable / Log Analytics).

Somente **metadados** são registrados (minimização, §4): nunca o texto sensível.

Uso (self-test da integridade da cadeia):
    uv run task ropa      # ou: python -m src.security.treatment --self-test

Referência:
    BRASIL (2018). LGPD — art. 37. · UNIÃO EUROPEIA (2016). GDPR — art. 30.
    Haber & Stornetta (1991). How to Time-Stamp a Digital Document (hash chain).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from src.security.schemas import TreatmentRecord

_GENESIS = "0" * 64
_CONFIGS = Path(__file__).resolve().parents[2] / "configs"


def _hash_entry(prev_hash: str, payload: dict[str, Any]) -> str:
    """Hash encadeado da entrada (prev_hash + payload canônico)."""
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(f"{prev_hash}|{canonical}".encode()).hexdigest()


@dataclass
class ChainEntry:
    """Uma entrada da trilha WORM (registro + encadeamento)."""

    index: int
    prev_hash: str
    entry_hash: str
    record: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
            "record": self.record,
        }


class TreatmentRegistry:
    """Registro de tratamento append-only com integridade por hash chain."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self._entries: list[ChainEntry] = []
        self._lock = threading.Lock()
        if self.path:
            self._load()

    # -- persistência --------------------------------------------------------
    def _load(self) -> None:
        if not self.path or not self.path.exists():
            return
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            self._entries.append(
                ChainEntry(
                    index=data["index"],
                    prev_hash=data["prev_hash"],
                    entry_hash=data["entry_hash"],
                    record=data["record"],
                )
            )

    def _append_line(self, entry: ChainEntry) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")

    # -- API -----------------------------------------------------------------
    @property
    def head_hash(self) -> str:
        return self._entries[-1].entry_hash if self._entries else _GENESIS

    def record(self, treatment: TreatmentRecord) -> ChainEntry:
        """Registra uma operação de tratamento (evidência de art. 37)."""
        with self._lock:
            prev = self.head_hash
            payload = treatment.to_dict()
            entry = ChainEntry(
                index=len(self._entries),
                prev_hash=prev,
                entry_hash=_hash_entry(prev, payload),
                record=payload,
            )
            self._entries.append(entry)
            self._append_line(entry)
            return entry

    def entries(self) -> list[ChainEntry]:
        with self._lock:
            return list(self._entries)

    def query(
        self, *, subject_ref: str | None = None, operation: str | None = None
    ) -> list[dict[str, Any]]:
        """Consulta RoPA (o que um auditor pediria — Doc 04, §4)."""
        rows = []
        for entry in self.entries():
            rec = entry.record
            if subject_ref and rec.get("subject_ref") != subject_ref:
                continue
            if operation and rec.get("operation") != operation:
                continue
            rows.append(rec)
        return rows

    def verify(self) -> bool:
        """Verifica a integridade da cadeia (detecta adulteração/reordenação)."""
        prev = _GENESIS
        for i, entry in enumerate(self.entries()):
            if entry.index != i or entry.prev_hash != prev:
                return False
            if _hash_entry(prev, entry.record) != entry.entry_hash:
                return False
            prev = entry.entry_hash
        return True


def load_treatment_policies(path: str | Path | None = None) -> dict[str, Any]:
    """Carrega ``configs/treatment_policies.yaml`` (RoPA por operação)."""
    target = Path(path) if path else _CONFIGS / "treatment_policies.yaml"
    return yaml.safe_load(target.read_text(encoding="utf-8"))


def build_treatment_record(
    operation: str, subject_ref: str, policies: dict[str, Any] | None = None
) -> TreatmentRecord:
    """Monta o registro a partir da política declarada para a operação."""
    policies = policies or load_treatment_policies()
    op = (policies.get("operations") or {}).get(operation)
    if op is None:
        raise KeyError(f"Operação sem política de tratamento declarada: {operation!r}")
    return TreatmentRecord(
        operation=operation,
        legal_basis=op["legal_basis"],
        data_categories=list(op.get("data_categories", [])),
        retention_days=int(op.get("retention_days", 365)),
        transferred_to=op.get("transferred_to", "Azure Brazil South"),
        subject_ref=subject_ref,
        special_category=bool(op.get("special_category", False)),
        gdpr_basis=op.get("gdpr_basis", ""),
    )


def pseudonymize(subject_id: str | None) -> str:
    """Pseudonimiza o id do titular para o registro (Doc 04, §4 — minimização)."""
    raw = (subject_id or "anon").encode("utf-8")
    return "subj-" + hashlib.sha256(raw).hexdigest()[:12]


def _self_test() -> int:
    """Demonstra a imutabilidade: adulterar uma entrada quebra a verificação."""
    reg = TreatmentRegistry()
    policies = load_treatment_policies()
    for op in ("consulta_saldo", "faq_produtos", "consulta_saldo"):
        reg.record(build_treatment_record(op, pseudonymize("cli-90432"), policies))
    ok = reg.verify()
    print(f"[ropa] entradas={len(reg.entries())} head={reg.head_hash[:12]}… íntegra={ok}")
    # Adultera o registro e reprova a verificação (evidência de WORM lógico).
    reg._entries[1].record["retention_days"] = 999999  # noqa: SLF001 (demo didática)
    tampered_ok = reg.verify()
    print(f"[ropa] após adulteração -> íntegra={tampered_ok} (esperado: False)")
    return 0 if (ok and not tampered_ok) else 1


def main() -> None:
    parser = argparse.ArgumentParser(description="Registro de tratamento (RoPA) — Aula 05.")
    parser.add_argument("--self-test", action="store_true", help="valida a hash chain")
    args = parser.parse_args()
    if args.self_test:
        raise SystemExit(_self_test())
    parser.print_help()


if __name__ == "__main__":
    main()
