"""Gestão de consentimento granular e versionado (Aula 05).

Implementa o consentimento **específico por finalidade** e **versionado**
discutido no Hands On e no §3 do Documento 04. Cada concessão/revogação gera uma
nova **versão** do registro (histórico auditável), respondendo à pergunta do
auditor da ANPD: *qual versão dos termos o titular aceitou, e quando?*

Três backends, com o MESMO contrato (:class:`ConsentStore`):
    * :class:`InMemoryConsentStore` — offline/testes (padrão).
    * :class:`FileConsentStore`     — persistência simples em JSONL (append-only).
    * :class:`PostgresConsentStore` — produção-like (análogo ao Azure Cosmos DB
      do Snippet 1). Requer ``uv sync --group postgres``.

Referência:
    BRASIL (2018). LGPD — arts. 7, I; 8; 18, IX (revogação). · Doc 04, §3, Hands On.
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Protocol

from src.security.schemas import ConsentRecord, utc_now_iso

logger = logging.getLogger(__name__)


class ConsentStore(Protocol):
    """Contrato de um store de consentimento versionado."""

    name: str

    def get(self, subject_id: str) -> ConsentRecord | None: ...  # pragma: no cover

    def upsert(self, record: ConsentRecord) -> ConsentRecord: ...  # pragma: no cover

    def revoke(self, subject_id: str) -> ConsentRecord | None: ...  # pragma: no cover

    def history(self, subject_id: str) -> list[ConsentRecord]: ...  # pragma: no cover


def _next_version(previous: ConsentRecord | None) -> int:
    return (previous.version + 1) if previous else 1


class InMemoryConsentStore:
    """Store em memória (offline/testes). Mantém o histórico de versões."""

    name = "memory"

    def __init__(self) -> None:
        self._versions: dict[str, list[ConsentRecord]] = {}
        # RLock (reentrante): ``upsert`` chama ``get`` mantendo o lock.
        self._lock = threading.RLock()

    def get(self, subject_id: str) -> ConsentRecord | None:
        with self._lock:
            versions = self._versions.get(subject_id)
            return versions[-1] if versions else None

    def upsert(self, record: ConsentRecord) -> ConsentRecord:
        """Cria uma NOVA versão (nunca sobrescreve — trilha imutável)."""
        with self._lock:
            previous = self.get(record.subject_id)
            record.version = _next_version(previous)
            record.timestamp = utc_now_iso()
            self._versions.setdefault(record.subject_id, []).append(record)
            return record

    def revoke(self, subject_id: str) -> ConsentRecord | None:
        """Revogação instantânea (art. 18, IX): nova versão com revoked=True."""
        current = self.get(subject_id)
        if current is None:
            return None
        revoked = ConsentRecord(
            subject_id=subject_id,
            purposes=dict.fromkeys(current.purposes, False),
            terms_version=current.terms_version,
            revocable=current.revocable,
            revoked=True,
        )
        return self.upsert(revoked)

    def history(self, subject_id: str) -> list[ConsentRecord]:
        with self._lock:
            return list(self._versions.get(subject_id, []))


class FileConsentStore(InMemoryConsentStore):
    """Store append-only em JSONL (persistência simples entre execuções)."""

    name = "file"

    def __init__(self, path: str | Path) -> None:
        super().__init__()
        self.path = Path(path)
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                rec = ConsentRecord.from_dict(json.loads(line))
                self._versions.setdefault(rec.subject_id, []).append(rec)

    def upsert(self, record: ConsentRecord) -> ConsentRecord:
        saved = super().upsert(record)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(saved.to_dict(), ensure_ascii=False) + "\n")
        return saved


class PostgresConsentStore:
    """Store versionado em PostgreSQL (produção-like; análogo ao Cosmos DB).

    Cada upsert insere uma NOVA linha (append-only) — a versão vigente é a de
    maior ``version`` por ``subject_id``. Requer ``uv sync --group postgres``.
    """

    name = "postgres"

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._ensure_schema()

    def _connect(self):
        try:
            import psycopg
        except ImportError as exc:  # limite: dependência opcional
            raise RuntimeError(
                "CONSENT_STORE=postgres requer o grupo opcional: `uv sync --group postgres`."
            ) from exc
        return psycopg.connect(self._dsn)

    def _ensure_schema(self) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS consent_records (
                    id          BIGSERIAL PRIMARY KEY,
                    subject_id  TEXT NOT NULL,
                    version     INTEGER NOT NULL,
                    purposes    JSONB NOT NULL,
                    terms_version TEXT NOT NULL,
                    revocable   BOOLEAN NOT NULL DEFAULT TRUE,
                    revoked     BOOLEAN NOT NULL DEFAULT FALSE,
                    ts          TIMESTAMPTZ NOT NULL DEFAULT now()
                );
                CREATE INDEX IF NOT EXISTS ix_consent_subject
                    ON consent_records (subject_id, version DESC);
                """
            )
            conn.commit()

    def get(self, subject_id: str) -> ConsentRecord | None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT subject_id, purposes, terms_version, revocable, revoked, version, ts "
                "FROM consent_records WHERE subject_id = %s ORDER BY version DESC LIMIT 1",
                (subject_id,),
            )
            row = cur.fetchone()
        return _row_to_record(row) if row else None

    def upsert(self, record: ConsentRecord) -> ConsentRecord:
        previous = self.get(record.subject_id)
        record.version = _next_version(previous)
        record.timestamp = utc_now_iso()
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO consent_records "
                "(subject_id, version, purposes, terms_version, revocable, revoked) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (
                    record.subject_id,
                    record.version,
                    json.dumps(record.purposes),
                    record.terms_version,
                    record.revocable,
                    record.revoked,
                ),
            )
            conn.commit()
        return record

    def revoke(self, subject_id: str) -> ConsentRecord | None:
        current = self.get(subject_id)
        if current is None:
            return None
        return self.upsert(
            ConsentRecord(
                subject_id=subject_id,
                purposes=dict.fromkeys(current.purposes, False),
                terms_version=current.terms_version,
                revocable=current.revocable,
                revoked=True,
            )
        )

    def history(self, subject_id: str) -> list[ConsentRecord]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT subject_id, purposes, terms_version, revocable, revoked, version, ts "
                "FROM consent_records WHERE subject_id = %s ORDER BY version ASC",
                (subject_id,),
            )
            rows = cur.fetchall()
        return [_row_to_record(r) for r in rows]


def _row_to_record(row: tuple) -> ConsentRecord:
    purposes = row[1] if isinstance(row[1], dict) else json.loads(row[1])
    return ConsentRecord(
        subject_id=row[0],
        purposes=dict(purposes),
        terms_version=row[2],
        revocable=bool(row[3]),
        revoked=bool(row[4]),
        version=int(row[5]),
        timestamp=str(row[6]),
    )


def build_consent_store(
    kind: str, *, path: str | None = None, dsn: str | None = None
) -> ConsentStore:
    """Fábrica de store por configuração (Doc 04, §12 — 12-factor)."""
    kind = (kind or "memory").lower()
    if kind == "postgres":
        if not dsn:
            raise ValueError("PostgresConsentStore requer um DSN (POSTGRES_*).")
        return PostgresConsentStore(dsn)
    if kind == "file":
        return FileConsentStore(path or "/tmp/consent_store.jsonl")
    return InMemoryConsentStore()
