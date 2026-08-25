"""purge-worker — operacionaliza o direito ao esquecimento (Aula 05).

Worker que consome a fila de **solicitações de exclusão** (DSR do tipo
``erasure``) no consent-service e executa a **purga seletiva** dos vetores do
titular no vector store (Doc 04, §10, Snippet 3). É a materialização do direito
à exclusão (LGPD art. 18, VI) na camada de RECUPERAÇÃO.

Modos:
    python -m app.purge --process-requests --report reports/purge_report.json
    python -m app.purge --serve --interval 20     # loop (usado no docker compose)

⚠️ Limite honesto (Doc 04, §10): a purga cobre embeddings do RAG, mas NÃO o
conhecimento absorvido em fine-tuning (machine unlearning — Bourtoule et al.,
2021). Esse limite é registrado no relatório e deve constar no DPIA.

Referência:
    BRASIL (2018). LGPD — art. 18, VI. · Bourtoule et al. (2021). Machine Unlearning.
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from pathlib import Path

import httpx

from app.config import get_settings
from src.security.schemas import DSRStatus, DSRType, PurgeResult
from src.security.vector_store import build_vector_store

logger = logging.getLogger(__name__)


def _fetch_pending(consent_url: str, timeout: float = 5.0) -> list[dict]:
    """Lista DSRs pendentes no consent-service (best-effort)."""
    try:
        resp = httpx.get(
            f"{consent_url.rstrip('/')}/dsr",
            params={"status": DSRStatus.PENDING.value},
            timeout=timeout,
        )
        resp.raise_for_status()
        return list(resp.json())
    except httpx.HTTPError as exc:  # limite: serviço externo
        logger.warning("consent-service indisponível: %s", exc)
        return []


def _mark_completed(consent_url: str, request_id: str, note: str, timeout: float = 5.0) -> None:
    try:
        httpx.patch(
            f"{consent_url.rstrip('/')}/dsr/{request_id}",
            json={"status": DSRStatus.COMPLETED.value, "note": note},
            timeout=timeout,
        )
    except httpx.HTTPError as exc:  # limite: serviço externo
        logger.warning("Falha ao marcar DSR %s como concluída: %s", request_id, exc)


def process_requests() -> list[PurgeResult]:
    """Processa todas as DSRs de exclusão pendentes -> purga seletiva."""
    settings = get_settings()
    store = build_vector_store(
        settings.vector_store, url=settings.qdrant_url, collection=settings.qdrant_collection
    )
    results: list[PurgeResult] = []
    for dsr in _fetch_pending(settings.consent_service_url):
        if dsr.get("dsr_type") != DSRType.ERASURE.value:
            continue
        subject_id = dsr["subject_id"]
        purge = store.purge_subject(subject_id)
        results.append(purge)
        note = f"Purga seletiva: {purge.deleted_count} vetor(es) removido(s)."
        _mark_completed(settings.consent_service_url, dsr["request_id"], note)
        logger.info("DSR %s concluída (%s)", dsr["request_id"], note)
    return results


def _write_report(results: list[PurgeResult], report_path: str | Path) -> None:
    path = Path(report_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "processed": len(results),
        "results": [r.to_dict() for r in results],
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.info("Relatório de purga escrito em %s", path)


def serve(interval: int) -> None:
    """Loop de serviço: processa a fila a cada ``interval`` segundos."""
    logger.info("purge-worker iniciado (intervalo=%ss). Aguardando DSRs de exclusão…", interval)
    while True:
        try:
            results = process_requests()
            if results:
                logger.info("Processadas %d solicitações de exclusão.", len(results))
        except Exception as exc:  # limite: worker não pode morrer por 1 falha
            logger.exception("Erro no ciclo do purge-worker: %s", exc)
        time.sleep(max(1, interval))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="purge-worker — direito ao esquecimento (Aula 05)."
    )
    parser.add_argument("--process-requests", action="store_true", help="processa a fila uma vez")
    parser.add_argument("--serve", action="store_true", help="executa em loop (worker)")
    parser.add_argument("--interval", type=int, default=20, help="intervalo do loop (s)")
    parser.add_argument("--report", default="reports/purge_report.json", help="saída JSON")
    args = parser.parse_args()

    logging.basicConfig(level=get_settings().log_level)

    if args.serve:
        serve(args.interval)
        return
    if args.process_requests:
        results = process_requests()
        _write_report(results, args.report)
        print(f"[purge] {len(results)} solicitação(ões) de exclusão processada(s).")
        return
    parser.print_help()


if __name__ == "__main__":
    main()
