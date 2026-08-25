#!/usr/bin/env python
"""Gera os corpora de TEXTO/TRÁFEGO da Aula 06 (seed fixa, reprodutível).

Produz dados SINTÉTICOS (Faker + NumPy, seed=42) para exercitar os controles de
LLMOps do Documento 04, jamais PII real:

- ``data/knowledge/knowledge.jsonl`` — base institucional do Aurora Assist (RAG),
  usada para medir *groundedness* (§"métrica de qualidade").
- ``data/traffic/reference.jsonl``   — janela de REFERÊNCIA (baseline) de tráfego
  de produção: prompts + latência + comprimento de resposta + groundedness.
- ``data/traffic/production.jsonl``  — janela de PRODUÇÃO com **drift injetado**
  (novos produtos/gíria = prompt drift; respostas mais longas e menos
  fundamentadas = response drift; latência maior = data drift). Permite a
  detecção de KS/PSI/MMD/Wasserstein (§Drift).
- ``data/golden/golden_qa.jsonl``    — Q&A de referência para avaliação de
  qualidade contínua (§"métrica de qualidade").
- ``data/feedback/feedback.jsonl``   — feedback do usuário para o loop governado
  (§"Feedback loops"), pseudonimizado (nunca PII em claro).

Uso:  uv run task seed-data   (ou:  python scripts/generate_datasets.py)

⚠️ USO ÉTICO: nenhum dado real. O tráfego é sintético e serve apenas para
demonstrar monitoramento contínuo em laboratório.

Referência:
    Doc 04, §Drift, §Observabilidade, §SLOs, §"Feedback loops".
    Gebru et al. (2021). Datasheets for Datasets (ver data/README.md).
"""

from __future__ import annotations

import json
import random
from pathlib import Path

import numpy as np
from faker import Faker

SEED = 42
DATA_DIR = Path(__file__).resolve().parent.parent / "data"

fake = Faker("pt_BR")
_rng = np.random.default_rng(SEED)

# Perguntas TÍPICAS (formais, curtas) — vocabulário estável da referência.
TYPICAL_PROMPTS = [
    "Qual o horário de funcionamento da agência central?",
    "Qual a taxa do CDB do Aurora?",
    "Como funciona o rendimento da poupança?",
    "Quais são as tarifas do pacote de serviços?",
    "Como emito um boleto de pagamento?",
    "Qual o limite do cartão de crédito Aurora Gold?",
    "Como simulo um empréstimo pessoal?",
    "Quais documentos preciso para abrir uma conta?",
    "Como ativo as notificações do aplicativo?",
    "Qual a alíquota de IR do CDB acima de 720 dias?",
    "Como faço uma transferência via TED?",
    "Quais são as opções de investimento disponíveis?",
]

# Perguntas de PRODUÇÃO com DRIFT: novos produtos + estilo casual (prompt drift).
NEW_TOPIC_PROMPTS = [
    "vcs tao com aurora cripto agora? como compro bitcoin no app",
    "manda ai como funciona o pix parcelado novo",
    "blz e o cashback do cartao aurora black, quanto rende?",
    "tem como investir em cripto staking pelo banco?",
    "quero saber do open finance e portabilidade de salario rapidão",
    "o tal do buy now pay later de vcs cobra juros?",
    "como ativo o pix por aproximacao no celular?",
    "aurora cripto tem taxa de custodia? responde rapido pfv",
    "e a conta global em dolar, ja lancou?",
    "consigo antecipar o fgts pelo app novo de vcs?",
]


def _reset_seed() -> None:
    random.seed(SEED)
    Faker.seed(SEED)


# --------------------------------------------------------------------------- #
# KNOWLEDGE — base institucional para RAG/groundedness (Doc 04)
# --------------------------------------------------------------------------- #
def build_knowledge() -> list[dict]:
    """Documentos institucionais do Aurora Assist (sem PII)."""
    docs = [
        ("kb-horarios", "Horários das Agências",
         "As agências do Banco Aurora funcionam de segunda a sexta. A agência central "
         "atende das 10h às 16h; a agência Paulista, das 9h às 15h."),
        ("kb-cdb", "Rendimento do CDB",
         "O CDB Aurora rende um percentual do CDI conforme o prazo. Aplicações acima de "
         "720 dias têm a menor alíquota de imposto de renda, de 15%."),
        ("kb-poupanca", "Poupança Aurora",
         "A poupança Aurora tem rendimento mensal e liquidez diária, isenta de imposto "
         "de renda para pessoa física."),
        ("kb-tarifas", "Tarifas de Serviços",
         "O pacote essencial inclui 4 saques e 2 transferências TED por mês. A anuidade "
         "do cartão pode ser isenta conforme o relacionamento."),
        ("kb-cartao", "Cartão de Crédito",
         "O cartão Aurora Gold oferece limite conforme análise. As notificações de "
         "compra são ativadas no aplicativo, na seção de segurança."),
        ("kb-emprestimo", "Empréstimo Pessoal",
         "A simulação de empréstimo pessoal considera prazo e taxa. A contratação exige "
         "análise e não é decidida automaticamente pelo assistente."),
        ("kb-investimentos", "Investimentos",
         "O Banco Aurora oferece CDB, fundos e tesouro. As opções aparecem no app "
         "conforme o perfil de investidor do cliente."),
        ("kb-boleto", "Boletos e Pagamentos",
         "Boletos podem ser emitidos e pagos pelo aplicativo. A TED é concluída em "
         "horário comercial; fora dele, agenda-se para o próximo dia útil."),
        ("kb-conta", "Abertura de Conta",
         "Para abrir conta são necessários documento de identidade, CPF e comprovante "
         "de residência. O processo é feito pelo aplicativo."),
        ("kb-seguranca", "Segurança e Golpes",
         "O Banco Aurora nunca solicita senha por telefone. Desconfie de mensagens que "
         "pedem dados pessoais ou transferências urgentes."),
    ]
    return [{"doc_id": d, "title": t, "text": x} for d, t, x in docs]


# --------------------------------------------------------------------------- #
# TRAFFIC — janelas de referência e produção (com drift injetado) — Doc 04
# --------------------------------------------------------------------------- #
def _traffic_rows(
    prompts: list[str],
    lat_mean: float,
    lat_sd: float,
    len_mean: float,
    len_sd: float,
    ground_mean: float,
    ground_sd: float,
    n: int,
    prefix: str,
) -> list[dict]:
    rows: list[dict] = []
    for i in range(n):
        prompt = prompts[i % len(prompts)]
        latency = float(max(50.0, _rng.normal(lat_mean, lat_sd)))
        resp_len = float(max(20.0, _rng.normal(len_mean, len_sd)))
        ground = float(np.clip(_rng.normal(ground_mean, ground_sd), 0.0, 1.0))
        rows.append(
            {
                "id": f"{prefix}-{i + 1:04d}",
                "prompt": prompt,
                "latency_ms": round(latency, 1),
                "response_len": round(resp_len, 1),
                "groundedness": round(ground, 4),
            }
        )
    return rows


def build_reference(n: int = 200) -> list[dict]:
    """Janela baseline: prompts típicos, latência baixa, respostas fundamentadas."""
    pool = list(TYPICAL_PROMPTS)
    random.shuffle(pool)
    return _traffic_rows(
        pool, lat_mean=800, lat_sd=150, len_mean=220, len_sd=40,
        ground_mean=0.90, ground_sd=0.05, n=n, prefix="ref",
    )


def build_production(n: int = 200) -> list[dict]:
    """Janela de produção com DRIFT: metade de novos tópicos/gíria + degradação."""
    # 50% típicos + 50% novos tópicos => prompt drift (MMD).
    half = n // 2
    mixed = (TYPICAL_PROMPTS * 10)[:half] + (NEW_TOPIC_PROMPTS * 10)[:n - half]
    random.shuffle(mixed)
    # Latência maior (data drift/PSI), respostas mais longas (KS) e menos
    # fundamentadas (Wasserstein) — degradação silenciosa (Doc 04).
    return _traffic_rows(
        mixed, lat_mean=1300, lat_sd=400, len_mean=320, len_sd=90,
        ground_mean=0.78, ground_sd=0.12, n=n, prefix="prod",
    )


# --------------------------------------------------------------------------- #
# GOLDEN — Q&A de referência para avaliação de qualidade (Doc 04)
# --------------------------------------------------------------------------- #
def build_golden() -> list[dict]:
    """Q&A de referência ancorado na base institucional (contexto para RAGAS/qualidade)."""
    pairs = [
        ("Qual a alíquota de IR do CDB acima de 720 dias?",
         "É de 15%, a menor faixa, para aplicações acima de 720 dias.", "kb-cdb"),
        ("Qual o horário da agência central?",
         "A agência central atende das 10h às 16h, de segunda a sexta.", "kb-horarios"),
        ("A poupança Aurora paga imposto de renda?",
         "Não; a poupança é isenta de IR para pessoa física.", "kb-poupanca"),
        ("Quantos saques o pacote essencial inclui?",
         "O pacote essencial inclui 4 saques e 2 transferências TED por mês.", "kb-tarifas"),
        ("Como ativo as notificações de compra do cartão?",
         "Pelo aplicativo, na seção de segurança do cartão.", "kb-cartao"),
        ("O assistente decide meu empréstimo automaticamente?",
         "Não; a contratação exige análise e não é decidida pelo assistente.", "kb-emprestimo"),
        ("Quais documentos preciso para abrir conta?",
         "Documento de identidade, CPF e comprovante de residência.", "kb-conta"),
        ("O banco pede senha por telefone?",
         "Nunca; o Banco Aurora não solicita senha por telefone.", "kb-seguranca"),
    ]
    knowledge = {d["doc_id"]: d["text"] for d in build_knowledge()}
    rows = []
    for i, (q, a, doc_id) in enumerate(pairs, 1):
        rows.append(
            {
                "id": f"gold-{i:03d}",
                "question": q,
                "reference_answer": a,
                "context_doc": doc_id,
                "context": knowledge[doc_id],
            }
        )
    return rows


# --------------------------------------------------------------------------- #
# FEEDBACK — loop governado, pseudonimizado (Doc 04, §"Feedback loops")
# --------------------------------------------------------------------------- #
def build_feedback(n: int = 30) -> list[dict]:
    """Feedback sintético do usuário (rating -1/0/1) para curadoria posterior."""
    _reset_seed()
    comments_good = ["resposta clara", "resolveu minha dúvida", "rápido e útil"]
    comments_bad = ["não respondeu o que perguntei", "demorou muito", "resposta genérica"]
    rows = []
    for i in range(1, n + 1):
        rating = random.choices([-1, 0, 1], weights=[0.2, 0.2, 0.6])[0]
        if rating == 1:
            comment = random.choice(comments_good)
        elif rating == -1:
            comment = random.choice(comments_bad)
        else:
            comment = ""
        rows.append(
            {
                "request_id": f"trace-{i:04d}",
                "rating": rating,
                "subject_ref": f"subj_{random.randint(100000, 999999)}",  # pseudônimo
                "comment": comment,
                "curated": False,
            }
        )
    return rows


# --------------------------------------------------------------------------- #
def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> None:
    _reset_seed()
    knowledge = build_knowledge()
    reference = build_reference()
    production = build_production()
    golden = build_golden()
    feedback = build_feedback()

    write_jsonl(DATA_DIR / "knowledge" / "knowledge.jsonl", knowledge)
    write_jsonl(DATA_DIR / "traffic" / "reference.jsonl", reference)
    write_jsonl(DATA_DIR / "traffic" / "production.jsonl", production)
    write_jsonl(DATA_DIR / "golden" / "golden_qa.jsonl", golden)
    write_jsonl(DATA_DIR / "feedback" / "feedback.jsonl", feedback)

    print("Datasets da Aula 06 gerados (seed fixa = 42):")
    print(f"  knowledge/knowledge.jsonl     -> {len(knowledge):4d} documentos institucionais")
    print(f"  traffic/reference.jsonl       -> {len(reference):4d} eventos (baseline)")
    print(f"  traffic/production.jsonl      -> {len(production):4d} eventos (com drift)")
    print(f"  golden/golden_qa.jsonl        -> {len(golden):4d} pares Q&A de referência")
    print(f"  feedback/feedback.jsonl       -> {len(feedback):4d} feedbacks (não curados)")


if __name__ == "__main__":
    main()
