#!/usr/bin/env python
"""Gera os corpora de TEXTO da Aula 05 (seed fixa, reprodutível).

Produz quatro conjuntos, todos SINTÉTICOS (Faker + templates), jamais PII real —
para exercitar os controles de conformidade do Documento 04:

- ``data/subjects/subjects.jsonl``     — titulares com estado de consentimento
  granular por finalidade (§3, Hands On Snippet 1).
- ``data/pii_samples/pii_samples.jsonl`` — textos com PII BR sintética + rótulos,
  para validar a MINIMIZAÇÃO (§2 — art. 6, V) e medir falso positivo.
- ``data/rag_corpus/rag_corpus.jsonl``  — documentos do índice RAG, cada um
  associado a um ``subject_id`` (alguns com PII embutida). Permite a PURGA
  SELETIVA do direito ao esquecimento (§10, Snippet 3).
- ``data/dsr/dsr.jsonl``                — solicitações do titular (acesso,
  exclusão, revisão) para alimentar o consent-service e o purge-worker.

Uso:  uv run task seed-data   (ou:  python scripts/generate_datasets.py)

⚠️ USO ÉTICO: nenhum dado real. CPF/CNPJ têm apenas dígitos verificadores válidos
(para exercitar os validadores), sem corresponder a pessoas reais.

Referência:
    Doc 04, §2 (minimização), §3 (consentimento), §10 (esquecimento).
    Gebru et al. (2021). Datasheets for Datasets (ver data/README.md).
"""

from __future__ import annotations

import json
import random
from pathlib import Path

from faker import Faker

SEED = 42
DATA_DIR = Path(__file__).resolve().parent.parent / "data"

fake = Faker("pt_BR")

# Finalidades reconhecidas (espelham configs/treatment_policies.yaml).
PURPOSES = ["consulta_saldo", "faq_produtos", "treino_modelo", "recomendacao_credito"]
TERMS_VERSION = "2026-06-v3"


def _reset_seed() -> None:
    random.seed(SEED)
    Faker.seed(SEED)


def _fake_phone() -> str:
    ddd = random.randint(11, 99)
    return f"({ddd}) 9{random.randint(1000, 9999)}-{random.randint(1000, 9999)}"


def _fake_rg() -> str:
    a, b, c = random.randint(10, 99), random.randint(100, 999), random.randint(100, 999)
    return f"RG: {a}.{b}.{c}-{random.randint(0, 9)}"


def _fake_account() -> str:
    return f"conta corrente nº {random.randint(10000, 99999)}-{random.randint(0, 9)}"


# --------------------------------------------------------------------------- #
# SUBJECTS — titulares e consentimento granular por finalidade (Doc 04, §3)
# --------------------------------------------------------------------------- #
def build_subjects(n: int = 12) -> list[dict]:
    """Titulares com consentimento granular (alguns negam treino/crédito)."""
    _reset_seed()
    subjects: list[dict] = []
    for i in range(1, n + 1):
        subject_id = f"cli-{90000 + i}"
        # Todos consentem finalidades essenciais; opt-in de treino/crédito varia.
        consent = {
            "consulta_saldo": True,
            "faq_produtos": True,
            "treino_modelo": random.random() < 0.4,
            "recomendacao_credito": random.random() < 0.3,
        }
        subjects.append(
            {
                "subject_id": subject_id,
                "name": fake.name(),  # sintético
                "consent": consent,
                "terms_version": TERMS_VERSION,
            }
        )
    return subjects


# --------------------------------------------------------------------------- #
# PII SAMPLES — textos rotulados por entidade (+ benignos) — Doc 04, §2
# --------------------------------------------------------------------------- #
def build_pii_samples() -> list[dict]:
    """Textos com PII BR sintética + rótulos, e amostras benignas (FP baseline)."""
    _reset_seed()
    rows: list[dict] = []
    idx = 0

    def add(text: str, entities: list[str]) -> None:
        nonlocal idx
        idx += 1
        rows.append({"id": f"pii-{idx:04d}", "text": text, "entities": entities})

    single = [
        (lambda: f"O CPF informado foi {fake.cpf()}.", ["BR_CPF"]),
        (lambda: f"A empresa tem CNPJ {fake.cnpj()}.", ["BR_CNPJ"]),
        (lambda: f"Envie o comprovante para {fake.email()}.", ["EMAIL_ADDRESS"]),
        (lambda: f"O endereço fica no CEP {fake.postcode()}.", ["BR_CEP"]),
        (lambda: f"Meu telefone de contato é {_fake_phone()}.", ["PHONE_NUMBER"]),
        (lambda: f"O cartão usado foi {fake.credit_card_number()}.", ["CREDIT_CARD"]),
        (lambda: _fake_rg() + " foi apresentado no caixa.", ["BR_RG"]),
        (lambda: f"Consulte a minha {_fake_account()}, por favor.", ["BR_ACCOUNT"]),
        (lambda: f"O cliente {fake.name()} pediu a segunda via.", ["PERSON"]),
    ]
    for builder, entities in single:
        for _ in range(4):
            add(builder(), entities)

    for _ in range(12):
        cpf, email, phone = fake.cpf(), fake.email(), _fake_phone()
        add(
            f"Cliente {fake.name()}, CPF {cpf}, telefone {phone}, e-mail {email}.",
            ["PERSON", "BR_CPF", "PHONE_NUMBER", "EMAIL_ADDRESS"],
        )
    for _ in range(8):
        add(
            f"Titular com {_fake_account()} e CPF {fake.cpf()} no CEP {fake.postcode()}.",
            ["BR_ACCOUNT", "BR_CPF", "BR_CEP"],
        )

    benign = [
        "Qual é o horário de funcionamento da agência central?",
        "Como faço para simular um empréstimo pessoal?",
        "Quais são as taxas do cartão de crédito Aurora Gold?",
        "Gostaria de saber sobre as opções de investimento.",
        "Como ativo as notificações de compras do meu cartão?",
        "Qual a taxa de rendimento da poupança Aurora?",
        "Como funciona o financiamento de veículos?",
        "Preciso de ajuda para emitir um boleto de pagamento.",
        "Quais documentos preciso para abrir uma conta?",
        "O aplicativo está fora do ar neste momento?",
    ]
    for text in benign:
        add(text, [])
    return rows


# --------------------------------------------------------------------------- #
# RAG CORPUS — documentos por titular (para a purga seletiva) — Doc 04, §10
# --------------------------------------------------------------------------- #
def build_rag_corpus(subjects: list[dict]) -> list[dict]:
    """Documentos do índice RAG do Aurora Assist, atrelados a titulares.

    Documentos institucionais (sem titular) coexistem com registros de
    atendimento por titular (alguns com PII embutida). A purga seletiva remove
    apenas os vetores do titular solicitante, preservando os institucionais.
    """
    _reset_seed()
    docs: list[dict] = []

    # Documentos institucionais (sem titular específico -> subject_id "banco").
    institutional = [
        (
            "Horários das Agências",
            "As agências do Banco Aurora funcionam de segunda a sexta. A agência "
            "central atende das 10h às 16h; a agência Paulista, das 9h às 15h.",
        ),
        (
            "Tarifas de Serviços",
            "O pacote essencial inclui 4 saques e 2 transferências TED por mês. "
            "Consulte o app para valores atualizados de anuidade do cartão.",
        ),
        (
            "Rendimento do CDB",
            "O CDB Aurora rende um percentual do CDI conforme o prazo. Aplicações "
            "acima de 720 dias têm a menor alíquota de IR (15%).",
        ),
        (
            "Segurança e Golpes",
            "O Banco Aurora nunca solicita senha por telefone. Desconfie de "
            "mensagens que pedem dados pessoais ou transferências urgentes.",
        ),
    ]
    for i, (title, text) in enumerate(institutional, 1):
        docs.append(
            {
                "doc_id": f"doc-inst-{i:04d}",
                "subject_id": "banco",
                "title": title,
                "text": text,
                "contains_pii": False,
            }
        )

    # Registros de atendimento por titular (alguns com PII embutida — §10: o risco
    # de vetorizar PII é justamente o que a purga seletiva precisa endereçar).
    doc_idx = 0
    for subject in subjects:
        for _ in range(random.randint(1, 3)):
            doc_idx += 1
            has_pii = random.random() < 0.6
            if has_pii:
                text = (
                    f"Protocolo de atendimento do cliente {subject['name']} "
                    f"(CPF {fake.cpf()}): solicitou atualização de cadastro. "
                    f"Contato: {fake.email()}, telefone {_fake_phone()}, {_fake_account()}."
                )
            else:
                text = (
                    "Resumo de atendimento: o cliente perguntou sobre tarifas do "
                    "pacote de serviços e limites do cartão de crédito."
                )
            docs.append(
                {
                    "doc_id": f"doc-atend-{doc_idx:04d}",
                    "subject_id": subject["subject_id"],
                    "title": "Registro de Atendimento",
                    "text": text,
                    "contains_pii": has_pii,
                }
            )
    return docs


# --------------------------------------------------------------------------- #
# DSR — solicitações do titular (Doc 04, §3 — arts. 17-22)
# --------------------------------------------------------------------------- #
def build_dsr(subjects: list[dict]) -> list[dict]:
    """Solicitações de acesso, exclusão e revisão de decisão automatizada."""
    _reset_seed()
    rows: list[dict] = []
    picks = subjects[:6]
    plan = [
        ("access", "Titular solicita confirmação e acesso aos dados (art. 18, I-II)."),
        ("erasure", "Titular exerce o direito ao esquecimento (art. 18, VI)."),
        ("review", "Titular pede revisão de decisão automatizada (art. 20)."),
        ("erasure", "Encerramento de conta: apagar dados pessoais do índice."),
        ("access", "Auditoria interna: relatório do que se sabe do titular."),
        ("rectification", "Titular pede correção de dado cadastral (art. 18, III)."),
    ]
    for i, (subject, (dsr_type, note)) in enumerate(zip(picks, plan, strict=False), 1):
        rows.append(
            {
                "request_id": f"dsr-seed-{i:03d}",
                "subject_id": subject["subject_id"],
                "dsr_type": dsr_type,
                "note": note,
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
    subjects = build_subjects()
    pii = build_pii_samples()
    corpus = build_rag_corpus(subjects)
    dsr = build_dsr(subjects)

    write_jsonl(DATA_DIR / "subjects" / "subjects.jsonl", subjects)
    write_jsonl(DATA_DIR / "pii_samples" / "pii_samples.jsonl", pii)
    write_jsonl(DATA_DIR / "rag_corpus" / "rag_corpus.jsonl", corpus)
    write_jsonl(DATA_DIR / "dsr" / "dsr.jsonl", dsr)

    print("Datasets da Aula 05 gerados (seed fixa = 42):")
    print(f"  subjects/subjects.jsonl      -> {len(subjects):4d} titulares")
    print(f"  pii_samples/pii_samples.jsonl -> {len(pii):4d} textos (com e sem PII)")
    print(f"  rag_corpus/rag_corpus.jsonl  -> {len(corpus):4d} documentos")
    print(f"  dsr/dsr.jsonl                -> {len(dsr):4d} solicitações do titular")


if __name__ == "__main__":
    main()
