# DATASHEET — Datasets da Aula 05 (Conformidade LGPD/GDPR/EU AI Act)

> Estilo *Datasheets for Datasets* (Gebru et al., 2021). Todos os dados são
> **100% sintéticos** e destinam-se **exclusivamente ao ensino de conformidade e
> proteção de dados em laboratório controlado** (Doc 04).

> [!WARNING]
> ⚠️ **Uso ético e legal.** Nenhum dado pessoal real é utilizado. CPF/CNPJ têm
> apenas **dígitos verificadores válidos** (para exercitar os validadores), sem
> corresponder a pessoas reais. Os textos servem para demonstrar **minimização**,
> **consentimento**, **registro de tratamento** e **direito ao esquecimento** —
> nunca para reidentificação ou qualquer uso fora do laboratório.

## 1. Motivação

A conformidade opera sobre **dados pessoais** (LGPD/GDPR) e sobre **texto** (o que
o assistente processa). Estes corpora materializam os controles do Documento 04:
minimização de PII (§2 — art. 6, V), consentimento granular e versionado (§3),
registro de tratamento (§4 — art. 37) e a **purga seletiva** do direito ao
esquecimento em vector store (§10, Snippet 3).

## 2. Composição

| Pasta | Arquivo | Conteúdo | Rótulos |
|---|---|---|---|
| `subjects/` | `subjects.jsonl` | titulares com consentimento granular por finalidade | `consent{purpose:bool}`, `terms_version` |
| `pii_samples/` | `pii_samples.jsonl` | textos com PII BR sintética + benignos (FP baseline) | `entities[]` |
| `rag_corpus/` | `rag_corpus.jsonl` | documentos do índice RAG, atrelados a `subject_id` | `contains_pii` |
| `dsr/` | `dsr.jsonl` | solicitações do titular (acesso/exclusão/revisão) | `dsr_type` |

**Esquema `subjects.jsonl`:** `{subject_id, name, consent{...}, terms_version}`
**Esquema `pii_samples.jsonl`:** `{id, text, entities[]}`
**Esquema `rag_corpus.jsonl`:** `{doc_id, subject_id, title, text, contains_pii}`
**Esquema `dsr.jsonl`:** `{request_id, subject_id, dsr_type, note}`

> `attacks/`, `benign/` e `golden/` **omitidos**: esta aula é sobre CONFORMIDADE,
> não sobre red team (Aulas 1/4) nem avaliação de qualidade (Aula 7). Reaproveita-se
> o corpus de PII no espírito da Aula 03 (Presidio), agora sob leitura jurídica.

### Amostras (formato — os valores reais são gerados por script)

`subjects/subjects.jsonl` (2 de ~12):
```json
{"subject_id": "cli-90001", "name": "Sofia Nogueira", "consent": {"consulta_saldo": true, "faq_produtos": true, "treino_modelo": false, "recomendacao_credito": false}, "terms_version": "2026-06-v3"}
{"subject_id": "cli-90002", "name": "Enzo da Rocha", "consent": {"consulta_saldo": true, "faq_produtos": true, "treino_modelo": true, "recomendacao_credito": false}, "terms_version": "2026-06-v3"}
```

`pii_samples/pii_samples.jsonl` (3 de ~90):
```json
{"id": "pii-0001", "text": "O CPF informado foi 123.456.789-09.", "entities": ["BR_CPF"]}
{"id": "pii-0050", "text": "Cliente Ana Souza, CPF 000.000.001-91, telefone (11) 91234-5678, e-mail ana@exemplo.com.", "entities": ["PERSON", "BR_CPF", "PHONE_NUMBER", "EMAIL_ADDRESS"]}
{"id": "pii-0085", "text": "Qual é o horário de funcionamento da agência central?", "entities": []}
```

`rag_corpus/rag_corpus.jsonl` (3 de ~30):
```json
{"doc_id": "doc-inst-0001", "subject_id": "banco", "title": "Horários das Agências", "text": "As agências do Banco Aurora funcionam de segunda a sexta...", "contains_pii": false}
{"doc_id": "doc-atend-0003", "subject_id": "cli-90003", "title": "Registro de Atendimento", "text": "Protocolo de atendimento do cliente ... (CPF ...): solicitou atualização...", "contains_pii": true}
{"doc_id": "doc-atend-0004", "subject_id": "cli-90004", "title": "Registro de Atendimento", "text": "Resumo de atendimento: o cliente perguntou sobre tarifas...", "contains_pii": false}
```

`dsr/dsr.jsonl` (3 de ~6):
```json
{"request_id": "dsr-seed-001", "subject_id": "cli-90001", "dsr_type": "access", "note": "Titular solicita confirmação e acesso aos dados (art. 18, I-II)."}
{"request_id": "dsr-seed-002", "subject_id": "cli-90002", "dsr_type": "erasure", "note": "Titular exerce o direito ao esquecimento (art. 18, VI)."}
{"request_id": "dsr-seed-003", "subject_id": "cli-90003", "dsr_type": "review", "note": "Titular pede revisão de decisão automatizada (art. 20)."}
```

## 3. Coleta / Geração

- **Proveniência:** gerados por [`scripts/generate_datasets.py`](../scripts/generate_datasets.py)
  com **Faker (`pt_BR`)** e templates, **seed fixa = 42** (reprodutível).
- **PII:** CPF/CNPJ/RG/CEP/telefone/e-mail/conta **fictícios**, válidos apenas em
  formato. Nunca há dado de pessoa real.
- **Consentimento:** o opt-in de `treino_modelo`/`recomendacao_credito` varia entre
  titulares para exercitar o *enforcement* de base legal (art. 7).

Para (re)gerar os conjuntos:

```bash
uv run task seed-data     # ou: python scripts/generate_datasets.py
```

Como a geração é **determinística** (seed = 42), o comando reproduz exatamente os
mesmos arquivos.

## 4. Usos recomendados

- Medir a **minimização de PII** (precisão/recall do detector BR / Presidio).
- Exercitar **consentimento granular** e o *enforcement* de finalidade.
- Alimentar o **registro de tratamento** (RoPA — art. 37) com metadados.
- Demonstrar a **purga seletiva** (direito ao esquecimento) por `subject_id`.

## 5. Usos NÃO recomendados

- Treinar/ajustar modelos de produção.
- Reidentificação — não há dados reais a reidentificar (tudo é sintético).
- Qualquer uso fora do laboratório didático.

## 6. Distribuição e Licença

Distribuído sob **MIT**, junto ao repositório. Como é sintético, não há restrição
de privacidade; ainda assim, trate `pii_samples/` com responsabilidade (é a
matéria-prima dos controles de proteção de dados).

## 7. Manutenção

Mantido no repositório do curso. Alterações devem preservar a **seed** e o
**esquema**, e passar em `uv run task test`.

## 8. Considerações éticas

A PII sintética existe para **ensinar a protegê-la** (minimização, purga). Segue-se
o princípio de **Privacy by Design** (GDPR art. 25): o dado mais seguro é aquele
que não existe. Segredos e credenciais **nunca** são versionados (use `.env`).

## Referências

- Gebru, T. et al. (2021). *Datasheets for Datasets.* Communications of the ACM.
- BRASIL (2018). *LGPD* — arts. 6, 7, 11, 17-22, 37.
- Sweeney, L. (2002). *k-Anonymity.*
- Bourtoule, L. et al. (2021). *Machine Unlearning.* IEEE S&P.
