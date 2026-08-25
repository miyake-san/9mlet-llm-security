# DATASHEET — Datasets da Aula 06 (LLMOps: Governança de Dados e Monitoramento)

> Estilo *Datasheets for Datasets* (Gebru et al., 2021). Todos os dados são
> **100% sintéticos** e destinam-se **exclusivamente ao ensino de observabilidade,
> detecção de drift e SLOs em laboratório controlado** (Doc 04).

> [!WARNING]
> ⚠️ **Uso ético e legal.** Nenhum dado pessoal real é utilizado. O tráfego de
> produção é simulado; os identificadores de feedback são **pseudônimos**
> (`subj_XXXXXX`), nunca PII. Os dados servem para demonstrar **monitoramento
> contínuo** — jamais para reidentificação ou uso fora do laboratório.

## 1. Motivação

O LLMOps opera sobre **tráfego de produção** (o que os usuários perguntam e como
o sistema responde ao longo do tempo). Estes corpora materializam os conceitos do
Documento 04: detecção de **drift** (§"Detecção estatística de drift"), medição
de **groundedness/qualidade** (§"métrica de qualidade"), **SLIs/SLOs/Data SLOs**
(§SLOs) e o **loop de feedback** governado (§"Feedback loops").

## 2. Composição

| Pasta | Arquivo | Conteúdo | Papel |
|---|---|---|---|
| `knowledge/` | `knowledge.jsonl` | base institucional do Aurora Assist (RAG) | groundedness |
| `traffic/` | `reference.jsonl` | janela baseline de tráfego (prompts + métricas) | referência de drift |
| `traffic/` | `production.jsonl` | janela de produção com **drift injetado** | alvo de drift |
| `golden/` | `golden_qa.jsonl` | Q&A de referência ancorado na base | avaliação de qualidade |
| `feedback/` | `feedback.jsonl` | feedback do usuário pseudonimizado | loop governado |

**Esquema `knowledge.jsonl`:** `{doc_id, title, text}`
**Esquema `reference.jsonl` / `production.jsonl`:** `{id, prompt, latency_ms, response_len, groundedness}`
**Esquema `golden_qa.jsonl`:** `{id, question, reference_answer, context_doc, context}`
**Esquema `feedback.jsonl`:** `{request_id, rating, subject_ref, comment, curated}`

### Drift injetado (por design) — Doc 04, §Drift

A janela `production.jsonl` diverge da `reference.jsonl` de forma controlada, para
que os quatro testes detectem sinais distintos:

| Sinal | Método | Como foi injetado |
|---|---|---|
| **Prompt drift** | MMD (embeddings) | 50% dos prompts viram novos tópicos/gíria (Aurora Cripto, PIX parcelado) |
| **Response drift** (tamanho) | KS | respostas mais longas (média 220 → 320) |
| **Response drift** (qualidade) | Wasserstein | groundedness degradada (média 0,90 → 0,78) |
| **Data drift** (latência) | PSI | latência maior (média 800ms → 1300ms) |

> `attacks/`, `benign/` e `pii_samples/` **omitidos**: esta aula é sobre
> MONITORAMENTO, não sobre red team (Aulas 1/4) nem anonimização (Aula 3). O
> detector de PII (`src/security/pii.py`) reaproveita o espírito da Aula 03 para
> medir o **Data SLO de segurança** (vazamento de PII nas respostas).

### Amostras (formato — os valores reais são gerados por script)

`knowledge/knowledge.jsonl` (1 de ~10):
```json
{"doc_id": "kb-cdb", "title": "Rendimento do CDB", "text": "O CDB Aurora rende um percentual do CDI... acima de 720 dias, 15% de IR."}
```

`traffic/reference.jsonl` (2 de ~200):
```json
{"id": "ref-0001", "prompt": "Qual a taxa do CDB do Aurora?", "latency_ms": 812.4, "response_len": 218.0, "groundedness": 0.91}
{"id": "ref-0002", "prompt": "Como emito um boleto de pagamento?", "latency_ms": 774.9, "response_len": 231.5, "groundedness": 0.88}
```

`traffic/production.jsonl` (2 de ~200):
```json
{"id": "prod-0001", "prompt": "vcs tao com aurora cripto agora? como compro bitcoin no app", "latency_ms": 1502.7, "response_len": 351.0, "groundedness": 0.71}
{"id": "prod-0002", "prompt": "Qual a taxa do CDB do Aurora?", "latency_ms": 1288.1, "response_len": 305.2, "groundedness": 0.80}
```

`golden/golden_qa.jsonl` (1 de ~8):
```json
{"id": "gold-001", "question": "Qual a alíquota de IR do CDB acima de 720 dias?", "reference_answer": "É de 15%...", "context_doc": "kb-cdb", "context": "O CDB Aurora rende..."}
```

`feedback/feedback.jsonl` (2 de ~30):
```json
{"request_id": "trace-0001", "rating": 1, "subject_ref": "subj_482913", "comment": "resposta clara", "curated": false}
{"request_id": "trace-0002", "rating": -1, "subject_ref": "subj_119540", "comment": "resposta genérica", "curated": false}
```

## 3. Coleta e geração

- **Gerador:** [`scripts/generate_datasets.py`](../scripts/generate_datasets.py) com
  **seed fixa = 42** (Faker `pt_BR` + NumPy `default_rng`). Reexecutar reproduz
  byte-a-byte os mesmos arquivos.
- **Comando:** `uv run task seed-data`.

## 4. Usos recomendados e limites

- **Recomendado:** demonstrar detecção de drift, instrumentação gen_ai.*,
  cálculo de SLIs/SLOs e o loop de feedback governado.
- **NÃO recomendado:** treinar modelos, inferir comportamento real de clientes ou
  qualquer uso fora do laboratório. O feedback sintético **não** representa
  preferências reais e não deve alimentar decisões sem curadoria humana (Doc 04,
  §"Feedback loops" — feedback não é verdade absoluta).

## 5. Manutenção

- **Proveniência:** elaboração própria (curso 9mlet — Segurança de LLMs).
- **Licença:** MIT (código) / CC0 (dados sintéticos).
- **Contato:** repositório canônico do curso.
