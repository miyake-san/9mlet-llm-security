# DATASHEET — Datasets da Aula 07

> Estilo *Datasheets for Datasets* (Gebru et al., 2021). Todos os dados são
> **100% sintéticos** (Faker `pt_BR`, seed fixa = 42) e destinam-se
> **exclusivamente** à auditoria defensiva de **viés** e **qualidade** de LLMs em
> laboratório controlado (Doc 04, "Auditoria em escala" e "Avaliação de RAG").

> [!WARNING]
> ⚠️ **Uso ético e legal.** Os perfis de cliente, nomes, rendas e pedidos são
> **fictícios**. Os grupos "A" e "B" são rótulos abstratos de **atributo
> protegido** para auditoria de *fairness* — não representam pessoas reais nem um
> grupo social específico. **Nenhum** CPF ou dado pessoal real é utilizado.

## 1. Motivação

A IA Responsável exige converter "parece justo/bom" em **evidência mensurável**
(Doc 04, "Saudável não é o mesmo que justo"). Estes corpora permitem medir, sobre
o Aurora Assist: (a) **qualidade** das respostas (BLEU/ROUGE vs. BERTScore),
(b) **fidelidade** RAG (RAGAS *faithfulness*), (c) **disparidade** entre grupos
(paridade demográfica, igualdade de oportunidade) e (d) **viés contrafactual**
(a resposta muda ao trocar só o atributo protegido?).

## 2. Composição

| Pasta | Arquivo | Conteúdo | Rótulos |
|---|---|---|---|
| `rag_corpus/` | `*.md` | documentos de produtos do Banco Aurora (fatos citáveis) | — |
| `golden/` | `golden_qa.jsonl` | perguntas com resposta de referência (*gold*) | `answerable`, `category` |
| `fairness/` | `profiles.jsonl` | perfis balanceados por grupo protegido | `group`, `qualified` (y_true) |
| `fairness/` | `counterfactual_pairs.jsonl` | pares idênticos que só variam o grupo/nome | `a`, `b` |

**Esquema `golden_qa.jsonl`:** `{id, question, reference, answerable, category}`
**Esquema `profiles.jsonl`:** `{id, name, group, qualified, income, request}`
**Esquema `counterfactual_pairs.jsonl`:** `{id, a:{perfil}, b:{perfil}}`

### Balanceamento (essencial para a auditoria)

Os grupos **A** e **B** têm **40 perfis cada**, com **distribuição de qualificação
idêntica** (24 qualificados / 16 não, ou seja, 60% em cada grupo). Assim, qualquer
disparidade medida é atribuível ao **comportamento do assistente**, não a um
desequilíbrio dos dados — condição necessária para uma auditoria estatística
honesta (Doc 04, "Definições estatísticas de fairness").

### Comportamento pedagógico esperado

| Item | Sem mitigação (padrão) | Com mitigação |
|---|---|---|
| Perfis grupo B qualificados | parte é **negada** (queda de TPR) | aprovados como o grupo A |
| Recomendação de produto | difere por grupo (Premium vs. Básico) | produto único para todos |
| Pares contrafactuais | resposta **muda** ao trocar o grupo | resposta equivalente |
| Perguntas sem resposta no corpus | assistente **alucina** um número | **abstém-se** (faithful) |

## 3. Coleta / Geração

- **Proveniência:** gerados por [`scripts/generate_datasets.py`](../scripts/generate_datasets.py)
  com **Faker (`pt_BR`)** e **seed fixa = 42** (reprodutível).
- **Golden set:** as referências alinham-se aos fatos do `rag_corpus/`; itens
  `answerable=false` referenciam fatos **ausentes** do corpus (para medir alucinação).

Para (re)gerar todos os conjuntos:

```bash
uv run task seed-data     # ou: python scripts/generate_datasets.py
```

Como a geração é **determinística**, o comando reproduz exatamente os mesmos
arquivos — nenhum dado real entra no versionamento.

## 4. Usos recomendados

- Medir **qualidade** (BLEU/ROUGE vs. BERTScore) e **RAGAS** (`app/eval_ragas.py`).
- Auditar **fairness de grupo** (Fairlearn / `src/security/fairness.py`).
- Rodar o **teste contrafactual** (Snippet 1 do Doc 04).
- Alimentar o **quality gate** ético (`configs/thresholds.yaml`).

## 5. Artefatos omitidos (e por quê)

- `attacks/`, `benign/`, `pii_samples/`: são o foco das Aulas 01-05 (red team,
  guardrails, PII). A Aula 07 concentra-se em **ética, viés e qualidade**, cujos
  artefatos próprios são `golden/`, `fairness/` e `rag_corpus/` (ver tabela de
  mapeamento do prompt V2). Reintroduzi-los aqui só adicionaria ruído.
