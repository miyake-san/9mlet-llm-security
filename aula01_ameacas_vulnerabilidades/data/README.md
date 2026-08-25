# DATASHEET — Datasets da Aula 01

> Estilo *Datasheets for Datasets* (Gebru et al., 2021). Todos os dados são
> **100% sintéticos** e destinam-se **exclusivamente a testes defensivos de
> segurança de LLMs em laboratório controlado**.

> [!WARNING]
> ⚠️ **Uso ético e legal.** Os corpora de `attacks/` contêm payloads adversariais
> (prompt injection, jailbreak). Eles existem **apenas** para atacar o Aurora
> Assist **do próprio laboratório**, com fim didático e defensivo. **Não** use
> contra sistemas de terceiros. **Nenhum** dado pessoal real é utilizado.

## 1. Motivação

Segurança de LLMs opera sobre **texto adversarial e dados sensíveis**, não sobre
tabelas numéricas. Estes corpora materializam os riscos do **OWASP Top 10 for
LLM (2025)** discutidos no Documento 04 (seções 4-8), permitindo medir a
superfície de ataque do Aurora Assist e a linha de base de insegurança.

## 2. Composição

| Pasta | Arquivo | Conteúdo | Rótulos |
|---|---|---|---|
| `attacks/` | `attacks.jsonl` | prompt injection direta/indireta, jailbreak, encoding, abuso de ferramenta | `owasp` (LLM01/LLM06/LLM08), `technique` |
| `benign/` | `benign.jsonl` | perguntas bancárias legítimas | — (baseline de falso positivo) |
| `pii_samples/` | `pii_samples.jsonl` | texto PT-BR com CPF/CNPJ/RG/CEP/e-mail/telefone **sintéticos** | `pii_types` |
| `rag_corpus/` | `*.md` | documentos do Aurora; **dois** com injeção indireta oculta | — |

**Esquema `attacks.jsonl`:** `{id, owasp, technique, lang, prompt, success_markers[]}`
**Esquema `benign.jsonl`:** `{id, lang, prompt}`
**Esquema `pii_samples.jsonl`:** `{id, text, pii_types[], synthetic}`

> `golden/` (Q&A de referência para RAGAS) **é omitido** nesta aula — pertence à
> **Aula 07 (Ética, Viés e Validação)**, onde a métrica de *faithfulness* se aplica.

## 3. Coleta / Geração

- **Proveniência:** gerados por [`scripts/generate_datasets.py`](../scripts/generate_datasets.py)
  com **Faker (`pt_BR`)** e templates, **seed fixa = 42** (reprodutível).
- **PII:** produzida por `Faker` — **fictícia**, válida apenas em formato. Nunca
  há CPF/CNPJ/RG/nome/e-mail de pessoa real.
- **Ataques:** derivados de técnicas públicas descritas na literatura (Greshake
  et al., 2023; Wei et al., 2023) e no OWASP, em versão **mínima e didática**.

Para (re)gerar os conjuntos completos:

```bash
uv run task seed-data     # ou: python scripts/generate_datasets.py
```

Os arquivos versionados neste diretório são o **conjunto pedagógico completo**
produzido pelo script (56 ataques, 60 prompts benignos, 100 amostras de PII e
6 documentos de RAG). Como a geração é **determinística** (seed = 42),
`uv run task seed-data` reproduz exatamente os mesmos arquivos — nada de dados
reais entra no versionamento.

## 4. Usos recomendados

- Medir **attack success rate** contra a API vulnerável (`src/security/redteam.py`).
- Medir **falso positivo** de detectores/guardrails (corpus `benign/`).
- Exercitar detecção de **PII BR** (`src/security/detectors.py`; Presidio na Aula 03).
- Demonstrar **injeção indireta** via RAG (`rag_corpus/`).

## 5. Usos NÃO recomendados

- Treinar/ajustar modelos de produção.
- Qualquer uso ofensivo fora do laboratório.
- Reidentificação — não há dados reais a reidentificar (tudo é sintético).

## 6. Distribuição e Licença

Distribuído sob **MIT**, junto ao repositório. Como é sintético, não há restrição
de privacidade; ainda assim, trate os payloads de `attacks/` com responsabilidade.

## 7. Manutenção

Mantido no repositório do curso. Alterações devem preservar a **seed** e o
**esquema**, e passar em `uv run task test`.

## 8. Considerações éticas

Os payloads são deliberadamente **de baixo risco** e suficientes apenas para o
aprendizado. Segue-se o princípio de **red team defensivo**: expor para corrigir.
Segredos e credenciais **nunca** são versionados (use `.env` a partir de
`.env.example`).

## Referências

- Gebru, T. et al. (2021). *Datasheets for Datasets.* Communications of the ACM.
- OWASP Foundation (2025). *Top 10 for LLM Applications, v2025.*
- Greshake, K. et al. (2023). *Indirect Prompt Injection.* AISec'23.
