# DATASHEET — Datasets da Aula 04

> Estilo *Datasheets for Datasets* (Gebru et al., 2021). Todos os dados são
> **100% sintéticos** e destinam-se **exclusivamente a testes defensivos de
> segurança de LLMs em laboratório controlado** (Doc 04, seção 14).

> [!WARNING]
> ⚠️ **Uso ético e legal.** Os corpora de `attacks/` contêm payloads adversariais
> (prompt injection, jailbreak, evasão por ofuscação, escalada *crescendo*). Eles
> existem **apenas** para atacar o Aurora Assist **do próprio laboratório**, com
> fim didático e defensivo. **Não** use contra sistemas de terceiros. **Nenhum**
> dado pessoal real é utilizado.

## 1. Motivação

O red teaming de LLMs opera sobre **texto adversarial**, não sobre tabelas
numéricas. Estes corpora materializam o ciclo PAIR e as técnicas discutidas no
Documento 04 (seções 6-9), permitindo medir o **Attack Success Rate** do Aurora
Assist DEFENDIDO, a eficácia dos guardrails e a **efetividade da mitigação**
($E = 1 - R_1/R_0$).

## 2. Composição

| Pasta | Arquivo | Conteúdo | Rótulos |
|---|---|---|---|
| `attacks/` | `attacks.jsonl` | ataques single-turn: planos, ofuscados (leet/base64/split) e de exfiltração | `owasp`, `technique`, `obfuscated` |
| `attacks/` | `crescendo.jsonl` | sequências **multi-turno** de escalada gradual | `owasp`, `technique`, `turns[]` |
| `benign/` | `benign.jsonl` | perguntas bancárias legítimas | — (baseline de falso positivo) |

**Esquema `attacks.jsonl`:** `{id, owasp, technique, lang, prompt, success_markers[], obfuscated}`
**Esquema `crescendo.jsonl`:** `{id, owasp, technique, turns[], success_markers[]}`
**Esquema `benign.jsonl`:** `{id, lang, prompt}`

### Comportamento esperado no alvo DEFENDIDO (pedagógico)

| Categoria | OWASP | Guardrail de entrada (superfície) | Desfecho |
|---|---|---|---|
| Planos | LLM01/02/06/08 | **detecta** (palavra-chave) | **bloqueado** |
| Ofuscados (leet/base64/split) | LLM01/02/08 | **evade** | **sucesso** (risco residual) |
| Ofuscados de exfiltração | LLM06 | evade a entrada | **barrado no egresso** (PII/canário) |
| Crescendo | LLM01 | evade filtro por-mensagem | **sucesso** (barrado só na conversa) |

> **PII/`golden`/`rag_corpus` omitidos:** a PII sintética aparece *inline* no
> desfecho de exfiltração; a detecção robusta de PII é da **Aula 03 (Presidio)** e
> o *golden set* de RAGAS é da **Aula 07**.

## 3. Coleta / Geração

- **Proveniência:** gerados por [`scripts/generate_datasets.py`](../scripts/generate_datasets.py)
  com **Faker (`pt_BR`)** e templates, **seed fixa = 42** (reprodutível).
- **PII:** qualquer CPF/valor exibido em respostas comprometidas é **fictício**,
  válido apenas em formato. Nunca há dado de pessoa real.
- **Ataques:** derivados de técnicas públicas (Greshake et al., 2023; Russinovich
  et al., 2024; OWASP 2025), em versão **mínima e didática**.

Para (re)gerar os conjuntos completos:

```bash
uv run task seed-data     # ou: python scripts/generate_datasets.py
```

Como a geração é **determinística** (seed = 42), o comando reproduz exatamente os
mesmos arquivos — nada de dados reais entra no versionamento.

## 4. Usos recomendados

- Medir **attack success rate** por classe OWASP (`app/redteam_ci.py`).
- Medir **falso positivo** do guardrail (corpus `benign/`).
- Demonstrar **evasão por ofuscação** e **crescendo** e sua **mitigação**.
- Alimentar a **trilha de auditoria** (`app/audit_log.py`) com eventos de decisão.

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
aprendizado. Segue-se o princípio de **red team defensivo**: expor para corrigir
(Doc 04, seção 14 — autorização, ambiente delimitado, dados sintéticos, critérios
de interrupção). Segredos e credenciais **nunca** são versionados (use `.env`).

## Referências

- Gebru, T. et al. (2021). *Datasheets for Datasets.* Communications of the ACM.
- OWASP Foundation (2025). *Top 10 for LLM Applications, v2025.*
- Greshake, K. et al. (2023). *Indirect Prompt Injection.* AISec'23.
- Russinovich, M. et al. (2024). *Crescendo Multi-Turn Jailbreak.* arXiv:2404.01833.
