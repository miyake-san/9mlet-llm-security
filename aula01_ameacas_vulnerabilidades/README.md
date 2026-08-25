# Aula 01 — Ameaças e Vulnerabilidades em LLMs

> **Disciplina:** Segurança, Guardrails e Conformidade para LLMs
> **Caso condutor:** Banco **Aurora** / assistente **Aurora Assist**
> **Documento-base:** [`MATERIAIS/AULA 1/DOCUMENTO_AULA_1.md`](../../06_Education) · **Status:** ✅ Lab executável

Esta aula é o **diagnóstico** da disciplina: em vez de defender, primeiro aprendemos a **atacar em laboratório controlado**. O lab entrega uma versão **deliberadamente vulnerável** do Aurora Assist (sem guardrails) para que o estudante observe, na prática, os riscos do **OWASP Top 10 for LLM Applications (2025)** antes de construir defesas na Aula 02.

> [!WARNING]
> ⚠️ **Uso ético e legal.** Este diretório contém payloads adversariais (prompt injection, jailbreak) e uma API propositalmente insegura. Eles existem **exclusivamente para uso defensivo em ambiente de laboratório controlado**. Não utilize estas técnicas contra sistemas de terceiros. Todo dado de PII é **100% sintético** (Faker). Nunca versione segredos reais — use `.env` a partir de `.env.example`.

---

## 🎯 Objetivos (Doc 04)

Ao concluir esta aula, o estudante será capaz de:

- Explicar **por que um LLM é uma superfície de ataque diferente** (confusão entre instrução e dado, comportamento probabilístico e agência) — Doc 04, seção 1.
- Aplicar **modelagem de ameaças** (STRIDE/LINDDUN) ao Aurora Assist e mapeá-la para o **OWASP Top 10 for LLM (2025)** — Doc 04, seções 2-3.
- Distinguir **prompt injection direta, indireta e jailbreak** e reproduzir a confusão de autoridade $C = s \Vert u \Vert d$ — Doc 04, seções 4-5.
- Reconhecer **vazamento de dados (LLM06), roubo de modelo (LLM10), poisoning (LLM03), supply chain (LLM05), ferramentas inseguras (LLM07) e agência excessiva (LLM08)** — Doc 04, seções 6-8.
- Executar um **scanning adversarial** (Garak/PyRIT + harness offline) e transformar achados em uma **matriz probabilidade × impacto** $R(t) = P(t) \cdot I(t)$ — Doc 04, seções 9-10.

## 🛡️ Riscos OWASP cobertos

| Risco | Onde aparece no lab |
|---|---|
| **LLM01 — Prompt Injection** | `POST /rag` (injeção indireta via `rag_corpus/`), notebook 02 |
| **LLM06 — Sensitive Information Disclosure** | `POST /chat` (vazamento de *system prompt*), notebook 03 |
| **LLM07 — Insecure Plugin/Tool Design** | `POST /tools/balance` (consulta por CPF arbitrário) |
| **LLM08 — Excessive Agency** | ferramenta de saldo acionável sem autorização (*confused deputy*) |
| **LLM10 — Model Theft** (conceitual) | notebook 03 (extração/fingerprinting) |
| LLM03 / LLM05 (conceitual) | notebook 03 + checklist de *supply chain* |

## 🧱 Arquitetura do Lab

```mermaid
flowchart LR
    Attacker([Red Team / Estudante]) -->|payloads| API
    subgraph Stack["docker compose up"]
        API[vulnerable-rag-api<br/>FastAPI · SEM guardrails]
        OLLAMA[(ollama<br/>llama3.1:8b — offline)]
        RT[redteam-runner<br/>Garak · PyRIT · replay<br/>profile: redteam]
    end
    API -->|s || u || d| OLLAMA
    API -->|RAG| CORPUS[(rag_corpus/<br/>docs c/ injeção indireta)]
    API -->|tool insegura| TOOL[/tools/balance/]
    RT -->|ataca| API
    RT -->|achados JSON| REPORTS[(reports/)]
```

Nenhuma camada defensiva está presente **por design** — o objetivo é medir a **linha de base de insegurança** que a Aula 02 irá corrigir.

## 🚀 Como subir

Pré-requisitos: [Docker](https://docs.docker.com/), [uv](https://docs.astral.sh/uv/) e [Ollama](https://ollama.com/) (para uso fora do container).

```bash
# 1) ambiente Python (offline-first) desta aula
uv sync

# 2) segredos / endpoints (sem valores reais)
cp .env.example .env            # Windows: copy .env.example .env

# 3) suba a stack do Lab (API vulnerável + Ollama)
uv run task up                  # docker compose up -d

# 4) baixe o modelo local (uma vez)
docker compose exec ollama ollama pull llama3.1:8b

# 5) gere os datasets sintéticos completos (seed fixa)
uv run task seed-data

# 6) rode a campanha adversarial (Garak/PyRIT + replay offline)
uv run task scan                # docker compose --profile redteam run --build --rm redteam-runner

# encerrar
uv run task down
```

> **Offline-first:** o lab roda 100% local via Ollama. O backend **Azure** (Azure OpenAI/Foundry) é opcional: defina `LLM_BACKEND=azure` e as variáveis `AZURE_OPENAI_*` no `.env` e instale o grupo extra com `uv sync --group azure`.

## 📓 Notebooks (vídeos 1-4)

| Vídeo | Notebook | Tipo | Conteúdo |
|---|---|---|---|
| **1 de 4** — Panorama de Ameaças e OWASP Top 10 | *(sem notebook)* | conceitual/teórico | a base de código serve aos vídeos 2-4 |
| **2 de 4** — Prompt Injection e Jailbreak | [`notebooks/02_prompt_injection.ipynb`](notebooks/02_prompt_injection.ipynb) | conceitual + prático | injeção direta/indireta, jailbreak, encoding attack |
| **3 de 4** — Data Leakage, Model Theft, Supply Chain | [`notebooks/03_data_leakage_model_theft.ipynb`](notebooks/03_data_leakage_model_theft.ipynb) | conceitual + prático | LLM06/LLM10/LLM03/LLM05/LLM07/LLM08 |
| **4 de 4** — Lab: Scanning com Garak e PyRIT | [`notebooks/04_lab_e2e.ipynb`](notebooks/04_lab_e2e.ipynb) | conceitual + prático (E2E) | orquestra a stack, gera matriz de risco e `reports/` |

Abra com `uv run task lab` (JupyterLab). Execute em **Restart & Run All** — seeds fixas garantem reprodutibilidade.

## 📦 Datasets

Corpora de **texto** (não CSV numérico), sintéticos e reprodutíveis. Detalhes, proveniência, licença e **advertência ética** no **[DATASHEET](data/README.md)**.

| Pasta | Conteúdo | Uso |
|---|---|---|
| `data/attacks/` | prompt injection + jailbreak rotulados por classe OWASP | medir *attack success rate* |
| `data/benign/` | prompts bancários legítimos | medir **falso positivo** |
| `data/pii_samples/` | PII PT-BR sintético (CPF/CNPJ/RG/CEP) | detectar vazamento (LLM06) |
| `data/rag_corpus/` | documentos do Aurora — alguns com **injeção indireta** | RAG vulnerável (LLM01) |

> `data/golden/` (Q&A de referência para RAGAS) **é omitido** nesta aula — pertence à **Aula 07 (Ética, Viés e Validação)**.

## 🧪 Testes

```bash
uv run task test    # pytest — determinístico, offline, sem LLM
uv run task lint    # ruff check
```

Cobrem: catálogo OWASP + mapeamento STRIDE + matriz de risco (`test_threat_model.py`); heurísticas de detecção de injeção e PII BR (`test_detectors.py`, precursoras dos guardrails da Aula 02 e do Presidio da Aula 03); *harness* de red team com contabilidade FP/FN (`test_redteam.py`); caracterização da API vulnerável (`test_vulnerable_app.py`); e **regressão de segurança** (`test_security_regression.py`).

## ⚠️ Uso Ético

Os payloads e a API insegura destinam-se **apenas ao aprendizado defensivo em laboratório**. Nenhum segredo ou PII real é versionado. Consulte o [DATASHEET](data/README.md) e a política do repositório em [`../README.md`](../README.md#-uso-ético-e-legal).

## 📚 Referências do Doc 04

- OWASP Foundation (2025). *Top 10 for LLM Applications, v2025.* https://genai.owasp.org/
- Greshake, K. et al. (2023). *Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection.* AISec'23. DOI: 10.1145/3605764.3623985
- Wei, A.; Haghtalab, N.; Steinhardt, J. (2023). *Jailbroken: How Does LLM Safety Training Fail?* NeurIPS 2023.
- Carlini, N. et al. (2021). *Extracting Training Data from Large Language Models.* USENIX Security.
- MITRE (2024). *ATLAS — Adversarial Threat Landscape for AI Systems.* https://atlas.mitre.org/
- NIST (2024). *Adversarial Machine Learning: A Taxonomy and Terminology.* NIST AI 100-2 E2023.
- Shostack, A. (2014). *Threat Modeling: Designing for Security.* Wiley.

## 🎥 Vídeos relacionados

1. Panorama de Ameaças em LLMs e OWASP Top 10 (2025) — *30 min*
2. Prompt Injection Direta, Indireta e Técnicas de Jailbreak — *35 min*
3. Data Leakage, Model Theft e Supply Chain Attacks — *30 min*
4. Lab: Scanning de Vulnerabilidades com Garak e PyRIT — *25 min*

## 🧭 Navegação

- ⬅️ [Voltar ao README principal](../README.md)
- 📖 [Arquitetura](../docs/architecture/overview.md) · 🎯 [Threat Model](../docs/architecture/diagrams/threat-model.md) · 💼 [Business Cases](../docs/business/README.md)
- ➡️ Próxima: [Aula 02 — Guardrails e Políticas](../aula02_guardrails_politicas/README.md)
