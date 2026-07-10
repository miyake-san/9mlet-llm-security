# 9mlet-llm-security

![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white)
![License MIT](https://img.shields.io/badge/License-MIT-green.svg)

Repositório acadêmico da disciplina **Segurança, Conformidade e Guardrails para LLMs**, da pós-graduação/mestrado em Engenharia de Machine Learning.

## 📋 Sobre

Este repositório reúne materiais práticos e conceituais para o estudo de segurança aplicada a sistemas baseados em Large Language Models (LLMs). O objetivo é capacitar o aluno a projetar, implementar e operar guardrails, políticas de segurança e controles de conformidade em aplicações com modelos generativos.

A disciplina adota como fio condutor a empresa fictícia **Banco Aurora** e o assistente **Aurora Assist**, um chatbot bancário com LLM. Ao longo das 8 aulas, o sistema evolui de um protótipo vulnerável para uma solução com controles de segurança, privacidade, auditoria, observabilidade, governança e implantação segura.

A abordagem combina fundamentos acadêmicos, frameworks de risco, normas regulatórias e experimentação aplicada. O conteúdo cobre ameaças e vulnerabilidades, proteção e isolamento de dados, red teaming, LGPD/GDPR/EU AI Act, LLMOps, ética, viés, fairness e DevSecOps para IA.

O público-alvo são estudantes de nível mestrado/pós-graduação, engenheiros de Machine Learning, arquitetos de software, profissionais de segurança e pesquisadores interessados em desenvolver sistemas de IA generativa confiáveis, auditáveis e aderentes a requisitos regulatórios.

## 🎯 Objetivos de Aprendizagem

Ao concluir a disciplina, o aluno deverá ser capaz de:

- Identificar, classificar e demonstrar ameaças específicas de LLMs, incluindo prompt injection, jailbreak e excessive agency.
- Projetar guardrails de entrada, saída e comportamento usando defesa em profundidade e policy-as-code.
- Implementar proteção de dados sensíveis, anonimização/pseudonimização e isolamento seguro de ferramentas.
- Automatizar testes de segurança, red teaming, auditoria e geração de evidências técnicas.
- Traduzir requisitos de LGPD, GDPR e EU AI Act em controles de engenharia verificáveis.
- Operar observabilidade, monitoramento, detecção de drift e métricas de LLMOps em produção.
- Avaliar qualidade, viés, fairness e riscos éticos em aplicações com LLMs.
- Integrar governança de IA, AI-BOM/SBOM e práticas DevSecOps em pipelines de implantação segura.

## 📚 Conteúdo das Aulas

### 1. [Ameaças e Vulnerabilidades em LLMs](01_ameacas_e_vulnerabilidades/)

**Objetivo específico:** identificar e classificar ameaças de LLMs no contexto do Aurora Assist.

**Teoria-chave:** Prompt injection, direta ou indireta, jailbreak e excessive agency representam riscos centrais para sistemas conversacionais com ferramentas e dados sensíveis. O OWASP Top 10 for LLM e o MITRE ATLAS ajudam a mapear a superfície de ataque e a organizar controles defensivos de forma sistemática.

**Tecnologias e referências:** Garak, PyRIT, OWASP Top 10 for LLM, MITRE ATLAS, NIST AI 100-2.

### 2. [Guardrails e Políticas para LLMs](02_guardrails_e_politicas/)

**Objetivo específico:** implementar guardrails de input, output e comportamento para reduzir respostas inseguras e ações indevidas.

**Teoria-chave:** Defense-in-depth e policy-as-code permitem que políticas de segurança sejam expressas, versionadas e testadas como artefatos de engenharia. Guardrails programáveis interceptam entradas e saídas inseguras, aplicando restrições antes, durante e depois da chamada ao modelo.

**Tecnologias e referências:** NeMo Guardrails (Colang), Guardrails AI, Llama Guard 3, Azure AI Content Safety, HarmBench, AdvBench.

### 3. [Proteção de Dados e Isolamento de Ferramentas](03_protecao_de_dados_e_isolamento/)

**Objetivo específico:** proteger PII e isolar ferramentas usadas pelo assistente bancário.

**Teoria-chave:** Anonimização, pseudonimização e minimização reduzem a exposição de dados sensíveis em prompts, logs e respostas. Zero Trust e least privilege limitam o impacto de falhas, restringindo permissões de ferramentas, credenciais e integrações externas.

**Tecnologias e referências:** Microsoft Presidio, MCP, Azure Key Vault, Entra ID, Confidential Computing.

### 4. [Testes de Segurança e Auditoria em LLMs](04_testes_de_seguranca_e_auditoria/)

**Objetivo específico:** automatizar red teaming e auditoria para gerar evidências de due diligence.

**Teoria-chave:** Red teaming sistemático, incluindo abordagens como PAIR, permite testar comportamentos adversariais de forma repetível. Trilhas imutáveis de auditoria, métricas de severidade e registros estruturados dão suporte à rastreabilidade, investigação e prestação de contas.

**Tecnologias e referências:** PyRIT, Garak, promptfoo, Azure Monitor/Sentinel, CVSS-AI.

### 5. [Conformidade e Proteção de Dados (LGPD/GDPR)](05_conformidade_lgpd_gdpr/)

**Objetivo específico:** traduzir regulação de privacidade e IA em controles técnicos aplicáveis ao Aurora Assist.

**Teoria-chave:** Bases legais, DPIA e direitos do titular deixam de ser apenas requisitos jurídicos e passam a orientar arquitetura, logs, retenção, consentimento e resposta a incidentes. LGPD, GDPR e EU AI Act exigem governança, transparência e avaliação de risco proporcionais ao contexto de uso.

**Tecnologias e referências:** Microsoft Presidio, Azure Log Analytics, DPIA, LGPD, GDPR, EU AI Act.

### 6. [Governança de Dados e Monitoramento de LLMs](06_governanca_e_monitoramento/)

**Objetivo específico:** operar observabilidade, monitoramento e detecção de drift em pipelines de LLMOps.

**Teoria-chave:** SLIs e SLOs ajudam a acompanhar qualidade, custo, latência e segurança de sistemas com LLMs ao longo do tempo. Técnicas de drift, como KS, PSI e MMD, combinadas com tracing, apoiam a detecção de degradação, anomalias e mudanças de distribuição.

**Tecnologias e referências:** Evidently AI, Langfuse, OpenTelemetry, Azure Workbooks, Grafana.

### 7. [Ética, Viés e Validação em LLMs](07_etica_vies_e_validacao/)

**Objetivo específico:** auditar viés/fairness e validar qualidade de respostas em cenários sensíveis.

**Teoria-chave:** Métricas de fairness, como paridade demográfica e equalized odds, permitem investigar desigualdades sistemáticas entre grupos. Avaliação com LLM-as-Judge e RAGAS complementa testes tradicionais ao medir qualidade semântica, groundedness e adequação ao contexto.

**Tecnologias e referências:** Fairlearn, AIF360, RAGAS, Azure AI Evaluation SDK.

### 8. [Governança de IA e Implantação Segura em Produção](08_governanca_de_ia_e_producao/)

**Objetivo específico:** integrar controles e implantar o Aurora Assist com governança contínua.

**Teoria-chave:** DevSecOps, AI-BOM/SBOM e governança contínua tornam segurança e conformidade parte do ciclo de vida do produto, não uma etapa final. NIST AI RMF e ISO/IEC 42001 fornecem referência para gestão de risco, responsabilidades, monitoramento e melhoria contínua.

**Tecnologias e referências:** Azure AI Foundry, Microsoft Agent Framework, Purview AI Hub, Azure Policy.

## 🚀 Como Usar Este Repositório

### Pré-requisitos

- Python 3.12 ou superior (o `uv` pode instalá-lo automaticamente).
- [`uv`](https://docs.astral.sh/uv/) para gerenciamento de pacotes e ambientes virtuais.
- Docker para laboratórios que exigem serviços isolados.
- Node.js/npm para instalação do `promptfoo`.
- Dependências declaradas em [`pyproject.toml`](pyproject.toml) e travadas em `uv.lock`.

### Instalação

```powershell
# 1. Instale o uv (caso ainda não tenha)
#    Windows (PowerShell):
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
#    Linux/macOS: curl -LsSf https://astral.sh/uv/install.sh | sh

# 2. Clone o repositório e sincronize o ambiente
git clone https://github.com/miyake-san/9mlet-llm-security.git
cd 9mlet-llm-security
uv sync            # cria o .venv e instala tudo a partir de pyproject.toml / uv.lock

# 3. Ferramenta Node usada na Aula 4
npm install -g promptfoo
```

Com o `uv` **não é necessário ativar o ambiente manualmente**: use `uv run <comando>` para
executar qualquer ferramenta dentro do ambiente sincronizado. O comando `uv sync` é idêntico em
Windows, Linux e macOS. Caso prefira ativar, o `.venv` fica na raiz
(`.\.venv\Scripts\Activate.ps1` no Windows; `source .venv/bin/activate` no Linux/macOS).

### Execução por aula

Cada pasta de aula contém materiais próprios, como notebooks, scripts, datasets sintéticos, testes e instruções específicas. O fluxo recomendado é:

```powershell
cd 01_ameacas_e_vulnerabilidades
uv run jupyter lab
```

Quando houver tarefas automatizadas configuradas com Taskipy, consulte o `README.md` da aula e execute comandos no formato:

```powershell
uv run task --list
uv run task test
```

Para avaliações com `promptfoo`, use a pasta da aula correspondente e execute os cenários definidos localmente:

```powershell
promptfoo eval
```

## 📂 Estrutura do Repositório

```text
9mlet-llm-security/
├── 01_ameacas_e_vulnerabilidades/        # Ameaças, jailbreak, prompt injection e superfície de ataque
├── 02_guardrails_e_politicas/            # Guardrails, policy-as-code e defesa em profundidade
├── 03_protecao_de_dados_e_isolamento/    # PII, anonimização, MCP e isolamento de ferramentas
├── 04_testes_de_seguranca_e_auditoria/   # Red teaming, auditoria, evidências e promptfoo
├── 05_conformidade_lgpd_gdpr/            # LGPD, GDPR, EU AI Act e controles técnicos
├── 06_governanca_e_monitoramento/        # LLMOps, observabilidade, tracing e drift
├── 07_etica_vies_e_validacao/            # Fairness, viés, validação e qualidade
├── 08_governanca_de_ia_e_producao/       # DevSecOps, governança de IA e produção segura
├── docs/
│   ├── architecture/
│   │   ├── overview.md                   # Visão arquitetural do Aurora Assist
│   │   ├── diagrams/
│   │   │   ├── system-architecture.md    # Diagrama de arquitetura do sistema
│   │   │   ├── data-flow.md              # Fluxos de dados e limites de confiança
│   │   │   └── deployment.md             # Topologia de implantação segura
│   │   └── adr/
│   │       ├── template.md               # Template de Architecture Decision Record
│   │       ├── 0001-escolha-framework-guardrails.md
│   │       ├── 0002-estrategia-protecao-anonimizacao-dados.md
│   │       ├── 0003-isolamento-de-ferramentas-mcp.md
│   │       ├── 0004-observabilidade-llmops.md
│   │       └── 0005-infraestrutura-deployment-seguro.md
│   ├── business/
│   │   ├── README.md                     # Visão de negócio e contexto do Banco Aurora
│   │   ├── use-cases.md                  # Casos de uso funcionais e de risco
│   │   ├── business-case-aurora-assist.md
│   │   ├── business-case-healthcare-compliance.md
│   │   ├── business-case-customer-service-redteaming.md
│   │   └── process-diagrams/
│   │       ├── business-process.md       # Processo de negócio
│   │       └── user-journey.md           # Jornada do usuário
│   └── contributing.md                   # Guia de contribuição
├── pyproject.toml                        # Projeto e dependências (gerenciado pelo uv)
├── uv.lock                               # Lockfile reproduzível (uv)
├── .python-version                       # Versão de Python fixada (3.12)
├── .gitignore                            # Arquivos ignorados pelo Git
├── LICENSE                               # Licença MIT
└── README.md                             # Documentação central do repositório
```

## 📖 Documentação

- [Visão de arquitetura](docs/architecture/overview.md)
- Diagramas:
  - [Arquitetura do sistema](docs/architecture/diagrams/system-architecture.md)
  - [Fluxo de dados](docs/architecture/diagrams/data-flow.md)
  - [Implantação](docs/architecture/diagrams/deployment.md)
- ADRs:
  - [Template de ADR](docs/architecture/adr/template.md)
  - [ADR 0001 — Escolha do framework de guardrails](docs/architecture/adr/0001-escolha-framework-guardrails.md)
  - [ADR 0002 — Estratégia de proteção e anonimização de dados](docs/architecture/adr/0002-estrategia-protecao-anonimizacao-dados.md)
  - [ADR 0003 — Isolamento de ferramentas com MCP](docs/architecture/adr/0003-isolamento-de-ferramentas-mcp.md)
  - [ADR 0004 — Observabilidade e LLMOps](docs/architecture/adr/0004-observabilidade-llmops.md)
  - [ADR 0005 — Infraestrutura e deployment seguro](docs/architecture/adr/0005-infraestrutura-deployment-seguro.md)
- Negócio:
  - [Documentação de negócio](docs/business/README.md)
  - [Casos de uso](docs/business/use-cases.md)
  - [Business case — Aurora Assist](docs/business/business-case-aurora-assist.md)
  - [Business case — Healthcare Compliance](docs/business/business-case-healthcare-compliance.md)
  - [Business case — Customer Service Red Teaming](docs/business/business-case-customer-service-redteaming.md)
  - [Processo de negócio](docs/business/process-diagrams/business-process.md)
  - [Jornada do usuário](docs/business/process-diagrams/user-journey.md)

## 🤝 Contribuindo

Contribuições são bem-vindas para melhorar exemplos, notebooks, testes, documentação e materiais de apoio. Leia o guia completo em [docs/contributing.md](docs/contributing.md).

## 📄 Licença

Este projeto está licenciado sob a licença **MIT**. Consulte o arquivo [LICENSE](LICENSE) para mais detalhes.
