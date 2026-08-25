# 💼 Negócio — Banco Aurora / Aurora Assist

Esta pasta reúne os **artefatos de negócio** que sustentam a estratégia de **segurança de LLMs** do **Banco Aurora**. O caso condutor é o **Aurora Assist**, chatbot bancário com LLM que combina **RAG** sobre políticas internas e **ferramentas** para saldo, PIX e cartões, operado em regime *offline-first* (Ollama) e endurecido por **defesa em profundidade**.

O propósito destes documentos é conectar **risco → controle técnico → aula**, traduzindo decisões de arquitetura de segurança em valor de negócio mensurável: **perda evitada**, **conformidade demonstrável** e **continuidade operacional**. Toda a narrativa é 100% orientada a segurança de LLMs — não a treino/avaliação de modelos.

## 🏦 Contexto do Banco Aurora

O Banco Aurora é uma instituição financeira digital que precisa **escalar atendimento** sem ampliar proporcionalmente o *contact center*, preservando **sigilo bancário**, **proteção de dados pessoais** e **conformidade regulatória** (LGPD, GDPR, EU AI Act). O Aurora Assist é estratégico porque concentra quatro vetores de risco simultâneos:

- 📈 **Alto volume** de interações digitais (superfície de ataque ampla e contínua).
- 🔐 **Dados sensíveis** (PII e dados financeiros sob sigilo bancário).
- 💸 **Risco financeiro direto** (ferramentas que executam ações como PIX e emissão de cartão).
- ⚖️ **Exposição regulatória** (LGPD, GDPR, EU AI Act, Banco Central).

Por isso o banco adota **Secure LLMOps** desde o desenho: segurança é requisito de engenharia versionável e testável, não uma etapa final. Ameaças centrais incluem *prompt injection* (direta e indireta via RAG), **vazamento de PII**, *excessive agency* nas ferramentas e ausência de evidências para auditoria.

## 📑 Business Cases

| Caso de negócio | Foco de segurança | Risco principal (OWASP LLM) | Aulas relacionadas |
|---|---|---|---|
| [Aurora Assist — Assistente Bancário Seguro](business-case-aurora-assist-guardrails.md) | Guardrails de ponta a ponta contra *prompt injection* e vazamento de PII | LLM01 · LLM06 · LLM08 | [1](../../aula01_ameacas_vulnerabilidades/) · [2](../../aula02_guardrails_politicas/) · [3](../../aula03_protecao_dados_isolamento/) · [4](../../aula04_testes_seguranca_auditoria/) · [6](../../aula06_governanca_monitoramento/) · [8](../../aula08_governanca_deploy_seguro/) |
| [Conformidade LGPD/GDPR/EU AI Act](business-case-conformidade-lgpd.md) | Atendimento automatizado privacy-first, minimização e direitos do titular | LLM06 (+ LGPD/GDPR/EU AI Act) | [3](../../aula03_protecao_dados_isolamento/) · [5](../../aula05_conformidade_lgpd_gdpr/) |
| [Deploy Seguro e Governança Contínua](business-case-deploy-seguro-governanca.md) | Esteira DevSecOps com gates adversariais, AI-BOM e governança | LLM05 (+ regressão de segurança) | [4](../../aula04_testes_seguranca_auditoria/) · [6](../../aula06_governanca_monitoramento/) · [8](../../aula08_governanca_deploy_seguro/) |

> 🧩 Os três casos são **complementares**: o primeiro estabelece a defesa em profundidade do produto, o segundo garante a **conformidade** de privacidade, e o terceiro assegura que a segurança **não regride** ao longo do ciclo de vida.

### Aurora Assist — Assistente Bancário Seguro
Núcleo do produto: classificação de risco, detecção de *prompt injection*, *redaction* de PII, RAG governado e ferramentas isoladas por MCP, com ROI orientado a **deflexão segura de atendimento**. É o caso base sobre o qual os demais se apoiam.

### Conformidade LGPD/GDPR/EU AI Act
Foca o **tratamento de dados pessoais** do atendimento automatizado: minimização, base legal e consentimento, DPIA, purga seletiva e *logging* de operações (LGPD art. 37 / GDPR art. 30). ROI orientado a **risco regulatório evitado** (multas e dano reputacional).

### Deploy Seguro e Governança Contínua
Trata a **operação** do sistema: *blue/green* + *canary*, gates de red team (Garak/PyRIT/promptfoo) em CI/CD, AI-BOM (CycloneDX) e governança (NIST AI RMF, ISO/IEC 42001, Purview, Azure Policy). ROI orientado a **redução de incidentes** e **MTTD/MTTR**.

## 🔗 Casos de Uso e Diagramas de Processo

- 📚 [`use-cases.md`](use-cases.md) — catálogo de **casos de uso de segurança** do Aurora Assist (risco OWASP LLM, controle técnico e aula associada).
- 🔄 [`process-diagrams/secure-sdlc.md`](process-diagrams/secure-sdlc.md) — ciclo de **desenvolvimento seguro** (Secure SDLC).
- 🚨 [`process-diagrams/incident-response.md`](process-diagrams/incident-response.md) — **playbook de resposta a incidentes** de segurança de LLM.

## 📋 Conformidade

O detalhamento normativo vive em [`../compliance/`](../compliance/):

- [`../compliance/README.md`](../compliance/README.md) — visão geral da rastreabilidade normativa.
- [`../compliance/mapa-lgpd-gdpr-euaiact.md`](../compliance/mapa-lgpd-gdpr-euaiact.md) — tabela **cláusula normativa ↔ aula ↔ controle técnico**.

## 🗂️ Mapa de Navegação

```
docs/business/
├── README.md                                  (este índice)
├── use-cases.md                               (catálogo de casos de uso)
├── business-case-aurora-assist-guardrails.md  (caso base — já existente)
├── business-case-conformidade-lgpd.md         (conformidade LGPD/GDPR/EU AI Act)
├── business-case-deploy-seguro-governanca.md  (deploy seguro + governança)
└── process-diagrams/
    ├── secure-sdlc.md                          (ciclo de desenvolvimento seguro)
    └── incident-response.md                    (resposta a incidentes)
```

> 🔎 Para o mapeamento completo das 8 aulas, ver o [README do repositório](../../README.md#-conteúdo-das-aulas).

---

> ⚠️ Material **educacional**. Números de ROI e métricas são estimativas ilustrativas para fins didáticos e não constituem aconselhamento financeiro ou jurídico.
