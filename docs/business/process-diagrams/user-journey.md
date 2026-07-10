# Jornada do Engenheiro de ML/Segurança no Repositório

A jornada acompanha um engenheiro responsável por levar o **Aurora Assist** de protótipo acadêmico a um desenho de produção governado.

```mermaid
journey
    title Jornada de aprendizagem em segurança de LLMs
    section Fundamentos de risco
      Aula 1: mapear OWASP LLM e MITRE ATLAS: 4: Engenheiro ML, Segurança
      Artefato: matriz de ameaças do Aurora Assist: 5: Engenheiro ML
    section Controles preventivos
      Aula 2: desenhar guardrails e políticas: 4: Engenheiro ML, Produto
      Artefato: catálogo de políticas e fallback: 5: Segurança
      Aula 3: proteger PII e isolar dados: 4: Dados, Segurança
      Artefato: pipeline de mascaramento e RBAC: 5: Dados
    section Validação e conformidade
      Aula 4: executar red teaming e auditoria: 4: Segurança
      Artefato: relatório Garak/PyRIT: 5: Segurança
      Aula 5: demonstrar LGPD e GDPR: 4: Jurídico, DPO
      Artefato: registro de finalidade e evidências: 5: DPO
    section Operação responsável
      Aula 6: monitorar qualidade, custo e drift: 4: SRE, ML Ops
      Artefato: dashboard Langfuse/Evidently: 5: ML Ops
      Aula 7: validar ética, viés e fairness: 4: Governança
      Artefato: relatório Fairlearn/AIF360: 5: Governança
      Aula 8: preparar produção e governança de IA: 5: Comitê IA
      Artefato: gate de produção e modelo operacional: 5: Comitê IA
    section Challenge
      Challenge final: defender ROI, riscos e evidências: 5: Time completo
```

## Fluxo de artefatos

```mermaid
flowchart TD
    A1["Aula 1<br/>Ameaças e vulnerabilidades"] --> X1["Matriz OWASP LLM<br/>MITRE ATLAS"]
    A2["Aula 2<br/>Guardrails e políticas"] --> X2["Catálogo de políticas<br/>bloqueios e fallback"]
    A3["Aula 3<br/>Dados e isolamento"] --> X3["PII redaction<br/>RBAC e Key Vault"]
    A4["Aula 4<br/>Testes e auditoria"] --> X4["Relatório de red teaming<br/>Garak e PyRIT"]
    A5["Aula 5<br/>LGPD/GDPR"] --> X5["DPIA, base legal<br/>e retenção"]
    A6["Aula 6<br/>Governança e monitoramento"] --> X6["Dashboards<br/>drift, custo e abuso"]
    A7["Aula 7<br/>Ética e viés"] --> X7["Fairness report<br/>validação por subgrupos"]
    A8["Aula 8<br/>Produção"] --> X8["Release gate<br/>runbook e evidências"]
    X1 --> C["CHALLENGE<br/>Aurora Assist seguro"]
    X2 --> C
    X3 --> C
    X4 --> C
    X5 --> C
    X6 --> C
    X7 --> C
    X8 --> C
```

## Marcos de aprendizagem

| Aula | Competência desenvolvida | Artefato produzido | Valor para o negócio |
|---:|---|---|---|
| 1 | Reconhecer ameaças específicas de LLM | Matriz de ameaças | Prioriza risco antes do investimento |
| 2 | Traduzir política em controle técnico | Catálogo de guardrails | Reduz respostas inseguras e retrabalho |
| 3 | Proteger dados e acessos | Pipeline PII/RBAC | Diminui exposição regulatória |
| 4 | Testar ofensivamente | Relatório de red teaming | Evita incidentes antes do go-live |
| 5 | Demonstrar conformidade | Evidências LGPD/GDPR | Acelera auditoria e aprovação jurídica |
| 6 | Operar com observabilidade | Dashboard e alertas | Detecta drift e abuso em produção |
| 7 | Validar ética e viés | Relatório de fairness | Reduz risco discriminatório |
| 8 | Produzir com governança | Gate e runbook | Sustenta ROI com controle contínuo |
