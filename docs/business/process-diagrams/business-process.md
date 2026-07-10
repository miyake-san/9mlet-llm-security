# Processo de Negócio — Secure LLMOps Lifecycle

Este fluxo representa o ciclo end-to-end de um **LLM seguro em produção**, conectando requisitos de negócio, engenharia de ML, segurança ofensiva, governança e auditoria contínua.

```mermaid
graph TD
    A(["Requisito de negócio<br/>caso de uso e risco"]) --> B["Classificação de impacto<br/>dados, setor e criticidade"]
    B --> C["Threat modeling<br/>OWASP LLM + MITRE ATLAS"]
    C --> D["Design de guardrails<br/>políticas, escopo e fallback"]
    D --> E["Proteção de dados<br/>PII, isolamento e retenção"]
    E --> F["Implementação do LLM/RAG<br/>fontes aprovadas e RBAC"]
    F --> G["Testes e red teaming<br/>Garak, PyRIT e suites adversariais"]
    G --> H{"Gate de segurança aprovado?"}
    H -- "Não" --> I["Remediação<br/>prompts, políticas, dados ou modelo"]
    I --> D
    H -- "Sim" --> J["Deploy controlado<br/>canary, feature flags e Key Vault"]
    J --> K["Monitoramento contínuo<br/>qualidade, abuso, drift e custo"]
    K --> L{"Drift ou incidente?"}
    L -- "Sim" --> M["Resposta a incidente<br/>contenção, RCA e comunicação"]
    M --> N["Ajustar ou retreinar<br/>novo dataset e validação"]
    N --> G
    L -- "Não" --> O["Auditoria e conformidade<br/>LGPD, GDPR, NIST, ISO 42001"]
    O --> P{"Mudança regulatória<br/>ou nova política?"}
    P -- "Sim" --> B
    P -- "Não" --> K
```

## Controles-chave por etapa

| Etapa | Controle principal | Evidência esperada |
|---|---|---|
| Requisito | Matriz de risco e finalidade | Documento de caso de uso aprovado |
| Threat modeling | OWASP LLM e MITRE ATLAS | Registro de ameaças e severidade |
| Guardrails | Políticas versionadas | Testes unitários e regras de bloqueio |
| Dados | PII, criptografia e retenção | Relatório de DLP/Presidio/Purview |
| Red teaming | Ataques automatizados e humanos | Relatório Garak/PyRIT com SLA |
| Gate | Critérios de aceite | Aprovação de segurança e negócio |
| Produção | Observabilidade e alertas | Dashboards Langfuse/Evidently AI |
| Auditoria | NIST AI RMF, ISO/IEC 42001, LGPD/GDPR | Evidências imutáveis e revisão periódica |
