# Mapa de Rastreabilidade — LGPD / GDPR / EU AI Act ↔ Aulas ↔ Controles

Este mapa conecta **requisitos normativos** e **frameworks de governança** às **aulas** da disciplina e aos **controles técnicos** implementados para o **Aurora Assist**. Serve como base para auditoria, *Data Protection Impact Assessment* (DPIA) e evidências de *due diligence*.

> Legenda de aulas: as pastas seguem o padrão `aula0N_...`. Ver [README](../../README.md#-conteúdo-das-aulas).

## LGPD (Lei nº 13.709/2018)

| Artigo / Requisito | Descrição | Aula(s) | Controle técnico no repo |
|---|---|---|---|
| Art. 6º, VII — Segurança | Medidas técnicas de proteção | 3, 4 | Presidio, guardrails, sandbox MCP, red teaming |
| Art. 6º, III — Minimização | Coleta/uso mínimo necessário | 3, 5 | *Data minimization* em prompts/logs, redaction de PII |
| Arts. 7º / 11 — Bases legais | Fundamento do tratamento | 5 | Registro de base legal e consentimento |
| Arts. 17–22 — Direitos do titular | Acesso, correção, exclusão | 5 | Purga seletiva em vector store, `dpia.py` |
| Art. 37 — Registro de operações | *Record of Processing* | 4, 5 | Azure Log Analytics, trilha de auditoria imutável (WORM) |
| Art. 46 — Segurança | Prevenção de incidentes | 4, 8 | Gates de red team, resposta a incidentes |
| Art. 48 — Comunicação de incidente | Notificação à ANPD/titular | 8 | Playbook de *incident response* |

## GDPR (Regulation (EU) 2016/679)

| Artigo / Requisito | Descrição | Aula(s) | Controle técnico no repo |
|---|---|---|---|
| Art. 5 — Princípios | Minimização, integridade, confidencialidade | 3, 5 | Presidio, criptografia, retenção limitada |
| Art. 22 — Decisão automatizada | Direito a não ser objeto de decisão só automatizada | 5, 7 | Revisão humana, explicabilidade, auditoria de viés |
| Art. 25 — Privacy by Design | Proteção desde a concepção | 3 | Guardrails de entrada/saída, Zero Trust |
| Art. 30 — RoPA | Registro das atividades de tratamento | 5 | Log Analytics, catálogo de dados |
| Art. 35 — DPIA | Avaliação de impacto | 5 | Template de DPIA, `dpia.py` |
| Art. 32 — Segurança do tratamento | Medidas técnicas e organizacionais | 4, 8 | Red teaming em CI/CD, hardening de contêiner |

## EU AI Act (Regulation (EU) 2024/1689)

| Requisito | Descrição | Aula(s) | Controle técnico no repo |
|---|---|---|---|
| Classificação de risco | Mínimo / limitado / alto / inaceitável | 8 | Matriz de risco por caso de uso |
| Art. 9 — Gestão de risco | Processo contínuo de risco (alto risco) | 8 | NIST AI RMF, ADRs, gates |
| Art. 12 — Logging | Registro automático de eventos | 6 | Langfuse, OpenTelemetry, Azure Monitor |
| Art. 14 — Supervisão humana | *Human oversight* | 5, 8 | Aprovação humana em ações sensíveis (MCP) |
| Art. 15 — Robustez e cibersegurança | Resiliência a ataques adversariais | 1, 2, 4 | Garak/PyRIT, guardrails multi-camada |
| Transparência (GPAI) | Documentação técnica do modelo | 8 | AI-BOM (CycloneDX), Purview |

## Frameworks de Governança

| Framework | Função / Controle | Aula(s) | Evidência no repo |
|---|---|---|---|
| NIST AI RMF 1.0 | Govern · Map · Measure · Manage | 8 | ADRs, gates de deploy, governança contínua |
| ISO/IEC 42001:2023 | AIMS (ciclo PDCA, Anexo A) | 8 | Políticas, papéis, monitoramento |
| OWASP Top 10 for LLM | Catálogo de riscos LLM01–LLM10 | 1–4 | *Threat model*, red teaming, guardrails |
| MITRE ATLAS | Táticas/técnicas adversariais | 1, 4 | Campanhas Garak/PyRIT |

---

> **Observação:** cada linha deve ser sustentada por uma **evidência verificável** (código, ADR, relatório de red team em `reports/`, dashboard de observabilidade). A rastreabilidade é o que transforma "conformidade declarada" em "conformidade demonstrável".
