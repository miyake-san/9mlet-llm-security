# Casos de Uso de Negócio — Segurança e Conformidade de LLMs

Os casos abaixo conectam riscos de LLM a resultados de negócio mensuráveis. Todos podem ser implementados incrementalmente ao longo das 8 aulas, usando o **Banco Aurora** como narrativa principal.

| # | Caso de uso | Problema de negócio | Papel dos guardrails/segurança | Aulas relacionadas |
|---:|---|---|---|---|
| 1 | **Aurora Assist — assistente bancário seguro** | Alto custo de atendimento, risco de resposta incorreta sobre crédito, PIX, cartões e investimentos. | Políticas de resposta, detecção de prompt injection, filtragem de PII, RAG com controle de acesso, auditoria. | [Aula 1](../../01_ameacas_e_vulnerabilidades/), [Aula 2](../../02_guardrails_e_politicas/), [Aula 3](../../03_protecao_de_dados_e_isolamento/), [Aula 8](../../08_governanca_de_ia_e_producao/) |
| 2 | **Copiloto clínico com proteção de PII** | Profissionais de saúde precisam resumir prontuários e orientar condutas administrativas sem expor dados sensíveis. | Mascaramento com Presidio, políticas LGPD/GDPR, logs minimizados, avaliação de respostas inseguras. | [Aula 3](../../03_protecao_de_dados_e_isolamento/), [Aula 5](../../05_conformidade_lgpd_gdpr/), [Aula 7](../../07_etica_vies_e_validacao/) |
| 3 | **Atendimento ao cliente com guardrails** | Chatbots podem oferecer compensações indevidas, prometer prazos não aprovados ou revelar instruções internas. | Guardrails de política comercial, moderação de conteúdo, bloqueio de jailbreak, fallback humano. | [Aula 2](../../02_guardrails_e_politicas/), [Aula 4](../../04_testes_de_seguranca_e_auditoria/), [Aula 6](../../06_governanca_e_monitoramento/) |
| 4 | **Assistente jurídico com conformidade** | Equipes jurídicas gastam horas revisando contratos, mas LLMs podem alucinar cláusulas ou violar sigilo. | RAG com fontes autorizadas, citações obrigatórias, classificação de documentos, trilha de auditoria. | [Aula 3](../../03_protecao_de_dados_e_isolamento/), [Aula 5](../../05_conformidade_lgpd_gdpr/), [Aula 8](../../08_governanca_de_ia_e_producao/) |
| 5 | **RAG corporativo com controle de acesso** | Funcionários consultam políticas e dados internos, mas a IA pode vazar informação entre áreas. | Autorização por identidade, isolamento de índice, filtros ABAC/RBAC, teste de data exfiltration. | [Aula 1](../../01_ameacas_e_vulnerabilidades/), [Aula 3](../../03_protecao_de_dados_e_isolamento/), [Aula 6](../../06_governanca_e_monitoramento/) |
| 6 | **Agente com ferramentas isoladas via MCP** | Agentes conectados a e-mail, CRM ou pagamentos podem executar ações fora de escopo. | Sandboxing de ferramentas, allowlist de ações, aprovação humana, secrets em Key Vault. | [Aula 2](../../02_guardrails_e_politicas/), [Aula 3](../../03_protecao_de_dados_e_isolamento/), [Aula 8](../../08_governanca_de_ia_e_producao/) |
| 7 | **Moderação de conteúdo e prevenção de abuso** | Plataformas digitais precisam bloquear fraude, discurso de ódio, automutilação e engenharia social. | Classificadores de segurança, Llama Guard 3, Azure AI Content Safety, métricas de precisão/recall. | [Aula 2](../../02_guardrails_e_politicas/), [Aula 7](../../07_etica_vies_e_validacao/) |
| 8 | **Red Teaming as a Service para LLMs** | Organizações aprovam copilotos sem medir jailbreak, prompt injection e vazamento de dados. | Garak/PyRIT, suites OWASP LLM, MITRE ATLAS, relatórios executivos e gates de release. | [Aula 1](../../01_ameacas_e_vulnerabilidades/), [Aula 4](../../04_testes_de_seguranca_e_auditoria/), [Aula 6](../../06_governanca_e_monitoramento/) |

## Priorização sugerida

| Prioridade | Critério | Casos recomendados |
|---|---|---|
| Alta | Dados pessoais, impacto regulatório e escala de usuários | 1, 2, 5, 8 |
| Média | Eficiência operacional com risco controlado | 3, 4, 6 |
| Exploratória | Aprendizado técnico e maturidade de governança | 7, 8 |

## Cases reais para inspiração

- **Samsung, 2023**: relatos públicos indicaram envio de código e dados internos para ferramentas generativas, reforçando a necessidade de políticas de dados e DLP.
- **OpenAI ChatGPT, 2023**: incidente de exposição de histórico de conversas e dados de cobrança de alguns usuários mostrou a importância de isolamento, observabilidade e resposta a incidentes.
- **Air Canada, 2024**: decisão pública responsabilizou a empresa por informação incorreta fornecida por chatbot, reforçando governança de respostas e revisão jurídica.
- **Serviços financeiros**: bancos como Morgan Stanley e JPMorgan exploram IA generativa com controles internos, governança, revisão humana e políticas de uso para reduzir risco operacional.
