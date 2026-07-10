# Documentação de Negócio — Segurança de LLMs

> Repositório: [9mlet-llm-security](https://github.com/miyake-san/9mlet-llm-security) · Disciplina: **Segurança, Conformidade e Guardrails para LLMs**

Esta área traduz os conceitos técnicos do repositório em valor executivo, usando o fio condutor do **Banco Aurora** e do assistente **Aurora Assist**. O objetivo é demonstrar como práticas de segurança para LLMs reduzem perdas operacionais, exposição regulatória e risco reputacional, ao mesmo tempo em que aceleram adoção responsável de IA generativa.

## Valor de Negócio

LLMs em produção criam uma nova superfície de risco: prompt injection, vazamento de PII, uso indevido de ferramentas, alucinações com impacto financeiro e vieses decisórios. Em setores regulados, o custo de não tratar esses riscos inclui multas LGPD/GDPR, retrabalho jurídico, perda de confiança e bloqueios de auditoria.

A disciplina posiciona segurança como **habilitador de ROI**:

| Alavanca | Impacto esperado | Métrica executiva |
|---|---:|---|
| Redução de incidentes de dados | -40% a -70% | Incidentes PII/mês, severidade média |
| Automação segura de atendimento | +20% a +35% | Deflexão no contact center, FCR |
| Red teaming contínuo | -50% em falhas críticas antes de produção | Taxa de jailbreak e prompt injection |
| Governança e evidências | -30% no esforço de auditoria | Horas por evidência, achados por ciclo |

## Índice

### Casos de uso
- [Casos de uso de negócio](./use-cases.md)

### Business cases
- [Business Case: Aurora Assist — Assistente Bancário Seguro](./business-case-aurora-assist.md)
- [Business Case: Copiloto Clínico com Conformidade LGPD/GDPR](./business-case-healthcare-compliance.md)
- [Business Case: Atendimento ao Cliente com Guardrails e Red Teaming Contínuo](./business-case-customer-service-redteaming.md)

### Diagramas de processo
- [Secure LLMOps Lifecycle](./process-diagrams/business-process.md)
- [Jornada do Engenheiro de ML/Segurança](./process-diagrams/user-journey.md)

## Referência técnica

- [Voltar ao README principal](../../README.md)
