# Aula 03 — Proteção de Dados e Isolamento de Ferramentas

> **Status:** 🏗️ Estrutura criada — conteúdo prático a ser adicionado.

## Objetivo
Proteger dados sensíveis (PII) e isolar as ferramentas invocadas pelo LLM, aplicando *least privilege* e Zero Trust.

## Tecnologias
- **Microsoft Presidio** (Analyzer + Anonymizer; recognizers BR: CPF/CNPJ/RG/CEP)
- **Model Context Protocol (MCP)** para isolamento de ferramentas
- **Azure Key Vault** (tokenização reversível), **Microsoft Entra ID**, Private Endpoints
- **Confidential Computing** (Intel SGX / AMD SEV-SNP)

## Caso de negócio
Atendimento do **Aurora Assist** sem exposição de dado bruto do cliente.

## Navegação
- ⬅️ [Voltar ao README principal](../README.md) · Anterior: [Aula 02](../02_guardrails_e_politicas/README.md)
- 📖 [Arquitetura](../docs/architecture/overview.md) · 💼 [Business Cases](../docs/business/README.md)
- ➡️ Próxima: [Aula 04 — Testes de Segurança e Auditoria](../04_testes_de_seguranca_e_auditoria/README.md)
