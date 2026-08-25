# 📋 Conformidade — Rastreabilidade Normativa

Esta pasta mapeia **requisitos regulatórios** (LGPD, GDPR, EU AI Act) e **frameworks de governança** (NIST AI RMF, ISO/IEC 42001) para as **aulas** da disciplina e os **controles técnicos** implementados no repositório, usando o **Banco Aurora / Aurora Assist** como caso condutor.

O objetivo é demonstrar que segurança e conformidade não são etapas finais, mas **requisitos rastreáveis** que orientam arquitetura, código e operação — do *threat modeling* à resposta a incidentes.

## Conteúdo

- [`mapa-lgpd-gdpr-euaiact.md`](mapa-lgpd-gdpr-euaiact.md) — tabela de rastreabilidade **cláusula normativa ↔ aula ↔ controle técnico**.

## Como usar

1. Parta de um requisito regulatório (ex.: *LGPD art. 6º — minimização*).
2. Localize a **aula** que o operacionaliza e o **controle técnico** correspondente no repositório.
3. Use a evidência (código, ADR, relatório de red team, dashboard de observabilidade) como artefato de auditoria.

> ⚠️ Este material é **educacional** e não constitui aconselhamento jurídico. A adequação regulatória real depende de análise do encarregado (DPO) e do jurídico da organização.

## Referências normativas

- **LGPD** — Lei nº 13.709/2018 (Brasil).
- **GDPR** — Regulation (EU) 2016/679.
- **EU AI Act** — Regulation (EU) 2024/1689.
- **NIST AI RMF 1.0** — AI Risk Management Framework.
- **ISO/IEC 42001:2023** — Artificial Intelligence Management System (AIMS).
