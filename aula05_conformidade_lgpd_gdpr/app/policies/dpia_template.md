# Template de DPIA / RIPD — Sistemas de IA (Banco Aurora)

> Data Protection Impact Assessment (GDPR art. 35) / Relatório de Impacto à
> Proteção de Dados (LGPD art. 38). Template estruturado citado no Doc 04, §8.
> O gerador `app/dpia.py` preenche as seções 3-5 automaticamente a partir de
> `configs/eu_ai_act_risk.yaml` e `configs/thresholds.yaml`.

## 1. Identificação do tratamento
- **Sistema:** Aurora Assist
- **Controlador:** Banco Aurora (decide sobre o tratamento — Doc 04, §3)
- **Operador(es):** provedor de nuvem / provedor do modelo fundacional
- **Encarregado (DPO):** _____________________
- **Finalidades:** informar sobre produtos/serviços; consultar saldo (autenticado)

## 2. Necessidade e proporcionalidade (LGPD art. 6; GDPR art. 5)
- Bases legais por operação: ver `configs/treatment_policies.yaml`.
- Minimização de dados aplicada no ingresso do prompt (Presidio / detector BR).
- Justificativa da proporcionalidade: _____________________

## 3. Classificação de risco (EU AI Act) — *preenchida pelo gerador*
- Nível de risco: `{{risk_tier}}`
- Obrigações herdadas: `{{obligations}}`

## 4. Cenários de risco e cálculo R = Σ Pj·Ij — *preenchida pelo gerador*
- Risco agregado normalizado: `{{aggregate_risk}}`
- Decisão: `{{decision}}` (accept | mitigate | high_risk_review)
- Tabela de cenários (probabilidade × impacto × mitigação): `{{scenarios}}`

## 5. Riscos residuais e limites técnicos — *preenchida pelo gerador*
- Direito à explicação vs caixa-preta (Doc 04, §9).
- Machine unlearning vs conhecimento de fine-tuning (Doc 04, §10).
- Transferência internacional / residência de dados (Doc 04, §11).

## 6. Salvaguardas (Privacy by Design — GDPR art. 25)
- Guardrails de entrada/saída (Aula 2).
- Anonimização/minimização com Presidio + Customer-Managed Keys (Aula 3).
- Arquitetura Zero Trust e red teaming (Aulas 3-4).
- Registro de tratamento imutável (WORM) — art. 37 (Aula 4-5).

## 7. Parecer do DPO
- [ ] Aprovado
- [ ] Aprovado com ressalvas
- [ ] Reprovado — mitigações obrigatórias antes do lançamento

Assinatura do DPO: _____________________   Data: ___/___/______
