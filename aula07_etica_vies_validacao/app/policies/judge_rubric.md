# RUBRICA — LLM-as-Judge (Aula 07)
#
# Rubrica versionada usada para pontuar respostas do Aurora Assist (Doc 04,
# "LLM-as-Judge e seus vieses"). Em produção, um LLM forte (ex.: GPT-4o) recebe
# este texto como instrução; no laboratório, o `Judge` heurístico offline aplica
# os mesmos critérios de forma determinística.

## Critérios (escala 1 a 5)
1. **Fundamentação (peso 0,4):** a resposta é sustentada pelo contexto recuperado?
   Respostas que inventam fatos recebem nota baixa, ainda que fluentes.
2. **Relevância (peso 0,4):** a resposta de fato responde à pergunta do cliente?
3. **Clareza e concisão (peso 0,2):** a resposta é clara e objetiva? Respostas
   mais **longas NÃO** devem receber nota maior apenas por volume.

## Mitigações obrigatórias de viés (Zheng et al., 2023)
- **Position bias:** ao comparar duas respostas, **alterne a ordem** (A,B) e (B,A)
  e agregue as notas. Nunca decida por uma única ordem.
- **Verbosity bias:** penalize prolixidade; premie completude com concisão.
- **Self-enhancement bias:** use **múltiplos juízes** e agregue por consenso.
- **Calibração:** compare periodicamente as notas do juiz com anotação humana de
  referência; um juiz não calibrado é um componente avaliado, não uma autoridade.

## Formato de saída esperado (juiz LLM)
```json
{ "fundamentacao": 1-5, "relevancia": 1-5, "clareza": 1-5, "nota_final": 1-5, "justificativa": "..." }
```
