"""Catálogo OWASP Top 10 for LLM Applications (2025).

Implementa a linguagem padronizada de risco discutida na seção 'Saiba Mais'
(item 3) do Documento 04. Transforma incidentes dispersos em classes
comparáveis (LLM01…LLM10), usadas para rotular ataques, priorizar backlog
e comunicar risco executivo.

Referência:
    OWASP Foundation (2025). Top 10 for LLM Applications, v2025.
    Disponível em: https://genai.owasp.org/
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OwaspRisk:
    """Uma classe de risco do OWASP Top 10 for LLM (2025).

    Attributes:
        id: identificador canônico (ex.: "LLM01").
        name: título oficial em inglês.
        name_pt: título em português.
        description: resumo do risco no contexto do Aurora Assist.
        doc04_section: seção do Documento 04 que discute o risco.
    """

    id: str
    name: str
    name_pt: str
    description: str
    doc04_section: str


# Catálogo canônico. A ordem segue a numeração oficial LLM01…LLM10.
OWASP_LLM_TOP10: dict[str, OwaspRisk] = {
    "LLM01": OwaspRisk(
        "LLM01",
        "Prompt Injection",
        "Injeção de Prompt",
        "Entrada (direta) ou conteúdo recuperado (indireta) altera o comportamento "
        "pretendido do modelo, quebrando a hierarquia de autoridade s ≫ u ≥ d.",
        "4",
    ),
    "LLM02": OwaspRisk(
        "LLM02",
        "Insecure Output Handling",
        "Tratamento Inseguro de Saída",
        "Saída do LLM é consumida sem validação (ex.: HTML/SQL/comando), propagando "
        "o ataque para sistemas a jusante.",
        "3",
    ),
    "LLM03": OwaspRisk(
        "LLM03",
        "Training Data Poisoning",
        "Envenenamento de Dados de Treino",
        "Adversário influencia dados de treino/ajuste/RAG para plantar backdoors ou "
        "vieses (BadNets — Gu et al., 2017).",
        "7",
    ),
    "LLM04": OwaspRisk(
        "LLM04",
        "Model Denial of Service",
        "Negação de Serviço do Modelo",
        "Prompts longos/caros esgotam recursos e custo de inferência, degradando a "
        "disponibilidade do Aurora Assist.",
        "2",
    ),
    "LLM05": OwaspRisk(
        "LLM05",
        "Supply Chain",
        "Cadeia de Fornecimento",
        "Bibliotecas, modelos, datasets, plugins e imagens de contêiner de origem "
        "incerta entram no ciclo sem verificação de procedência.",
        "7",
    ),
    "LLM06": OwaspRisk(
        "LLM06",
        "Sensitive Information Disclosure",
        "Divulgação de Informação Sensível",
        "Vazamento de PII, segredos de configuração/system prompt ou dados "
        "memorizados no treino (Carlini et al., 2021).",
        "6",
    ),
    "LLM07": OwaspRisk(
        "LLM07",
        "Insecure Plugin/Tool Design",
        "Design Inseguro de Plugin/Ferramenta",
        "Ferramentas aceitam parâmetros sem validação, misturam escopos ou executam "
        "ações irreversíveis sem confirmação.",
        "8",
    ),
    "LLM08": OwaspRisk(
        "LLM08",
        "Excessive Agency",
        "Agência Excessiva",
        "O modelo recebe autonomia acima do necessário; padrão 'confused deputy' usa "
        "autoridade legítima em benefício do atacante.",
        "8",
    ),
    "LLM09": OwaspRisk(
        "LLM09",
        "Overreliance",
        "Excesso de Confiança",
        "Usuários confiam cegamente na saída do modelo sem validação humana, "
        "amplificando erros e alucinações.",
        "3",
    ),
    "LLM10": OwaspRisk(
        "LLM10",
        "Model Theft",
        "Roubo de Modelo",
        "Cópia, extração ou fingerprinting indevidos do modelo, de pesos ou de "
        "ativos próprios (system prompts, few-shot, embeddings).",
        "7",
    ),
}


def get_risk(risk_id: str) -> OwaspRisk:
    """Retorna a classe OWASP pelo id canônico (ex.: 'LLM01').

    Raises:
        KeyError: se o id não existir no catálogo 2025.
    """
    key = risk_id.strip().upper()
    if key not in OWASP_LLM_TOP10:
        raise KeyError(f"Classe OWASP desconhecida: {risk_id!r}. Válidas: {list(OWASP_LLM_TOP10)}")
    return OWASP_LLM_TOP10[key]
