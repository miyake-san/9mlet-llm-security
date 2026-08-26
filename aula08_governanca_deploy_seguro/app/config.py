"""Configuração da aplicação (12-factor: tudo por variável de ambiente).

O *flag* de mitigação ``AGENT_GUARDRAILS_ENABLED`` começa **desligado** de
propósito (padrão pedagógico das Aulas 04-07): o agente ingênuo deixa jailbreaks
passarem, alucina e vaza PII — problemas mensuráveis que o **deploy gate** (Doc 04,
§6) reprova. Ligá-lo ativa os guardrails (Aula 02), o *grounding* estrito e a
redação de PII, permitindo a promoção segura. Ver ``.env.example``.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Variáveis de ambiente da Aula 08 (ver .env.example)."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Backend: "groq" (padrão) | "ollama" | "azure" | "stub" (sem rede)
    llm_backend: str = "groq"

    # Ollama (execução local, sem nuvem)
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2:3b"

    # Groq (API compatível com OpenAI)
    groq_api_key: str | None = None
    groq_base_url: str = "https://api.groq.com/openai/v1"
    groq_model: str = "openai/gpt-oss-20b"
    groq_min_interval_seconds: float = 1.0

    # Azure OpenAI / Azure AI Foundry (opcional)
    azure_openai_endpoint: str | None = None
    azure_openai_api_key: str | None = None
    azure_openai_api_version: str = "2024-06-01"
    azure_openai_deployment: str | None = None

    # Versão candidata do agente (proveniência nos relatórios e no AIBOM)
    model_version: str = "aurora-assist-3.0.0"

    # MITIGAÇÃO (Doc 04, §9): guardrails da Aula 02 + grounding + redação de PII.
    # false = agente ingênuo (jailbreak escapa, alucina, PII vaza) -> deploy gate REPROVA.
    # true  = agente endurecido (guardrails ligados) -> deploy gate APROVA.
    agent_guardrails_enabled: bool = False

    # Isolamento de ferramentas MCP (Aula 03)
    mcp_subject: str = "aurora-agent"
    mcp_enabled: bool = True

    # RAG (retriever offline in-memory; qdrant é o caminho de produção)
    rag_top_k: int = 3

    # Deployment seguro (Doc 04, §6)
    deployment_strategy: str = "canary"
    canary_percent: float = 5.0

    # SLO / deploy gate (Doc 04, §§6-7)
    slo_path: str = "configs/slo.yaml"
    thresholds_path: str = "configs/thresholds.yaml"

    # Observabilidade (Doc 04, §§6,9)
    cost_input_per_1k: float = 0.005
    cost_output_per_1k: float = 0.015
    langfuse_enabled: bool = False
    langfuse_host: str = "http://localhost:3000"

    # deploy_gates / eval ao vivo
    target_api_url: str = "http://agent-app:8000"
    report_dir: str = "reports"

    # Diversos
    llm_timeout: float = 60.0
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    """Instância única de Settings (cacheada)."""
    return Settings()
