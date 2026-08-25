"""Configuração da aplicação (12-factor: tudo por variável de ambiente).

Lê credenciais/endpoints do ambiente (Doc 04, seção 12: segredos e chaves ficam
fora do código e do git; a trilha de auditoria registra apenas metadados). Ver
`.env.example` para a lista completa.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Variáveis de ambiente da Aula 04 (ver .env.example)."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Backend: "groq" (padrão) | "ollama" | "azure" | "stub" (sem rede)
    llm_backend: str = "groq"

    # Ollama
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:8b"

    # Groq (API compatível com OpenAI)
    groq_api_key: str | None = None
    groq_base_url: str = "https://api.groq.com/openai/v1"
    groq_model: str = "openai/gpt-oss-20b"
    groq_min_interval_seconds: float = 1.0

    # Azure OpenAI (opcional)
    azure_openai_endpoint: str | None = None
    azure_openai_api_key: str | None = None
    azure_openai_api_version: str = "2024-06-01"
    azure_openai_deployment: str | None = None

    # Aurora Assist DEFENDIDO (target-api)
    model_version: str = "aurora-assist-2.4.0"
    guardrail_enabled: bool = True
    # Mitigação: normalizar ofuscação (leet/base64) antes de filtrar (Doc 04, sec. 13).
    guardrail_normalize: bool = False
    # Mitigação: avaliar a conversa inteira (defesa contra crescendo — Doc 04, sec. 8).
    guardrail_conversation: bool = False

    # Trilha de auditoria (audit-log)
    audit_enabled: bool = True
    audit_log_url: str = "http://audit-log:8091"
    audit_chain_path: str = "/tmp/audit_chain.jsonl"

    # OpenSearch (SIEM)
    opensearch_url: str = "http://opensearch:9200"
    opensearch_index: str = "aurora-audit"

    # Diversos
    llm_timeout: float = 60.0
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    """Instância única de Settings (cacheada)."""
    return Settings()
