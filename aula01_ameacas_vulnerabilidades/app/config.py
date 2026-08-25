"""Configuração da aplicação (12-factor: tudo por variável de ambiente).

Lê credenciais/endpoints do ambiente (Doc 04, seção 6: 'nunca inclusão de
credenciais no prompt'; segredos ficam fora do código e do git).
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Variáveis de ambiente da Aula 01 (ver .env.example)."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Backend: "ollama" (offline, padrão) | "groq" | "azure" | "stub" (determinístico, sem rede)
    llm_backend: str = "ollama"

    # Ollama
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:8b"

    # Groq (API compatível com OpenAI; requer chave)
    groq_api_key: str | None = None
    groq_base_url: str = "https://api.groq.com/openai/v1"
    groq_model: str = "openai/gpt-oss-20b"

    # Azure OpenAI (opcional)
    azure_openai_endpoint: str | None = None
    azure_openai_api_key: str | None = None
    azure_openai_api_version: str = "2024-06-01"
    azure_openai_deployment: str | None = None

    # Diversos
    llm_timeout: float = 60.0
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    """Instância única de Settings (cacheada)."""
    return Settings()
