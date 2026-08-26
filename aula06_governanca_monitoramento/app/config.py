"""Configuração da aplicação (12-factor: tudo por variável de ambiente).

Lê endpoints/credenciais do ambiente (Doc 04, §Obs. — segredos ficam fora do
código; a telemetria não pode virar risco). Ver `.env.example` para a lista
completa das variáveis desta aula (observabilidade, custo, cache e drift).
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Variáveis de ambiente da Aula 06 (ver .env.example)."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Backend: "groq" (padrão) | "ollama" | "azure" | "stub" (sem rede)
    llm_backend: str = "groq"

    # Ollama
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2:3b"

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

    # Aurora Assist v2.6 (app OTel-instrumentado)
    model_version: str = "aurora-assist-2.6.0"
    # Maturidade LLMOps alvo: 0 manual | 1 CI/CD | 2 automação governada (Doc 04).
    llmops_maturity_level: int = 1
    # Minimização de PII antes de logar telemetria (Doc 04, §Obs. — privacidade).
    minimize_telemetry_pii: bool = True

    # Observabilidade: OpenTelemetry (convenções gen_ai.*)
    otel_service_name: str = "aurora-assist"
    otel_traces_enabled: bool = True
    otel_exporter_otlp_endpoint: str | None = None

    # Langfuse (tracing por step; opcional)
    langfuse_enabled: bool = False
    langfuse_host: str = "http://langfuse:3000"
    langfuse_public_key: str | None = None
    langfuse_secret_key: str | None = None

    # Modelo de custo / token economics
    cost_input_per_1k: float = 0.005
    cost_output_per_1k: float = 0.015
    model_routing_enabled: bool = True
    semantic_cache_enabled: bool = True
    semantic_cache_threshold: float = 0.92

    # Detecção de drift (janelas de tráfego)
    drift_reference_path: str = "data/traffic/reference.jsonl"
    drift_production_path: str = "data/traffic/production.jsonl"

    # Coletor de spans em arquivo (tmpfs no contêiner read-only)
    trace_store_path: str = "/tmp/traces.jsonl"

    # Diversos
    llm_timeout: float = 60.0
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    """Instância única de Settings (cacheada)."""
    return Settings()
