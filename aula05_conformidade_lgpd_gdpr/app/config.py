"""Configuração da aplicação (12-factor: tudo por variável de ambiente).

Lê endpoints/credenciais do ambiente (Doc 04, §11-12: segredos ficam fora do
código e do git; a residência de dados é uma decisão de conformidade). Ver
`.env.example` para a lista completa.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Variáveis de ambiente da Aula 05 (ver .env.example)."""

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

    # Aurora Assist COMPLIANT (rag-api)
    model_version: str = "aurora-assist-2.5.0"
    # EU AI Act: "limited" (informar) | "high" (decidir crédito) — Doc 04, §6-7.
    ai_act_risk_tier: str = "limited"
    ai_disclosure_enabled: bool = True
    refuse_automated_credit_decision: bool = True
    minimize_pii: bool = True
    enforce_consent: bool = True

    # Residência de dados (Schrems II — Doc 04, §11)
    data_residency_region: str = "brazil-south"

    # consent-service
    consent_service_url: str = "http://consent-service:8010"
    consent_store: str = "memory"  # memory | file | postgres
    consent_store_path: str = "/tmp/consent_store.jsonl"
    consent_terms_version: str = "2026-06-v3"

    # Postgres (store do consent-service)
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_db: str = "aurora_consent"
    postgres_user: str = "aurora"
    postgres_password: str = "aurora-dev-only"

    # Registro de tratamento (WORM) — art. 37 / GDPR art. 30
    treatment_log_path: str = "/tmp/treatment_chain.jsonl"

    # Vector store (direito ao esquecimento)
    vector_store: str = "memory"  # memory | qdrant
    qdrant_url: str = "http://qdrant:6333"
    qdrant_collection: str = "aurora_rag"

    # Microsoft Presidio (minimização; opcional — cai no detector BR se ausente)
    presidio_analyzer_url: str | None = None
    presidio_anonymizer_url: str | None = None

    # Diversos
    llm_timeout: float = 60.0
    log_level: str = "INFO"

    @property
    def postgres_dsn(self) -> str:
        """DSN do PostgreSQL para o consent-service (store versionado)."""
        return (
            f"host={self.postgres_host} port={self.postgres_port} "
            f"dbname={self.postgres_db} user={self.postgres_user} "
            f"password={self.postgres_password}"
        )


@lru_cache
def get_settings() -> Settings:
    """Instância única de Settings (cacheada)."""
    return Settings()
