"""Configuração da aplicação (12-factor: tudo por variável de ambiente).

Lê endpoints/flags do ambiente. As duas flags de **mitigação** (fairness e
groundedness) começam desligadas de propósito: assim o Aurora Assist ingênuo
exibe problemas mensuráveis (disparidade e alucinação), e o Lab demonstra a
redução de risco ao ativá-las — o mesmo padrão pedagógico das Aulas 04-06.
Ver ``.env.example`` para a lista completa.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Variáveis de ambiente da Aula 07 (ver .env.example)."""

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

    # Aurora Assist (RAG) avaliado
    model_version: str = "aurora-assist-2.5.0"

    # Mitigação de FAIRNESS (Doc 04, "Viés específico de LLMs"): quando False, o
    # grupo protegido influencia decisão/recomendação -> disparidade mensurável.
    fairness_mitigation: bool = False

    # Mitigação de GROUNDEDNESS (Doc 04, "RAGAS"): quando False, o assistente
    # alucina se o fato não está no contexto -> faithfulness baixa.
    rag_strict_grounding: bool = False
    rag_top_k: int = 3

    # LLM-as-Judge (Doc 04, "LLM-as-Judge e seus vieses")
    judge_debias_position: bool = True
    judge_ensemble_size: int = 3

    # Quality gate
    thresholds_path: str = "configs/thresholds.yaml"

    # eval-runner
    target_api_url: str = "http://target-api:8000"
    report_dir: str = "reports"

    # Diversos
    llm_timeout: float = 60.0
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    """Instância única de Settings (cacheada)."""
    return Settings()
