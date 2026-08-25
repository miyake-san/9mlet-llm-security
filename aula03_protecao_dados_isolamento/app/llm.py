"""Abstração de backend de LLM — ollama (default) | azure | stub (Aula 03).

Segue a diretriz *offline-first* do repositório: por padrão o Aurora Assist fala
com um LLM local via **Ollama**, sem nuvem. O backend **azure** (Azure OpenAI /
Azure AI Foundry) é opcional e lê credenciais SEMPRE de variáveis de ambiente
(nunca *hard-coded* — Doc 04, §2: identidade primeiro, sem chaves estáticas). O
backend **stub** é determinístico e sem rede (testes/CI e demos).

⚠️ Nesta aula, por Zero Trust, o LLM recebe **apenas tokens** — jamais o dado
bruto do cliente (Doc 04, §7). A anonimização ocorre ANTES desta chamada.

Referência:
    Doc 04, §2 (Managed Identities / Entra ID) e §7 (LLM vê só tokens).
"""

from __future__ import annotations

import os
from typing import Protocol

import httpx

_SYSTEM_PROMPT = (
    "Você é o Aurora Assist, assistente virtual do Banco Aurora. "
    "Responda de forma objetiva e cordial APENAS sobre produtos e serviços do "
    "Banco Aurora. Alguns valores no texto podem estar TOKENIZADOS (por exemplo "
    "[BR_CPF_TOKEN_ab12cd34] ou [SALDO_TOKEN_...]) para proteger dados do cliente: "
    "trate cada token como o valor que ele representa, NUNCA tente adivinhar o valor "
    "real e mantenha o token inalterado na resposta."
)


class LLMBackend(Protocol):
    """Contrato mínimo de um backend de geração de texto."""

    def generate(self, prompt: str, system: str | None = None) -> str: ...


class StubBackend:
    """Backend determinístico e offline (testes/CI/demos).

    Não chama rede e preserva tokens: ecoa uma resposta bancária canônica,
    mantendo eventuais tokens presentes no prompt (para demonstrar o egress).
    """

    def generate(self, prompt: str, system: str | None = None) -> str:
        return (
            "Olá! Sou o Aurora Assist. Recebi sua solicitação e vou ajudar com "
            "segurança, sem expor dados sensíveis. Como posso continuar?"
        )


class OllamaBackend:
    """Backend local via Ollama (offline-first, padrão do lab)."""

    def __init__(
        self,
        base_url: str | None = None,
        model: str | None = None,
        timeout: float | None = None,
    ) -> None:
        self.base_url = (
            base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        ).rstrip("/")
        self.model = model or os.getenv("OLLAMA_MODEL", "llama3.1:8b")
        self.timeout = timeout or float(os.getenv("LLM_TIMEOUT", "60"))

    def generate(self, prompt: str, system: str | None = None) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system or _SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
        }
        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(f"{self.base_url}/api/chat", json=payload)
            response.raise_for_status()
            return response.json()["message"]["content"].strip()


class AzureBackend:
    """Backend opcional Azure OpenAI / Azure AI Foundry (grupo ``azure``)."""

    def __init__(self) -> None:
        from openai import AzureOpenAI  # import tardio

        self.deployment = os.environ["AZURE_OPENAI_DEPLOYMENT"]
        self.timeout = float(os.getenv("LLM_TIMEOUT", "60"))
        self._client = AzureOpenAI(
            azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
            api_key=os.environ["AZURE_OPENAI_API_KEY"],
            api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-06-01"),
        )

    def generate(self, prompt: str, system: str | None = None) -> str:
        response = self._client.chat.completions.create(
            model=self.deployment,
            messages=[
                {"role": "system", "content": system or _SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            timeout=self.timeout,
        )
        return (response.choices[0].message.content or "").strip()


def get_backend(name: str | None = None) -> LLMBackend:
    """Fábrica de backend a partir de ``LLM_BACKEND`` (ou do argumento)."""
    backend = (name or os.getenv("LLM_BACKEND", "ollama")).lower()
    if backend == "stub":
        return StubBackend()
    if backend == "azure":
        return AzureBackend()
    return OllamaBackend()
