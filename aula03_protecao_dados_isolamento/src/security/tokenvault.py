"""Cofre de tokens e anonimização reversível (Aula 03 — Doc 04, §7).

Materializa o **Snippet 2** do Documento 04: cada PII é substituída por um
**token determinístico** (o mesmo valor gera sempre o mesmo token, preservando a
coerência para o LLM) e o mapeamento token↔valor real é guardado em um **cofre
seguro**. O LLM processa apenas o token; só um serviço autorizado, FORA do
alcance do modelo, realiza a reversão (*reidratação*).

O token é derivado por **HMAC-SHA256** truncado: não vaza o dado (não é
reversível por adivinhação) e é estável (determinístico). Três backends:

- ``memory``  — dicionário em processo (padrão de testes/CI).
- ``file``    — JSON local (lab persistente; simula o cofre — dados SINTÉTICOS).
- ``azure``   — **Azure Key Vault** com Managed Identity (grupo ``azure``) — §2/§7.

Referência:
    Microsoft (2024b). Presidio — reversible anonymization / token vault.
    Doc 04, §7 (anonimização reversível) e §12 (Customer-Managed Keys).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Protocol

from src.security.schemas import PIIEntity


def make_token(
    entity: PIIEntity | str,
    value: str,
    secret: str,
    digest_len: int = 8,
    token_format: str = "[{entity}_TOKEN_{digest}]",
) -> str:
    """Gera um token DETERMINÍSTICO e não reversível por adivinhação (HMAC).

    Implementa a estratégia de token determinístico da seção 'Saiba Mais' (§7):
    o CPF ``123.456.789-00`` vira, por exemplo, ``[BR_CPF_TOKEN_8a3f1c2d]``.
    """
    entity_name = entity.value if isinstance(entity, PIIEntity) else str(entity)
    mac = hmac.new(secret.encode("utf-8"), f"{entity_name}:{value}".encode(), hashlib.sha256)
    digest = mac.hexdigest()[:digest_len]
    return token_format.format(entity=entity_name, digest=digest)


class TokenVault(Protocol):
    """Contrato do cofre: tokeniza (determinístico) e reverte (se autorizado)."""

    def tokenize(self, entity: PIIEntity | str, value: str) -> str: ...

    def resolve(self, token: str) -> str | None: ...


class _BaseVault:
    """Lógica comum: geração determinística de token a partir do segredo/formato."""

    def __init__(
        self,
        secret: str | None = None,
        digest_len: int = 8,
        token_format: str = "[{entity}_TOKEN_{digest}]",
    ) -> None:
        self.secret = secret or os.getenv("TOKEN_HMAC_SECRET", "dev-secret-change-me")
        self.digest_len = digest_len
        self.token_format = token_format

    def _token(self, entity: PIIEntity | str, value: str) -> str:
        return make_token(entity, value, self.secret, self.digest_len, self.token_format)


class InMemoryTokenVault(_BaseVault):
    """Cofre em memória (padrão de testes/CI; nada persiste)."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._map: dict[str, str] = {}

    def tokenize(self, entity: PIIEntity | str, value: str) -> str:
        token = self._token(entity, value)
        self._map[token] = value
        return token

    def resolve(self, token: str) -> str | None:
        return self._map.get(token)


class FileTokenVault(_BaseVault):
    """Cofre em arquivo JSON (lab persistente).

    ⚠️ Simulação didática: em produção o mapa fica no **Azure Key Vault** com
    **Customer-Managed Keys** (Doc 04, §12). Aqui os dados são SINTÉTICOS e o
    arquivo vive em ``reports/`` (gitignored, fora da imagem).
    """

    def __init__(self, path: str | Path | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.path = Path(path or os.getenv("TOKEN_VAULT_PATH", "reports/token_vault.json"))
        self._map: dict[str, str] = {}
        if self.path.exists():
            self._map = json.loads(self.path.read_text(encoding="utf-8"))

    def _flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._map, ensure_ascii=False), encoding="utf-8")

    def tokenize(self, entity: PIIEntity | str, value: str) -> str:
        token = self._token(entity, value)
        if self._map.get(token) != value:
            self._map[token] = value
            self._flush()
        return token

    def resolve(self, token: str) -> str | None:
        return self._map.get(token)


class AzureKeyVaultTokenVault(_BaseVault):
    """Cofre no **Azure Key Vault** (opcional; grupo ``azure``).

    Usa ``DefaultAzureCredential`` (Managed Identity / Entra ID — Doc 04, §2):
    sem chaves estáticas no código. O segredo é nomeado pelo *digest* do token.
    """

    def __init__(self, vault_url: str | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        from azure.identity import DefaultAzureCredential  # import tardio
        from azure.keyvault.secrets import SecretClient

        url = vault_url or os.environ["AZURE_KEY_VAULT_URL"]
        self._client = SecretClient(vault_url=url, credential=DefaultAzureCredential())

    @staticmethod
    def _secret_name(token: str) -> str:
        # Nomes de segredo aceitam apenas [0-9a-zA-Z-]; usamos o hash do token.
        return "tok-" + hashlib.sha256(token.encode()).hexdigest()[:32]

    def tokenize(self, entity: PIIEntity | str, value: str) -> str:
        token = self._token(entity, value)
        self._client.set_secret(self._secret_name(token), value)
        return token

    def resolve(self, token: str) -> str | None:
        try:
            return self._client.get_secret(self._secret_name(token)).value
        except Exception:  # noqa: BLE001 — segredo ausente/erro de acesso => não reidrata
            return None


def get_token_vault(backend: str | None = None, **kwargs) -> TokenVault:
    """Fábrica de cofre a partir de ``TOKEN_VAULT_BACKEND`` (ou do argumento)."""
    name = (backend or os.getenv("TOKEN_VAULT_BACKEND", "memory")).lower()
    if name == "file":
        return FileTokenVault(**kwargs)
    if name == "azure":
        return AzureKeyVaultTokenVault(**kwargs)
    return InMemoryTokenVault(**kwargs)
