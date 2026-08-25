"""Biblioteca reutilizável de segurança — Aula 03 (Proteção de dados / MCP isolado).

Reúne os controles do pipeline **Zero Trust** do Documento 04 (Stafford, 2020;
Anthropic, 2024): detecção/anonimização de PII BR (§5-6), anonimização reversível
com cofre de tokens (§7), isolamento de ferramentas por *capability tokens* (§9-10)
e trilha de auditoria (§12). Tudo *offline-first* e determinístico por padrão, com
adaptadores de PRODUÇÃO (Presidio, Azure Key Vault, MCP SDK) opcionais.
"""

from __future__ import annotations

from .anonymizer import (
    ReversibleAnonymizer,
    hash_value,
    mask_value,
    operators_from_config,
)
from .mcp_isolation import (
    AuditTrail,
    ToolAuthorizer,
    ToolCatalog,
    issue_capability,
    sign_payload,
    verify_signature,
)
from .metrics import ConfusionMatrix, detection_confusion
from .pii import detect_pii, is_valid_cnpj, is_valid_cpf
from .presidio_bridge import (
    Analyzer,
    DeterministicAnalyzer,
    PresidioHttpAnalyzer,
    PresidioPythonAnalyzer,
    get_analyzer,
)
from .schemas import (
    AnonymizationResult,
    AuditEntry,
    CapabilityToken,
    Operator,
    PIIEntity,
    PIIMatch,
    ToolCallResult,
    ToolCapability,
)
from .tokenvault import (
    AzureKeyVaultTokenVault,
    FileTokenVault,
    InMemoryTokenVault,
    TokenVault,
    get_token_vault,
    make_token,
)

__all__ = [
    # schemas
    "AnonymizationResult",
    "AuditEntry",
    "CapabilityToken",
    "Operator",
    "PIIEntity",
    "PIIMatch",
    "ToolCallResult",
    "ToolCapability",
    # pii detection
    "detect_pii",
    "is_valid_cpf",
    "is_valid_cnpj",
    # presidio bridge
    "Analyzer",
    "DeterministicAnalyzer",
    "PresidioHttpAnalyzer",
    "PresidioPythonAnalyzer",
    "get_analyzer",
    # anonymization
    "ReversibleAnonymizer",
    "mask_value",
    "hash_value",
    "operators_from_config",
    # token vault
    "TokenVault",
    "InMemoryTokenVault",
    "FileTokenVault",
    "AzureKeyVaultTokenVault",
    "get_token_vault",
    "make_token",
    # mcp isolation
    "ToolCatalog",
    "ToolAuthorizer",
    "AuditTrail",
    "issue_capability",
    "verify_signature",
    "sign_payload",
    # metrics
    "ConfusionMatrix",
    "detection_confusion",
]
