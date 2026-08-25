"""AIBOM (AI Bill of Materials) no padrão CycloneDX ML-BOM (Doc 04, §8).

Gera o inventário completo dos componentes do Aurora Assist — **modelo base**,
**datasets**, **fine-tunes** e **dependências** — respondendo "do que exatamente
esse sistema é feito?" (Doc 04, §8). Materializa o **Snippet 1** do Documento 04
(``cyclonedx-py``) de forma pura, sem exigir a ferramenta instalada, para manter o
lab *offline-first*. Em CI/CD, o container ``aibom-gen`` pode usar o
``cyclonedx-python-lib`` real (grupo opcional ``security``).

O AIBOM sustenta a gestão de risco de *supply chain* (LLM05 da Aula 1): quando uma
vulnerabilidade aparece em um componente, o inventário responde instantaneamente
se o Aurora Assist é afetado.

Referência:
    OWASP Foundation; CycloneDX (2026). ML-BOM specification (https://cyclonedx.org/).
    SPDX 3.0 AI Profile. · Doc 04, §8 (AIBOM) e §1 (LLM05 supply chain).
"""

from __future__ import annotations

import hashlib
import json
import tomllib
import uuid
from datetime import UTC, datetime
from pathlib import Path

_SPEC_VERSION = "1.6"
_BOM_FORMAT = "CycloneDX"

# Componentes de MODELO/DADOS do Aurora Assist (proveniência declarada; sintética).
_MODEL_COMPONENTS = (
    {
        "type": "machine-learning-model",
        "name": "llama3.1",
        "version": "8b",
        "publisher": "Meta",
        "description": "Modelo base servido localmente via Ollama (offline-first).",
        "properties": {
            "modelCard:task": "text-generation",
            "license": "Llama 3.1 Community License",
        },
    },
    {
        "type": "machine-learning-model",
        "name": "aurora-assist",
        "version": "3.0.0",
        "publisher": "Banco Aurora",
        "description": "Agente RAG: guardrails (Aula 2) + MCP isolado (Aula 3) + observabilidade.",
        "properties": {
            "modelCard:task": "retrieval-augmented-generation",
            "fineTune": "prompt-tuning (system policy)",
        },
    },
)

_DATA_COMPONENTS = (
    {
        "type": "data",
        "name": "aurora-rag-corpus",
        "version": "2026.1",
        "description": "Documentos sintéticos de produtos do Banco Aurora (Faker pt_BR, seed=42).",
        "properties": {"data:classification": "synthetic", "data:pii": "none"},
    },
    {
        "type": "data",
        "name": "aurora-golden-qa",
        "version": "2026.1",
        "description": "Q&A de referência para o quality gate (groundedness/qualidade).",
        "properties": {"data:classification": "synthetic"},
    },
    {
        "type": "data",
        "name": "aurora-redteam-attacks",
        "version": "2026.1",
        "description": "Ataques OWASP LLM para o red team do deploy gate (uso defensivo).",
        "properties": {"data:classification": "synthetic", "data:usage": "defensive-lab-only"},
    },
)


def _bom_ref(name: str, version: str) -> str:
    return f"{name}@{version}"


def _read_dependencies(pyproject_path: Path) -> list[dict]:
    """Lê as dependências de runtime do ``pyproject.toml`` (supply chain de software)."""
    if not pyproject_path.exists():
        return []
    data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    deps = data.get("project", {}).get("dependencies", [])
    components: list[dict] = []
    for spec in deps:
        # Extrai o nome do pacote (antes de qualquer especificador de versão).
        name = spec.split(">=")[0].split("==")[0].split("<")[0].split("[")[0].strip()
        version = spec.replace(name, "", 1).strip() or "*"
        components.append(
            {
                "type": "library",
                "bom-ref": _bom_ref(name, version),
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name}",
            }
        )
    return components


def build_aibom(project_root: Path | None = None) -> dict:
    """Constrói o AIBOM (CycloneDX ML-BOM) do Aurora Assist como um dicionário JSON."""
    root = project_root or Path(__file__).resolve().parents[2]
    serial = f"urn:uuid:{uuid.uuid4()}"
    now = datetime.now(UTC).replace(microsecond=0).isoformat()

    components: list[dict] = []
    for comp in (*_MODEL_COMPONENTS, *_DATA_COMPONENTS):
        entry = {**comp, "bom-ref": _bom_ref(comp["name"], comp["version"])}
        entry["properties"] = [
            {"name": k, "value": v} for k, v in comp.get("properties", {}).items()
        ]
        components.append(entry)
    components.extend(_read_dependencies(root / "pyproject.toml"))

    return {
        "bomFormat": _BOM_FORMAT,
        "specVersion": _SPEC_VERSION,
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": now,
            "component": {
                "type": "application",
                "bom-ref": "aurora-assist-app@3.0.0",
                "name": "aurora-assist",
                "version": "3.0.0",
                "description": "Agente Aurora Assist em produção (Aula 08 — capstone).",
            },
            "tools": [{"vendor": "9mlet", "name": "aula08-aibom-generator", "version": "1.0.0"}],
        },
        "components": components,
    }


def aibom_completeness(aibom: dict) -> dict:
    """Verifica se o AIBOM contém as quatro classes exigidas (Doc 04, §8).

    Usado pelo *deploy gate*: um AIBOM sem modelo base, datasets ou dependências
    não permite gerir risco de *supply chain* — bloqueia a promoção.
    """
    types = {c.get("type") for c in aibom.get("components", [])}
    names = {c.get("name") for c in aibom.get("components", [])}
    checks = {
        "has_base_model": "llama3.1" in names,
        "has_ml_models": "machine-learning-model" in types,
        "has_datasets": "data" in types,
        "has_dependencies": "library" in types,
    }
    return {
        "complete": all(checks.values()),
        "checks": checks,
        "component_count": len(aibom.get("components", [])),
        "digest": hashlib.sha256(
            json.dumps(aibom.get("components", []), sort_keys=True).encode("utf-8")
        ).hexdigest()[:16],
    }


def write_aibom(path: Path, project_root: Path | None = None) -> dict:
    """Gera e persiste o AIBOM em JSON (equivalente ao ``--output-file`` do Snippet 1)."""
    aibom = build_aibom(project_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(aibom, ensure_ascii=False, indent=2), encoding="utf-8")
    return aibom
