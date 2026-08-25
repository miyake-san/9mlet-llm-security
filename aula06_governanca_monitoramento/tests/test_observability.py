"""Testes de observabilidade e token economics (Aula 06 — Doc 04, §Observabilidade).

Verifica spans com convenções gen_ai.*, modelo de custo, cache semântico, model
routing, minimização de PII na telemetria e a exposição Prometheus em /metrics.
"""

from __future__ import annotations

from src.security.observability import (
    CostModel,
    SemanticCache,
    new_span,
    redact_preview,
    route_model,
)

_ROUTING = {
    "enabled": True,
    "complex_min_tokens": 24,
    "complex_terms": ["crédito", "renegocia"],
    "cheap_model": "aurora-mini",
    "capable_model": "aurora-pro",
}


def test_cost_model_por_1k_tokens():
    cost = CostModel(input_per_1k=0.005, output_per_1k=0.015)
    assert abs(cost.cost("qualquer", 1000, 1000) - 0.02) < 1e-9


def test_span_expoe_convencoes_gen_ai():
    span = new_span(
        "aurora_assist.chat",
        system="ollama",
        model="aurora-pro",
        input_tokens=12,
        output_tokens=34,
        latency_ms=120.0,
        cost_usd=0.001,
        groundedness=0.9,
    )
    attrs = span.to_otel_attributes()
    assert attrs["gen_ai.system"] == "ollama"
    assert attrs["gen_ai.request.model"] == "aurora-pro"
    assert attrs["gen_ai.usage.input_tokens"] == 12
    assert attrs["gen_ai.usage.output_tokens"] == 34
    assert "aurora.cost_usd" in attrs


def test_semantic_cache_hit_e_miss():
    cache = SemanticCache(threshold=0.8)
    cache.put("qual a taxa do cdb", "resposta cacheada")
    assert cache.get("qual a taxa do cdb hoje") == "resposta cacheada"  # similar -> hit
    assert cache.get("horario da agencia central xyz") is None  # distinto -> miss
    assert cache.hits == 1 and cache.misses == 1


def test_model_routing_simples_vs_complexo():
    simple_model, is_complex = route_model("Qual o horário da agência?", _ROUTING)
    assert simple_model == "aurora-mini" and is_complex is False
    complex_model, is_complex2 = route_model(
        "Preciso renegociar meu crédito com garantia imobiliária.", _ROUTING
    )
    assert complex_model == "aurora-pro" and is_complex2 is True


def test_redact_preview_mascara_pii():
    texto = "Cliente CPF 529.982.247-25, email joao@exemplo.com, tel (11) 91234-5678."
    preview = redact_preview(texto)
    assert "529.982.247-25" not in preview
    assert "joao@exemplo.com" not in preview
    assert "[REDACTED]" in preview


def test_chat_gera_span_e_metricas(client):
    body = client.post("/chat", json={"message": "Qual a taxa do CDB do Aurora?"}).json()
    assert body["trace_id"]
    assert body["output_tokens"] > 0
    assert body["regulated"] is True  # contém "cdb"/"taxa"
    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert "aurora_cost_usd_total" in metrics.text
    assert "aurora_request_latency_ms" in metrics.text


def test_cache_hit_via_api_zera_tokens(client):
    payload = {"message": "Como emito um boleto de pagamento?"}
    first = client.post("/chat", json=payload).json()
    second = client.post("/chat", json=payload).json()
    assert first["cache_hit"] is False
    assert second["cache_hit"] is True
    assert second["input_tokens"] == 0 and second["output_tokens"] == 0


def test_traces_endpoint_nao_expoe_prompt_em_claro(client):
    client.post("/chat", json={"message": "meu CPF é 529.982.247-25, ajuda?"})
    data = client.get("/traces").json()
    dump = str(data)
    assert "529.982.247-25" not in dump
