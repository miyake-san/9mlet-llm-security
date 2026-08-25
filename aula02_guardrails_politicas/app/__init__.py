"""Aurora Assist — serviço de guardrails (Aula 02).

A mesma aplicação FastAPI serve dois papéis (``APP_ROLE``):
- ``gateway``: aplica as camadas de *defense-in-depth* e encaminha ao rag-api.
- ``rag``: backend Aurora Assist que conversa com o LLM (Ollama/Azure/stub).
"""
