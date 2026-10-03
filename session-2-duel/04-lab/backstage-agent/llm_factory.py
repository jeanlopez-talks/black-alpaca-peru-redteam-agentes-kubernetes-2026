#!/usr/bin/env python3
"""
Fabrica del modelo de lenguaje del agente DevSecOps (human-in-the-loop).

Es una copia reducida de ../duel/llm_factory.py (misma decision de arquitectura:
proveedor y modelo parametrizables por entorno, API key NUNCA hardcodeada). Se
duplica a proposito: cada pieza del lab es autocontenida y kustomize/Argo CD no
permite leer archivos fuera del directorio de la app (load-restrictor), asi que
compartir el modulo por ruta relativa rompeia el build de la Application.

Por defecto usa el LLM LOCAL del cluster (vLLM qwen3-8b, OpenAI-compatible):

    LLM_PROVIDER    = openai-compatible   (default)
    LLM_MODEL       = qwen3-8b
    OPENAI_BASE_URL = http://vllm.inference.svc.cluster.local:8000/v1
    OPENAI_API_KEY  = not-needed          (dummy; vLLM no la valida)
"""

from __future__ import annotations

import os
from typing import Any

_DEFAULT_BASE_URL = "http://vllm.inference.svc.cluster.local:8000/v1"


def provider_name() -> str:
    """Proveedor LLM elegido (minusculas). Default: openai-compatible (vLLM local)."""
    return os.getenv("LLM_PROVIDER", "openai-compatible").strip().lower()


def llm_available() -> bool:
    """¿Se puede construir el modelo LLM? (langchain-openai instalado).

    El agente usa esto para decidir si redacta los resumenes/explicaciones con el
    LLM o cae al modo plantilla (sin LLM). Nunca inventa una clave.
    """
    try:
        import langchain_openai  # noqa: F401
    except ImportError:
        return False
    return bool(os.getenv("OPENAI_API_KEY", "not-needed"))


def build_chat_model(**kwargs: Any) -> Any:
    """Construye el ChatModel. Solo soporta el LLM local OpenAI-compatible (vLLM).

    Lanza RuntimeError con mensaje claro si falta langchain-openai; el llamador lo
    captura y cae al modo plantilla.
    """
    name = provider_name()
    if name != "openai-compatible":
        raise RuntimeError(
            f"LLM_PROVIDER='{name}' no soportado por este agente. Usa "
            "'openai-compatible' (LLM local del cluster)."
        )
    try:
        from langchain_openai import ChatOpenAI
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "langchain-openai no esta instalado; no se puede usar el LLM local. "
            "Instala requirements.txt o deja el modo plantilla."
        ) from exc

    base_url = os.getenv("OPENAI_BASE_URL", "").strip() or _DEFAULT_BASE_URL
    model_id = os.getenv("LLM_MODEL", "").strip() or "qwen3-8b"
    return ChatOpenAI(
        model=model_id,
        base_url=base_url,
        api_key=os.getenv("OPENAI_API_KEY", "not-needed"),  # dummy
        temperature=0,
        **kwargs,
    )
