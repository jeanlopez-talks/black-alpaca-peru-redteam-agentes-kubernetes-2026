#!/usr/bin/env python3
"""
Fabrica del modelo de lenguaje para los agentes (rojo y azul).

Centraliza la eleccion del proveedor LLM para no duplicar la logica en los dos
agentes. El proveedor y el modelo son PARAMETRIZABLES por variables de entorno
(decision de arquitectura de la charla):

    LLM_PROVIDER = anthropic | openai | google | openai-compatible
                   (default: openai-compatible, el LLM LOCAL del cluster)
    LLM_MODEL    = id del modelo del proveedor    (hay un default por proveedor)

La API key NUNCA se hardcodea: viene del entorno (en el cluster, de un Secret de
K8s montado como env var). Cada proveedor usa su propia variable estandar:

    anthropic         -> ANTHROPIC_API_KEY
    openai            -> OPENAI_API_KEY
    google            -> GOOGLE_API_KEY
    openai-compatible -> OPENAI_API_KEY (dummy, p.ej. "not-needed") + OPENAI_BASE_URL

PROVEEDOR 'openai-compatible' (el que usa la demo en k3s vanilla):
apunta a un LLM LOCAL servido por vLLM dentro del cluster, con API
OpenAI-compatible. Es el modo preferido de la charla porque NO depende de un
tercero externo ni de egress a internet: el modelo (qwen3-8b) vive en el propio
cluster (namespace inference). Se construye con `langchain_openai.ChatOpenAI`
pasando `base_url` (OPENAI_BASE_URL) y una key dummy; vLLM no la valida.

    OPENAI_BASE_URL = http://vllm.inference.svc.cluster.local:8000/v1
    LLM_MODEL       = qwen3-8b  (served-model-name del vLLM)
    OPENAI_API_KEY  = not-needed  (dummy; vLLM no la exige)

Para los demas proveedores se usa `langchain.chat_models.init_chat_model`, que
ya sabe mapear el proveedor al paquete correcto (langchain-anthropic /
langchain-openai / langchain-google-genai). Si LangChain no esta instalado (modo
rules puro), este modulo ni siquiera se importa: los agentes caen al fallback por
reglas.
"""

from __future__ import annotations

import os
from typing import Any

# Mapa proveedor -> (nombre de proveedor para init_chat_model, modelo por defecto,
# variable de entorno de la API key). Los modelos por defecto son placeholders
# razonables; se sobreescriben con LLM_MODEL.
_PROVIDERS: dict[str, tuple[str, str, str]] = {
    "anthropic": ("anthropic", "claude-sonnet-4-5", "ANTHROPIC_API_KEY"),
    "openai": ("openai", "gpt-4o", "OPENAI_API_KEY"),
    "google": ("google_genai", "gemini-2.0-flash", "GOOGLE_API_KEY"),
    # LLM LOCAL del cluster (vLLM, API OpenAI-compatible). Es el DEFAULT en k3s
    # vanilla: no hay egress externo, el modelo vive en el propio cluster.
    "openai-compatible": ("openai_compatible", "qwen3-8b", "OPENAI_API_KEY"),
}

# Base URL por defecto del LLM local (vLLM) servido dentro del cluster. Se puede
# sobreescribir con OPENAI_BASE_URL. Endpoint OpenAI-compatible (sufijo /v1).
_DEFAULT_OPENAI_BASE_URL = "http://vllm.inference.svc.cluster.local:8000/v1"


def provider_name() -> str:
    """Devuelve el proveedor LLM elegido (en minusculas).

    Default: 'openai-compatible' (el LLM local del cluster via vLLM). Asi la demo
    en k3s vanilla no depende de ningun proveedor externo ni de egress a internet.
    """
    return os.getenv("LLM_PROVIDER", "openai-compatible").strip().lower()


def api_key_present() -> bool:
    """¿Hay API key en el entorno para el proveedor elegido?

    Es la señal que usan los agentes para decidir si pueden levantar el modo LLM
    o deben caer al fallback por reglas (demo aislada sin egress/credenciales).
    """
    name = provider_name()
    if name not in _PROVIDERS:
        return False
    _, _, env_var = _PROVIDERS[name]
    return bool(os.getenv(env_var))


def build_chat_model(**kwargs: Any) -> Any:
    """
    Construye el ChatModel de LangChain segun LLM_PROVIDER / LLM_MODEL.

    Lanza RuntimeError con un mensaje claro si falta LangChain, el proveedor no
    esta soportado o no hay API key. Los llamadores (agentes) capturan ese error
    y caen al modo rules; nunca se inventa una clave.
    """
    name = provider_name()
    if name not in _PROVIDERS:
        raise RuntimeError(
            f"LLM_PROVIDER='{name}' no soportado. Usa uno de: "
            f"{', '.join(sorted(_PROVIDERS))}."
        )

    provider, default_model, env_var = _PROVIDERS[name]

    if not os.getenv(env_var):
        raise RuntimeError(
            f"Falta la API key del proveedor '{name}' (variable {env_var}). "
            "En el cluster viene de un Secret de K8s. Sin ella, usa AGENT_MODE=rules."
        )

    model_id = os.getenv("LLM_MODEL", "").strip() or default_model

    # --- PROVEEDOR 'openai-compatible': LLM LOCAL del cluster (vLLM) -----------
    # No se usa init_chat_model aqui porque necesitamos pasar base_url custom al
    # endpoint OpenAI-compatible de vLLM. Se usa ChatOpenAI directamente con
    # base_url (OPENAI_BASE_URL) y la key dummy. vLLM no valida la key.
    if name == "openai-compatible":
        try:
            from langchain_openai import ChatOpenAI
        except ImportError as exc:  # pragma: no cover - ayuda de entorno
            raise RuntimeError(
                "langchain-openai no esta instalado; no se puede usar el LLM local. "
                "Instala requirements.txt o usa AGENT_MODE=rules.\n"
                f"Detalle: {exc}"
            ) from exc

        base_url = os.getenv("OPENAI_BASE_URL", "").strip() or _DEFAULT_OPENAI_BASE_URL
        # temperature=0 para que la demo sea lo mas determinista posible.
        return ChatOpenAI(
            model=model_id,
            base_url=base_url,
            api_key=os.getenv(env_var),  # dummy, p.ej. "not-needed"
            temperature=0,
            **kwargs,
        )

    # --- Resto de proveedores: init_chat_model mapea al paquete correcto ------
    try:
        from langchain.chat_models import init_chat_model
    except ImportError as exc:  # pragma: no cover - ayuda de entorno
        raise RuntimeError(
            "LangChain no esta instalado; no se puede usar el modo LLM. "
            "Instala requirements.txt o usa AGENT_MODE=rules.\n"
            f"Detalle: {exc}"
        ) from exc

    # temperature=0 para que la demo sea lo mas determinista posible.
    return init_chat_model(
        model_id,
        model_provider=provider,
        temperature=0,
        **kwargs,
    )
