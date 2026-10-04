"""Fábrica única del modelo de lenguaje para los tres agentes.

El proveedor se elige por entorno:

    LLM_PROVIDER = openai-compatible (por defecto) | anthropic | openai | google
    LLM_MODEL    = id del modelo (cada proveedor tiene un valor por defecto)

`openai-compatible` es el LLM LOCAL del clúster (vLLM `qwen3-8b`): no sale a internet
y no necesita API key (vLLM no la valida). Los proveedores externos sí la exigen, y
siempre llega por entorno desde un Secret; nunca se escribe en el código.

Si LangChain no está instalado o el modelo no se puede construir, `build_chat_model`
lanza `LLMUnavailableError` y cada agente cae a su modo determinista.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

DEFAULT_PROVIDER = "openai-compatible"
DEFAULT_LOCAL_BASE_URL = "http://vllm.inference.svc.cluster.local:8000/v1"


class LLMUnavailableError(RuntimeError):
    """No hay forma de construir el modelo (sin dependencias, proveedor o credencial)."""


@dataclass(frozen=True)
class _Provider:
    langchain_name: str
    default_model: str
    api_key_env: str | None  # None: el proveedor no exige clave


_PROVIDERS: dict[str, _Provider] = {
    "openai-compatible": _Provider("openai", "qwen3-8b", None),
    "anthropic": _Provider("anthropic", "claude-sonnet-5", "ANTHROPIC_API_KEY"),
    "openai": _Provider("openai", "gpt-4o", "OPENAI_API_KEY"),
    "google": _Provider("google_genai", "gemini-2.0-flash", "GOOGLE_API_KEY"),
}


def provider_name() -> str:
    return os.getenv("LLM_PROVIDER", DEFAULT_PROVIDER).strip().lower()


def llm_configured() -> bool:
    """¿El proveedor elegido es válido y tiene lo que necesita para arrancar?"""
    provider = _PROVIDERS.get(provider_name())
    if provider is None:
        return False
    return provider.api_key_env is None or bool(os.getenv(provider.api_key_env))


def model_id() -> str:
    """Id del modelo en uso (para decir en el informe quién analizó)."""
    provider = _PROVIDERS.get(provider_name())
    default = provider.default_model if provider else ""
    return os.getenv("LLM_MODEL", "").strip() or default


def build_chat_model(**kwargs: Any) -> Any:
    """Construye el ChatModel de LangChain (temperature=0 para una demo reproducible)."""
    name = provider_name()
    provider = _PROVIDERS.get(name)
    if provider is None:
        raise LLMUnavailableError(
            f"LLM_PROVIDER='{name}' no soportado; usa uno de: {', '.join(sorted(_PROVIDERS))}"
        )
    if provider.api_key_env and not os.getenv(provider.api_key_env):
        raise LLMUnavailableError(f"falta {provider.api_key_env} para el proveedor '{name}'")

    model_id = os.getenv("LLM_MODEL", "").strip() or provider.default_model
    try:
        if name == "openai-compatible":
            from langchain_openai import ChatOpenAI

            return ChatOpenAI(
                model=model_id,
                base_url=os.getenv("OPENAI_BASE_URL", "").strip() or DEFAULT_LOCAL_BASE_URL,
                # vLLM no valida la clave, pero el cliente OpenAI exige un valor.
                api_key=os.getenv("OPENAI_API_KEY", "not-needed"),
                temperature=0,
                **kwargs,
            )
        from langchain.chat_models import init_chat_model

        return init_chat_model(
            model_id, model_provider=provider.langchain_name, temperature=0, **kwargs
        )
    except ImportError as exc:
        raise LLMUnavailableError(f"LangChain no disponible: {exc}") from exc
