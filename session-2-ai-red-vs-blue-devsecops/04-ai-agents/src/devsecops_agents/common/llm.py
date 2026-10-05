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

import logging
import os
from dataclasses import dataclass
from typing import Any

_log = logging.getLogger(__name__)

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


def build_chat_model(temperature: float = 0, **kwargs: Any) -> Any:
    """Construye el ChatModel de LangChain (temperature=0 por defecto: demo reproducible).

    Con razonamiento activado (Qwen3 thinking) conviene 0.6: en greedy el razonamiento
    puede entrar en bucle.
    """
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
                temperature=temperature,
                **kwargs,
            )
        from langchain.chat_models import init_chat_model

        return init_chat_model(
            model_id, model_provider=provider.langchain_name, temperature=temperature, **kwargs
        )
    except ImportError as exc:
        raise LLMUnavailableError(f"LangChain no disponible: {exc}") from exc


def usage_of(reply: Any) -> dict[str, Any]:
    """Por qué terminó y cuántos tokens usó una respuesta (metadatos de LangChain/vLLM)."""
    meta = getattr(reply, "response_metadata", None) or {}
    usage = meta.get("token_usage") or {}
    details = usage.get("completion_tokens_details") or {}
    return {
        "finish_reason": meta.get("finish_reason", ""),
        "prompt_tokens": usage.get("prompt_tokens", 0),
        "completion_tokens": usage.get("completion_tokens", 0),
        "reasoning_tokens": details.get("reasoning_tokens", 0) or 0,
        "reasoning_chars": len(
            str((getattr(reply, "additional_kwargs", None) or {}).get("reasoning_content", ""))
        ),
    }


def invoke_json(
    model: Any, messages: list[Any], attempts: int = 2, stats: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    """Llama al modelo, lee su respuesta como JSON y deja constancia de cada intento.

    Con salida guiada el JSON solo es inválido si la respuesta se corta
    (finish_reason=length: el razonamiento y la salida agotaron max_tokens). El remedio es
    dimensionar max_tokens y lo que se pide; el reintento es solo una red de seguridad y
    queda registrado (stats y log) con el motivo.
    """
    import json
    import time

    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        started = time.monotonic()
        reply = model.invoke(messages)
        info = usage_of(reply) | {
            "attempt": attempt,
            "seconds": round(time.monotonic() - started, 1),
        }
        try:
            value = json.loads(str(reply.content))
            if not isinstance(value, dict):
                raise ValueError(f"se esperaba un objeto JSON, llegó {type(value).__name__}")
            info["ok"] = True
        except ValueError as exc:  # JSONDecodeError es un ValueError
            info["ok"], last = False, exc
        if stats is not None:
            stats.append(info)
        _log.info("llamada al modelo: %s", info)
        if info["ok"]:
            return value
        _log.warning(
            "respuesta no válida (finish_reason=%s, %s tokens de salida): %s",
            info["finish_reason"],
            info["completion_tokens"],
            last,
        )
    raise ValueError(f"el modelo no devolvió JSON válido tras {attempts} intentos: {last}")
