"""Cliente A2A común (a2a-sdk 1.2): envía un mensaje de texto y devuelve el texto de la respuesta.

`create_client(url)` descubre la AgentCard en /.well-known/agent-card.json y elige el
transporte. Las cabeceras (p. ej. el token humano en `X-Human-Approval`) viajan en el
cliente httpx, nunca dentro del mensaje.
"""

from __future__ import annotations

import uuid

import httpx
from a2a.client import ClientConfig, create_client
from a2a.types import Message, Part, Role, SendMessageRequest

DEFAULT_TIMEOUT_S = 60.0


async def send_text(
    agent_url: str,
    text: str,
    *,
    message_id: str | None = None,
    headers: dict[str, str] | None = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> str:
    """Envía `text` al agente A2A en `agent_url` y devuelve el texto de su respuesta."""
    async with httpx.AsyncClient(headers=headers or {}, timeout=timeout_s) as http:
        client = await create_client(agent_url, client_config=ClientConfig(httpx_client=http))
        try:
            request = SendMessageRequest(
                message=Message(
                    role=Role.ROLE_USER,
                    message_id=message_id or uuid.uuid4().hex,
                    parts=[Part(text=text)],
                )
            )
            reply = ""
            async for response in client.send_message(request):
                reply = _text_of(response) or reply
            return reply
        finally:
            await client.close()


def _text_of(response: object) -> str:
    """Texto de un StreamResponse (oneof message/task) de a2a-sdk 1.2."""
    message = getattr(response, "message", None)
    text = "".join(p.text for p in getattr(message, "parts", []) or [] if p.text)
    if text:
        return text
    task = getattr(response, "task", None)
    for artifact in getattr(task, "artifacts", []) or []:
        text = "".join(p.text for p in artifact.parts if p.text)
        if text:
            return text
    return ""
