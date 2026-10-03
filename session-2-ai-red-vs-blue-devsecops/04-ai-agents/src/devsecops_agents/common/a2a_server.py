"""Servidor A2A común (a2a-sdk 1.2): AgentCard + JSON-RPC + /healthz sobre Starlette.

Cada agente aporta su AgentCard y su AgentExecutor; aquí se monta la app igual para
todos:

    GET  /.well-known/agent-card.json   AgentCard (descubrimiento A2A)
    POST /                              endpoint JSON-RPC del protocolo A2A
    GET  /healthz                       liveness/readiness de Kubernetes

Notas de a2a-sdk 1.2: los tipos son protobuf; la app se monta con
`create_agent_card_routes` y `create_jsonrpc_routes`; las cabeceras HTTP de cada
llamada llegan al executor en `context.call_context.state["headers"]`.
"""

from __future__ import annotations

import os

import uvicorn
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentSkill,
    Message,
    Part,
    Role,
)
from a2a.utils.constants import TransportProtocol
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route

RPC_PATH = "/"


def build_agent_card(
    *,
    name: str,
    description: str,
    version: str,
    public_url: str,
    skills: list[AgentSkill],
    **extra: object,
) -> AgentCard:
    """AgentCard con transporte JSON-RPC en `public_url` (la URL por la que lo llaman)."""
    return AgentCard(
        name=name,
        description=description,
        version=version,
        supported_interfaces=[
            AgentInterface(
                protocol_binding=TransportProtocol.JSONRPC.value,
                url=public_url,
                protocol_version="1.0",
            )
        ],
        capabilities=AgentCapabilities(streaming=False),
        default_input_modes=["text/plain"],
        default_output_modes=["application/json"],
        skills=skills,
        **extra,
    )


def text_reply(context: RequestContext, text: str) -> Message:
    """Respuesta A2A de un único Message (rol AGENT) con texto."""
    return Message(
        role=Role.ROLE_AGENT,
        message_id=f"{context.message.message_id if context.message else 'reply'}-reply",
        context_id=context.context_id or "",
        parts=[Part(text=text)],
    )


def request_header(context: RequestContext, name: str) -> str:
    """Cabecera HTTP de la llamada A2A en curso ('' si no llegó)."""
    call = context.call_context
    headers = call.state.get("headers", {}) if call else {}
    return headers.get(name.lower(), "")


async def _healthz(_: Request) -> PlainTextResponse:
    return PlainTextResponse("ok")


def build_app(card: AgentCard, executor: AgentExecutor) -> Starlette:
    handler = DefaultRequestHandler(
        agent_executor=executor, task_store=InMemoryTaskStore(), agent_card=card
    )
    routes = [Route("/healthz", _healthz, methods=["GET"])]
    routes.extend(create_agent_card_routes(card))
    routes.extend(create_jsonrpc_routes(handler, RPC_PATH))
    return Starlette(routes=routes)


def listen_address(default_port: int) -> tuple[str, int]:
    """Dirección de escucha: HOST/PORT por entorno (0.0.0.0 para que el kubelet sondee)."""
    return os.getenv("HOST", "0.0.0.0"), int(os.getenv("PORT", str(default_port)))  # noqa: S104


def serve(app: Starlette, host: str, port: int) -> None:
    uvicorn.run(app, host=host, port=port, log_level="info", access_log=False)
