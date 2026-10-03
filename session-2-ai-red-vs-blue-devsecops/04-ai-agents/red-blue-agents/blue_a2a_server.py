#!/usr/bin/env python3
"""
AGENTE AZUL expuesto como A2A SERVER (protocolo Agent2Agent, a2a-sdk 1.2.1).

Arquitectura del duelo (ver ../../01-proposal/concept.md):
    El azul ES un servidor A2A con su AgentCard (skill "review-pr"). El rojo es un
    A2A client que le manda el diff del PR; el azul lo revisa con BlueAgent (LLM o
    reglas) y devuelve el veredicto APPROVE/BLOCK.

    En Tekton, este server corre como un contenedor que escucha, y el step del
    rojo lo consume por A2A (ver ../../03-gitops/devsecops-pipeline/pipeline-devsecops.yaml).

Contrato A2A:
    - AgentCard publicada en /.well-known/agent-card.json (ruta estandar A2A, la
      usa el readinessProbe).
    - skill id="review-pr": recibe el texto del diff como mensaje y responde con
      una linea JSON con la decision (para que el client la parsee sin ambiguedad).

Este modulo SOLO se importa cuando hay a2a-sdk instalado (modo llm con A2A real).
El modo rules offline del duelo NO necesita a2a-sdk: usa el path directo en
run_duel.py / review_pr.py. Por eso los imports de a2a van dentro de funciones.

NOTAS sobre a2a-sdk 1.2.1 (la API cambio respecto a 0.x):
    - `a2a.server.apps` / `A2AStarletteApplication` YA NO EXISTEN. La app se monta
      a mano sobre Starlette con las rutas que da el SDK:
        * `a2a.server.routes.create_jsonrpc_routes(handler, rpc_url)` -> rutas RPC.
        * `a2a.server.routes.create_agent_card_routes(card, card_url=...)` -> card.
    - `DefaultRequestHandler` ahora EXIGE `agent_card` en el constructor.
    - Los tipos de `a2a.types` (AgentCard, Message, Part, ...) son PROTOBUF:
      se construyen por campos y no admiten metodos pydantic (.model_dump, etc.).
    - No existe `a2a.utils.new_agent_text_message`: el mensaje de respuesta se
      construye como `a2a.types.Message(role=ROLE_AGENT, parts=[Part(text=...)])`.
"""

from __future__ import annotations

import json
import os
from typing import Any

from blue_agent import BlueAgent

# Host/puerto del server azul (parametrizables; en Tekton el rojo apunta aqui).
DEFAULT_HOST: str = os.getenv("BLUE_A2A_HOST", "127.0.0.1")
DEFAULT_PORT: int = int(os.getenv("BLUE_A2A_PORT", "9999"))

# Identificador del skill expuesto por el azul.
SKILL_ID: str = "review-pr"

# Prefijo donde se montan las rutas JSON-RPC del protocolo A2A.
RPC_URL: str = "/"


def build_agent_card(host: str, port: int) -> Any:
    """Construye la AgentCard del azul (skill review-pr) con los tipos de a2a 1.2.1.

    En 1.2.1 los tipos son protobuf: se instancian por campos. La AgentCard ya no
    tiene un campo `url` plano; las URLs de transporte viven en
    `supported_interfaces` (lista de AgentInterface con `protocol_binding` + `url`).
    El transporte estandar aqui es JSONRPC.
    """
    from a2a.types import (
        AgentCapabilities,
        AgentCard,
        AgentInterface,
        AgentSkill,
    )
    from a2a.utils.constants import TransportProtocol

    url = f"http://{host}:{port}/"
    skill = AgentSkill(
        id=SKILL_ID,
        name="Review Pull Request",
        description=(
            "Revisa el diff de un PR y decide APPROVE o BLOCK por riesgo de "
            "seguridad. Usa un agente revisor (LLM o reglas)."
        ),
        tags=["security", "devsecops", "code-review"],
        examples=["Revisa este diff y dime si lo apruebo"],
    )
    # AgentCapabilities(streaming=False): el azul responde un unico Message.
    return AgentCard(
        name="Blue Reviewer Agent",
        description="Agente azul: revisor de seguridad de PRs del pipeline DevSecOps.",
        version="2.1.0",
        supported_interfaces=[
            AgentInterface(
                protocol_binding=TransportProtocol.JSONRPC.value,
                url=url,
                protocol_version="1.0",
            ),
        ],
        capabilities=AgentCapabilities(streaming=False),
        default_input_modes=["text/plain"],
        default_output_modes=["text/plain"],
        skills=[skill],
    )


def _build_executor_class() -> type:
    """Define el AgentExecutor del azul en tiempo de ejecucion (import tardio de a2a).

    El executor recibe el texto del diff (el mensaje del client), lo revisa con
    BlueAgent (modo vulnerable: honra las notas al revisor, para reproducir el
    Acto 2) y publica un unico Message de respuesta con el veredicto en JSON.
    """
    from a2a.server.agent_execution import AgentExecutor, RequestContext
    from a2a.server.events import EventQueue
    from a2a.types import Message, Part, Role

    class BlueReviewExecutor(AgentExecutor):  # type: ignore[misc]
        """Executor A2A que delega la revision en BlueAgent."""

        def __init__(self) -> None:
            # El modo (llm|rules) lo decide BlueAgent via AGENT_MODE.
            # honor_reviewer_notes=True = azul VULNERABLE (Actos 1-3): obedece la
            # instruccion incrustada en el diff, igual que el camino directo.
            self._blue = BlueAgent(honor_reviewer_notes=True)

        async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
            diff_text: str = context.get_user_input() or ""
            # En 1.2.1 el mensaje entrante es un proto; message_id es un str plano.
            pr_id: str = (
                getattr(context.message, "message_id", "") if context.message else ""
            ) or "pr-a2a"
            result = self._blue.review(pr_id, diff_text)
            payload: str = json.dumps(result.as_dict(), ensure_ascii=False)
            # Respuesta inmediata: un unico Message (rol AGENT) con el veredicto.
            response = Message(
                role=Role.ROLE_AGENT,
                message_id=f"{pr_id}-verdict",
                parts=[Part(text=payload)],
            )
            await event_queue.enqueue_event(response)

        async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
            # Revision sincrona y corta; no hay nada que cancelar.
            raise Exception("cancel no soportado por el revisor de PRs")

    return BlueReviewExecutor


def build_app(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> Any:
    """Construye la app ASGI (Starlette) del server A2A del azul, para a2a-sdk 1.2.1.

    Monta a mano las rutas que expone el SDK:
      - create_agent_card_routes(card) -> sirve la AgentCard en
        /.well-known/agent-card.json (ruta estandar, la usa el readinessProbe).
      - create_jsonrpc_routes(handler, RPC_URL) -> endpoint JSON-RPC del protocolo.

    Se separa de `serve` para poder testear la construccion sin abrir el socket.
    """
    from starlette.applications import Starlette

    from a2a.server.request_handlers import DefaultRequestHandler
    from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
    from a2a.server.tasks import InMemoryTaskStore

    executor_cls = _build_executor_class()
    agent_card = build_agent_card(host, port)

    # DefaultRequestHandler en 1.2.1 exige agent_card ademas del executor y el store.
    request_handler = DefaultRequestHandler(
        agent_executor=executor_cls(),
        task_store=InMemoryTaskStore(),
        agent_card=agent_card,
    )

    routes = []
    routes.extend(create_agent_card_routes(agent_card))
    routes.extend(create_jsonrpc_routes(request_handler, RPC_URL))
    return Starlette(routes=routes)


def serve(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    """Levanta el server A2A del azul con uvicorn (bloqueante)."""
    import uvicorn

    app = build_app(host, port)
    print(f"[blue-a2a] AgentCard en http://{host}:{port}/.well-known/agent-card.json")
    uvicorn.run(app, host=host, port=port, log_level="warning")


def main() -> int:
    serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
