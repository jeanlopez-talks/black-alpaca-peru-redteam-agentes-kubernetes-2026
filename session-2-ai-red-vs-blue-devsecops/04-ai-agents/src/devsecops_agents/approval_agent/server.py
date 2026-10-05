"""Agente de aprobación (human-in-the-loop) como servidor A2A. Lo consume Backstage.

Skills (el mensaje es un JSON de texto con el campo `skill`):

  summarize-pipeline  {"skill": "summarize-pipeline"}                  solo lectura
  propose-actions     {"skill": "propose-actions"}                     solo texto
  execute-action      {"skill": "execute-action", "action_id": "..."}  exige token humano

El token humano viaja en la cabecera `X-Human-Approval` (esquema de seguridad
`human-approval`, tipo API key, declarado en la AgentCard), nunca dentro del mensaje: así
no queda en el historial de la conversación ni en los logs del agente. No se usa
`Authorization` porque Backstage ya la ocupa con el token de su propio usuario.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.types import (
    AgentCard,
    AgentSkill,
    APIKeySecurityScheme,
    SecurityRequirement,
    SecurityScheme,
)

from devsecops_agents import __version__
from devsecops_agents.approval_agent import actions, cluster, narrative, review
from devsecops_agents.common.a2a_server import build_agent_card, request_header, text_reply
from devsecops_agents.common.backstage_mcp import GuidelineClient

log = logging.getLogger(__name__)

DEFAULT_PORT = 8080
HUMAN_SCHEME = "human-approval"
HUMAN_HEADER = "X-Human-Approval"


def agent_card(public_url: str) -> AgentCard:
    return build_agent_card(
        name="DevSecOps Approval Agent",
        description=(
            "Resume el pipeline del duelo, explica por qué se aprobó o rechazó y propone "
            "acciones. Solo ejecuta una acción con el token de un humano."
        ),
        version=__version__,
        public_url=public_url,
        skills=[
            AgentSkill(
                id="summarize-pipeline",
                name="Resumir el pipeline",
                description="Estado por etapa, Application de Argo CD y explicación.",
                tags=["devsecops", "read-only"],
            ),
            AgentSkill(
                id="propose-actions",
                name="Proponer acciones",
                description="Propuestas (re-run, aprobar con revisión, ticket). No ejecuta.",
                tags=["devsecops", "read-only"],
            ),
            AgentSkill(
                id="execute-action",
                name="Ejecutar una acción confirmada",
                description="Ejecuta una propuesta SOLO con el token de un humano.",
                tags=["devsecops", "human-in-the-loop"],
                security_requirements=[SecurityRequirement(schemes={HUMAN_SCHEME: {}})],
            ),
        ],
        security_schemes={
            HUMAN_SCHEME: SecurityScheme(
                api_key_security_scheme=APIKeySecurityScheme(
                    location="header",
                    name=HUMAN_HEADER,
                    description="Token de aprobación de un humano.",
                )
            )
        },
    )


def _human_token(context: RequestContext) -> str:
    return request_header(context, HUMAN_HEADER).strip()


_reviews: review.ReviewCache | None = None


def _review_cache() -> review.ReviewCache:
    global _reviews
    if _reviews is None:
        _reviews = review.ReviewCache(GuidelineClient())
    return _reviews


def handle(request: dict[str, Any], human_token: str) -> dict[str, Any]:
    skill = request.get("skill")
    if skill == "summarize-pipeline":
        runs = cluster.read_pipelineruns()
        return {
            "pipelineruns": [
                {
                    "name": r.name,
                    "overall": r.overall,
                    "is_mock": r.is_mock,
                    "started": r.started,
                    "stages": [vars(s) for s in r.stages],
                }
                for r in runs
            ],
            "argocd_apps": cluster.read_argocd_apps(),
            "explanation": narrative.template_explanation(runs),
            # Segunda opinión del modelo (en segundo plano): pending | done | failed.
            "review": _review_cache().get(runs),
        }
    if skill == "propose-actions":
        runs = cluster.read_pipelineruns()
        reviews = {r["run"]: r for r in _review_cache().get(runs).get("runs", [])}
        proposals = []
        for run in runs:
            reviewed = reviews.get(run.name, {})
            if reviewed.get("status") == "done":
                # Las del modelo para esta corrida, ya verificadas (solo acciones posibles).
                proposals += [
                    {
                        "id": p["id"],
                        "title": p["action"],
                        "why": p["why"],
                        "danger": "alta" if p["action"] == "approve" else "baja",
                        "source": "modelo (verificado)",
                    }
                    for p in reviewed["proposals"]
                ]
            else:
                proposals += [
                    p.as_dict() | {"source": "reglas"} for p in actions.propose_actions([run])
                ]
        return {
            "proposals": proposals,
            "note": "Son propuestas: ninguna se ejecuta sin el token de un humano.",
        }
    if skill == "execute-action":
        return actions.execute_action(str(request.get("action_id", "")), human_token)
    raise ValueError(f"skill desconocida '{skill}'")


class ApprovalExecutor(AgentExecutor):
    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        try:
            request = json.loads(context.get_user_input() or "{}")
            result = handle(request, _human_token(context))
        except actions.HumanApprovalRequiredError as exc:
            log.warning("acción rechazada: sin token humano válido")
            result = {"error": "human_approval_required", "detail": str(exc)}
        except (json.JSONDecodeError, ValueError) as exc:
            result = {"error": "bad_request", "detail": str(exc)}
        await event_queue.enqueue_event(text_reply(context, json.dumps(result, ensure_ascii=False)))

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise NotImplementedError("las peticiones son síncronas y cortas")
