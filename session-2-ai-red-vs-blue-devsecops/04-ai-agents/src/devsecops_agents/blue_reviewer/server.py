"""Agente azul como servidor A2A: skill `review-pr`.

Recibe el diff de un PR como texto y responde con el veredicto en JSON (ReviewResult).
La postura se fija al arrancar: BLUE_HARDENED=true lo endurece (Acto 4).
"""

from __future__ import annotations

import json
import logging
import os

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.types import AgentCard, AgentSkill

from devsecops_agents import __version__
from devsecops_agents.blue_reviewer.review import BlueReviewer
from devsecops_agents.common.a2a_server import build_agent_card, text_reply

log = logging.getLogger(__name__)

SKILL_ID = "review-pr"
DEFAULT_PORT = 9999


def agent_card(public_url: str) -> AgentCard:
    return build_agent_card(
        name="Blue Reviewer Agent",
        description="Agente azul: revisor de seguridad de PRs del pipeline DevSecOps.",
        version=__version__,
        public_url=public_url,
        skills=[
            AgentSkill(
                id=SKILL_ID,
                name="Review Pull Request",
                description="Revisa el diff de un PR y decide APPROVE o BLOCK por riesgo.",
                tags=["security", "devsecops", "code-review"],
                examples=["<diff unificado del PR>"],
            )
        ],
    )


class BlueReviewExecutor(AgentExecutor):
    def __init__(self, reviewer: BlueReviewer | None = None) -> None:
        hardened = os.getenv("BLUE_HARDENED", "false").strip().lower() == "true"
        self._reviewer = reviewer or BlueReviewer(hardened=hardened)

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        pr_id = (context.message.message_id if context.message else "") or "pr"
        result = self._reviewer.review(pr_id, context.get_user_input() or "")
        log.info("pr=%s decision=%s engine=%s", pr_id, result.decision, result.engine)
        await event_queue.enqueue_event(
            text_reply(context, json.dumps(result.as_dict(), ensure_ascii=False))
        )

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise NotImplementedError("la revisión es síncrona y corta; no hay nada que cancelar")
