"""Agente de remediación como servidor A2A, con dos puertas separadas por red.

  :8080  Backstage (chat con la persona): latest-report, chat, confirm-action, cancel-action
  :8081  pipeline (etapa `remediation`):   advise

El pipeline corre en `devsecops-duel`, donde se ejecuta código no confiable del PR: por
eso solo alcanza la puerta de `advise` (NetworkPolicy) y nunca la de confirmar acciones.

Petición (texto del Message): JSON {"skill": ..., ...}. Un texto que no es JSON en la
puerta de Backstage se trata como mensaje de chat. Respuesta: JSON de la skill.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime
from typing import Any

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.types import AgentCard, AgentSkill

from devsecops_agents import __version__
from devsecops_agents.common.a2a_server import build_agent_card, text_reply
from devsecops_agents.remediation_agent import conversation
from devsecops_agents.remediation_agent.analysis import analyze, rules_explanation
from devsecops_agents.remediation_agent.guidelines import GuidelineClient
from devsecops_agents.remediation_agent.policies import MISMATCH, PolicyReader, verify

log = logging.getLogger(__name__)

CHAT_PORT = 8080
ADVISE_PORT = 8081
CHAT_SKILLS = ("latest-report", "chat", "confirm-action", "cancel-action")


def _skill(sid: str, name: str, desc: str) -> AgentSkill:
    return AgentSkill(id=sid, name=name, description=desc, tags=["devsecops", "remediation"])


def chat_card(public_url: str) -> AgentCard:
    return build_agent_card(
        name="DevSecOps Remediation Agent",
        description="Explica los hallazgos del pipeline con los lineamientos del homelab y "
        "propone correcciones; solo se aplican con la confirmación de una persona.",
        version=__version__,
        public_url=public_url,
        skills=[
            _skill("latest-report", "Último informe", "Informe del último análisis del pipeline."),
            _skill("chat", "Chat", "Conversa sobre los hallazgos y prepara correcciones."),
            _skill("confirm-action", "Confirmar acción", "Aplica una acción pendiente (persona)."),
            _skill("cancel-action", "Cancelar acción", "Descarta una acción pendiente."),
        ],
    )


def advise_card(public_url: str) -> AgentCard:
    return build_agent_card(
        name="DevSecOps Remediation Agent (pipeline)",
        description="Recibe los resultados de Trivy y el Containerfile y devuelve el informe.",
        version=__version__,
        public_url=public_url,
        skills=[_skill("advise", "Analizar", "Recomendaciones priorizadas con su lineamiento.")],
    )


class RemediationAgent:
    """Lógica compartida por las dos puertas (un solo estado en memoria)."""

    def __init__(
        self, guidelines: GuidelineClient | None = None, policies: PolicyReader | None = None
    ) -> None:
        self.state = conversation.State()
        self.guidelines = guidelines or GuidelineClient()
        self.policies = policies or PolicyReader()
        self.repo = os.getenv("REMEDIATION_REPO", "")

    def advise(self, req: dict[str, Any]) -> dict[str, Any]:
        containerfile = str(req.get("containerfile", ""))
        result = analyze(
            list(req.get("trivy") or []),
            containerfile,
            image=str(req.get("image", "")),
            containerfile_path=str(req.get("containerfile_path", "Containerfile")),
        )
        missing, poisoned = [], []
        for rec in result.recommendations:
            if rec.guideline_entity:
                catalog = self.guidelines.get(rec.guideline_entity)
                if catalog is None:
                    missing.append(rec.guideline_entity)
                # El catálogo se contrasta con la política que Kyverno aplica (Acto 5).
                rec.guideline = verify(rec.guideline_entity, catalog, self.policies)
                if rec.guideline and rec.guideline.get("integrity") == MISMATCH:
                    poisoned.append(rec.guideline["id"])
                    rec.detail = f"{rec.guideline['warning']} {rec.detail}"
        explanation = rules_explanation(result)
        if poisoned:
            explanation = (
                f"⚠ Posible envenenamiento de lineamientos: {', '.join(sorted(set(poisoned)))} "
                "no coincide con la política vigente; uso la política. " + explanation
            )
        if missing:
            explanation += f" (No pude leer del catálogo: {', '.join(sorted(set(missing)))}.)"
        report = {
            "pipeline_run": str(req.get("pipeline_run", "manual")),
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "image": result.image,
            "summary": result.summary,
            "recommendations": [r.as_dict() for r in result.recommendations],
            "explanation": explanation,
            "engine": "rules",
        }
        # Un informe nuevo invalida las acciones preparadas sobre el anterior.
        self.state.report, self.state.analysis, self.state.containerfile = (
            report,
            result,
            containerfile,
        )
        self.state.actions.clear()
        log.info(
            "informe %s: %d recomendaciones, sin leer: %s, envenenados: %s",
            report["pipeline_run"],
            len(report["recommendations"]),
            missing or "ninguno",
            poisoned or "ninguno",
        )
        return report

    def handle_chat_port(self, context_id: str, raw: str) -> dict[str, Any]:
        try:
            req = json.loads(raw)
            if not isinstance(req, dict):
                raise ValueError
        except ValueError:
            req = {"skill": "chat", "message": raw}
        skill = req.get("skill")
        if skill == "latest-report":
            return {"report": self.state.report}
        if skill == "chat":
            return conversation.chat(self.state, context_id, str(req.get("message", "")), self.repo)
        if skill == "confirm-action":
            return conversation.confirm(self.state, context_id, str(req.get("action_id", "")))
        if skill == "cancel-action":
            return conversation.cancel(self.state, context_id, str(req.get("action_id", "")))
        return {
            "error": f"skill no soportada en esta puerta: {skill!r}; usa {', '.join(CHAT_SKILLS)}"
        }

    def handle_advise_port(self, raw: str) -> dict[str, Any]:
        try:
            req = json.loads(raw)
        except ValueError:
            return {"error": "advise espera JSON"}
        if not isinstance(req, dict) or req.get("skill") != "advise":
            return {"error": "esta puerta solo acepta la skill advise"}
        return self.advise(req)


class _Executor(AgentExecutor):
    def __init__(self, agent: RemediationAgent, *, advise_port: bool) -> None:
        self._agent = agent
        self._advise = advise_port

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        raw = context.get_user_input() or ""
        if self._advise:
            result = self._agent.handle_advise_port(raw)
        else:
            result = self._agent.handle_chat_port(context.context_id or "", raw)
        await event_queue.enqueue_event(text_reply(context, json.dumps(result, ensure_ascii=False)))

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise NotImplementedError("las skills son síncronas; no hay nada que cancelar")


def chat_executor(agent: RemediationAgent) -> AgentExecutor:
    return _Executor(agent, advise_port=False)


def advise_executor(agent: RemediationAgent) -> AgentExecutor:
    return _Executor(agent, advise_port=True)
