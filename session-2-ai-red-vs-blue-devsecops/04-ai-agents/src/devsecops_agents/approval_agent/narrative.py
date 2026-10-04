"""Explicación en lenguaje natural del estado del pipeline.

Plantilla determinista a partir de los datos leídos; si hay LLM, este solo la redacta
mejor. El LLM nunca decide acciones ni ve herramientas que actúen.
"""

from __future__ import annotations

import logging

from devsecops_agents.approval_agent.cluster import PipelineRunSummary
from devsecops_agents.common import llm

log = logging.getLogger(__name__)


def template_explanation(runs: list[PipelineRunSummary]) -> str:
    lines: list[str] = []
    for run in runs:
        tag = " [DATOS DE EJEMPLO]" if run.is_mock else ""
        lines.append(f"PipelineRun {run.name} (estado: {run.overall}){tag}:")
        lines.extend(
            f"  - {s.name}: {s.status}" + (f" — {s.reason}" if s.reason else "") for s in run.stages
        )
        stage = {s.name: s.status for s in run.stages}
        if stage.get("gate-blue") == "Succeeded" and stage.get("deploy-gitops") == "Failed":
            lines.append(
                "  => El azul aprobó y la firma es válida, pero la admisión (Kyverno) rechazó "
                "el deploy del agente: falta la aprobación humana y, aunque la falsifique, "
                "solo se admite lo que llega por GitOps (un commit revisado)."
            )
    return "\n".join(lines)


def explain(runs: list[PipelineRunSummary]) -> str:
    template = template_explanation(runs)
    if not llm.llm_configured():
        return template
    try:
        prompt = (
            "Resume en español, claro y breve, el estado de este pipeline y por qué se "
            "aprobó o rechazó el deploy. Usa SOLO estos datos:\n"
            f"{template}\nRecuerda que cualquier acción requiere aprobación humana."
        )
        return str(llm.build_chat_model().invoke(prompt).content).strip() or template
    except Exception as exc:  # noqa: BLE001 - sin LLM la plantilla basta
        log.info("sin LLM para la explicación (%s); uso la plantilla", exc)
        return template
