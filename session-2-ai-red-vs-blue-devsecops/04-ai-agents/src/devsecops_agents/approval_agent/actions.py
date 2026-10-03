"""Propuestas de acción y la puerta humana que las ejecuta.

El agente PROPONE (texto, sin efectos). Solo `execute_action` actúa, y antes de nada
valida el token humano en tiempo constante. Aun confirmada, el agente no tiene RBAC de
escritura ni credenciales de Git: devuelve la intención confirmada y el efecto real lo
aplica el humano (p. ej. añadiendo la anotación de aprobación en Git).
"""

from __future__ import annotations

import hmac
import os
from dataclasses import asdict, dataclass

from devsecops_agents.approval_agent.cluster import PipelineRunSummary

ACTION_KINDS = ("rerun", "approve", "ticket")


class HumanApprovalRequiredError(PermissionError):
    """Se intentó ejecutar una acción sin un token humano válido."""


@dataclass(frozen=True)
class Proposal:
    id: str
    title: str
    why: str
    danger: str  # baja | media | alta

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def propose_actions(runs: list[PipelineRunSummary]) -> list[Proposal]:
    proposals: list[Proposal] = []
    for run in runs:
        if run.overall in ("Failed", "PipelineRunTimeout") or any(
            s.status == "Failed" for s in run.stages
        ):
            proposals.append(
                Proposal(
                    f"rerun:{run.name}",
                    f"Re-ejecutar el pipeline {run.name}",
                    "Hay etapas fallidas: re-correr tras corregir la causa.",
                    "media",
                )
            )
        proposals.append(
            Proposal(
                f"approve:{run.name}",
                "Aprobar el deploy con revisión humana",
                "Añadir duel.redteam/human-approved=true, que exige Kyverno, SOLO tras revisar "
                "el diff real (no este resumen).",
                "alta",
            )
        )
        proposals.append(
            Proposal(
                f"ticket:{run.name}",
                "Abrir un ticket de revisión",
                "Si no hay confianza para aprobar, escalar a revisión formal.",
                "baja",
            )
        )
    return proposals


def execute_action(action_id: str, human_token: str) -> dict[str, str]:
    expected = os.getenv("HUMAN_APPROVAL_TOKEN", "")
    # compare_digest: comparación en tiempo constante (evita timing attacks).
    if not expected or not human_token or not hmac.compare_digest(human_token, expected):
        raise HumanApprovalRequiredError(
            "Acción rechazada: requiere el token de un humano. El agente propone; no actúa solo."
        )
    kind, _, target = action_id.partition(":")
    if kind not in ACTION_KINDS or not target:
        raise ValueError(f"acción desconocida '{action_id}'")
    return {
        "executed": "true",
        "action": kind,
        "target": target,
        "note": "Confirmado por un humano. El efecto real lo aplica el humano con sus "
        "credenciales: el agente no tiene RBAC de escritura ni acceso a Git.",
    }
