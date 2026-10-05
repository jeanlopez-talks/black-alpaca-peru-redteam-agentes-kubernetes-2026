"""Explicación en lenguaje natural del estado del pipeline.

Plantilla determinista a partir de los datos leídos. El análisis con el modelo (segunda
opinión sobre cada run) está en review.py.
"""

from __future__ import annotations

from devsecops_agents.approval_agent.cluster import PipelineRunSummary


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
