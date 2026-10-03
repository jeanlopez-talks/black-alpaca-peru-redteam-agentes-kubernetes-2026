#!/usr/bin/env python3
"""
Agente DevSecOps (human-in-the-loop) — nucleo de razonamiento.

Usa el LLM local (vLLM qwen3-8b) via LangChain/langgraph para REDACTAR en lenguaje
natural el resumen de cada etapa del pipeline y la explicacion del por que se
aprobo/rechazo. Las TOOLS de lectura (tools.py) le dan el estado real; el LLM solo
explica, no decide acciones peligrosas.

MODO PLANTILLA (fallback): si langgraph/langchain-openai no estan o el LLM no
responde, el agente genera el resumen/explicacion con plantillas deterministas a
partir del mismo estado. Asi la demo nunca depende de que el LLM este arriba, y
los tests corren sin red. Nunca se inventan datos: el estado viene de las tools.

IMPORTANTE: el agente NO tiene una tool que ejecute acciones. execute_action vive
en tools.py pero NO se expone al LLM como herramienta: solo la invoca el endpoint
/approve del servidor tras validar el token humano. El LLM jamas puede, por si
mismo, disparar una accion sobre el cluster. Human-in-the-loop por diseno.
"""

from __future__ import annotations

from typing import Any

import llm_factory
import tools


def summarize_pipeline() -> dict[str, Any]:
    """Resume el estado del pipeline (tool de lectura) + explicacion en NL."""
    runs = tools.read_pipelineruns()
    apps = tools.read_argocd_apps()
    explanation = _explain(runs)
    return {
        "pipelineruns": [_run_to_dict(r) for r in runs],
        "argocd_apps": apps,
        "explanation": explanation,
        "is_mock": any(r.is_mock for r in runs),
    }


def propose() -> dict[str, Any]:
    """Devuelve las propuestas de accion (NO ejecuta). Tool propose_actions."""
    runs = tools.read_pipelineruns()
    return {
        "proposals": tools.propose_actions(runs),
        "note": (
            "Son PROPUESTAS. Ninguna se ejecuta sin que un humano la confirme en "
            "/approve con un token valido. El agente propone, el humano decide."
        ),
    }


def _run_to_dict(r: tools.PipelineSummary) -> dict[str, Any]:
    return {
        "name": r.name,
        "overall": r.overall,
        "is_mock": r.is_mock,
        "stages": [{"name": s.name, "status": s.status, "reason": s.reason} for s in r.stages],
    }


def _explain(runs: list[tools.PipelineSummary]) -> str:
    """Explicacion en lenguaje natural. Intenta el LLM local; si no, plantilla."""
    template = _template_explanation(runs)
    if not llm_factory.llm_available():
        return template
    try:
        model = llm_factory.build_chat_model()
        prompt = (
            "Eres un asistente DevSecOps. Resume en espanol, claro y breve, el "
            "estado del pipeline y explica por que se aprobo o rechazo el deploy. "
            "Baston de datos (no inventes nada fuera de esto):\n" + template +
            "\nTermina recordando que cualquier accion requiere aprobacion humana."
        )
        resp = model.invoke(prompt)
        text = getattr(resp, "content", "") or ""
        return text.strip() or template
    except Exception:
        # Si el LLM no responde, la plantilla determinista es suficiente.
        return template


def _template_explanation(runs: list[tools.PipelineSummary]) -> str:
    """Resumen determinista por plantilla (sin LLM). Base de la explicacion."""
    lines: list[str] = []
    for r in runs:
        tag = " [DATOS DE EJEMPLO]" if r.is_mock else ""
        lines.append(f"PipelineRun {r.name} (estado: {r.overall}){tag}:")
        for s in r.stages:
            lines.append(f"  - {s.name}: {s.status}" + (f" — {s.reason}" if s.reason else ""))
        # Narrativa de la charla: firma valida pero admision frena.
        deploy = next((s for s in r.stages if s.name == "deploy-gitops"), None)
        gate = next((s for s in r.stages if s.name == "gate-blue"), None)
        if deploy and gate and gate.status == "Succeeded" and deploy.status == "Failed":
            lines.append(
                "  => El gate del agente azul APROBO, la firma es VALIDA, pero el "
                "DEPLOY lo RECHAZO la admision (Kyverno) por falta de aprobacion "
                "humana. Defensa en capas: la firma no detecta el ataque (solo toca "
                "config), la admision si."
            )
    return "\n".join(lines)
