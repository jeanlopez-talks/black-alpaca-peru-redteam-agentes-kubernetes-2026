#!/usr/bin/env python3
"""
Servidor HTTP (FastAPI) del agente DevSecOps — el punto de interaccion
humano <-> pipeline que consume Backstage.

ENDPOINTS:
  GET  /healthz   : liveness/readiness.
  GET  /summary   : resumen del estado del pipeline (etapas) + explicacion en NL
                    + estado de las Application de Argo CD.  (SOLO LECTURA)
  GET  /propose   : propuestas de accion (re-run, aprobar-con-anotacion, ticket).
                    NO ejecuta nada.                          (SOLO LECTURA)
  POST /approve   : EJECUTA una propuesta. EXIGE un token humano en el header
                    'X-Human-Approval'. Sin token valido -> 403. Es el unico
                    endpoint que puede cambiar algo, y solo tras el gate humano.

POR QUE FastAPI (y no MCP): el consumidor es Backstage (un portal web), que
integra APIs HTTP/OpenAPI de forma natural (proxy del backend + tarjetas en el
catalogo). Un servidor MCP encajaria si el consumidor fuera un cliente LLM del
mcp-system; aqui el consumidor es un humano via Backstage, asi que HTTP es el
ajuste correcto. (Decision documentada en README.md.)

HUMAN-IN-THE-LOOP: /summary y /propose son inocuos (lectura/texto). SOLO /approve
actua, y valida el token humano ANTES de nada (execute_action lo revalida: defensa
en profundidad). El agente propone; el humano, desde Backstage, confirma.
"""

from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

import agent
import tools

app = FastAPI(
    title="DevSecOps Agent (human-in-the-loop)",
    description=(
        "Agente que resume el pipeline DevSecOps del duelo y PROPONE acciones. "
        "No ejecuta nada sin aprobacion humana (mitigacion de la charla)."
    ),
    version="0.1.0",
)


class ApproveRequest(BaseModel):
    """Cuerpo de /approve: el id de la propuesta a ejecutar."""
    action_id: str


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/summary")
def summary() -> dict:
    """Resumen del pipeline + Argo CD + explicacion en NL. Solo lectura."""
    return agent.summarize_pipeline()


@app.get("/propose")
def propose() -> dict:
    """Propuestas de accion. NO ejecuta. Solo lectura/texto."""
    return agent.propose()


@app.post("/approve")
def approve(
    req: ApproveRequest,
    x_human_approval: str | None = Header(default=None),
) -> dict:
    """EJECUTA una propuesta. Requiere el header X-Human-Approval con token valido.

    GATE HUMANO: si falta el token o no es valido, execute_action lanza
    HumanApprovalRequired y respondemos 403. El agente nunca actua solo.
    """
    try:
        result = tools.execute_action(req.action_id, x_human_approval)
    except tools.HumanApprovalRequired as exc:
        # 403: la accion existe pero requiere aprobacion humana valida.
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return result


if __name__ == "__main__":
    import os
    import uvicorn

    # host/puerto parametrizables; por defecto escucha en 0.0.0.0:8080 (Service).
    uvicorn.run(
        app,
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8080")),
    )
