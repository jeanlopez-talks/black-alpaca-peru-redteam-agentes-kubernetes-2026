#!/usr/bin/env python3
"""
TOOLS del agente DevSecOps (human-in-the-loop).

Dos familias de tools, separadas A PROPOSITO por su poder:

  LECTURA (seguras, el agente las usa libremente):
    - read_pipelineruns()  : lee los PipelineRun/TaskRun de Tekton de openclaw-duel
                             y resume cada etapa (sast/build/sbom/trivy/sign/gate/
                             verify/deploy) con su estado y por que paso/fallo.
    - read_argocd_apps()   : lee las Application de Argo CD y su sync/health.

  ACCION (PELIGROSAS, NUNCA se ejecutan sin confirmacion humana):
    - propose_actions()    : a partir del estado, PROPONE acciones (re-run,
                             aprobar-con-anotacion, abrir-ticket). Solo texto:
                             NO toca el cluster.
    - execute_action()     : EJECUTA una propuesta. Exige un token humano valido
                             (HUMAN_APPROVAL_TOKEN). Es el unico punto donde el
                             agente actua, y SOLO tras el gate humano.

DISENO CLAVE DE LA CHARLA (mitigacion): el agente PROPONE pero NO ACTUA sin un
humano. execute_action() valida el token humano ANTES de hacer nada; sin el,
rechaza. Esto modela el human-in-the-loop del duelo: la accion mas peligrosa
—poner la anotacion duel.redteam/human-approved que Kyverno exige— la
desencadena un humano, nunca el agente por su cuenta. Un agente con poder de
accion es el riesgo central; este gate es la mitigacion.

ACCESO AL CLUSTER: el agente llama al API de Kubernetes con el token de su
ServiceAccount (de SOLO LECTURA para Tekton/Argo CD; sin RBAC de escritura). Si
no hay token montado o kubernetes no esta instalado, cae a DATOS DE EJEMPLO para
que la demo (y los tests) funcionen sin cluster. Nunca inventa resultados reales:
marca is_mock=True cuando usa el fallback.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

# Orden canonico de las etapas del pipeline DevSecOps del duelo (para resumir).
PIPELINE_STAGES = [
    "sast", "build", "sbom", "trivy-scan", "sign", "gate-blue", "verify", "deploy-gitops",
]

# Namespace donde corre el pipeline del duelo (parametrizable por entorno).
DUEL_NAMESPACE = os.getenv("DUEL_NAMESPACE", "openclaw-duel")


@dataclass
class StageSummary:
    """Resumen de una etapa del pipeline: estado y motivo legible."""
    name: str
    status: str            # Succeeded | Failed | Running | Skipped | Unknown
    reason: str = ""


@dataclass
class PipelineSummary:
    """Resumen de un PipelineRun completo."""
    name: str
    overall: str
    stages: list[StageSummary] = field(default_factory=list)
    is_mock: bool = False


def _k8s_client() -> Any | None:
    """Carga el cliente de Kubernetes usando el token de la SA del pod.

    Devuelve None si la libreria no esta o no hay config in-cluster (fuera del
    cluster, en tests): el llamador cae a datos de ejemplo.
    """
    try:
        from kubernetes import client, config
    except ImportError:
        return None
    try:
        config.load_incluster_config()
    except Exception:
        try:
            config.load_kube_config()
        except Exception:
            return None
    return client


def read_pipelineruns() -> list[PipelineSummary]:
    """Lee los PipelineRun de Tekton de openclaw-duel y los resume por etapa.

    TOOL DE LECTURA (segura). Sin cluster, devuelve un ejemplo representativo del
    duelo (gate aprueba pero deploy lo frena Kyverno) marcado is_mock=True.
    """
    client = _k8s_client()
    if client is None:
        return [_mock_pipeline()]

    try:
        api = client.CustomObjectsApi()
        runs = api.list_namespaced_custom_object(
            group="tekton.dev", version="v1", namespace=DUEL_NAMESPACE,
            plural="pipelineruns",
        )
    except Exception:
        return [_mock_pipeline()]

    summaries: list[PipelineSummary] = []
    for item in runs.get("items", []):
        name = item.get("metadata", {}).get("name", "desconocido")
        status = item.get("status", {})
        conds = status.get("conditions", [{}])
        overall = conds[0].get("reason", "Unknown") if conds else "Unknown"
        stages: list[StageSummary] = []
        # childReferences / taskRuns dan el estado por task; se mapea a etapas.
        for child in status.get("childReferences", []):
            tname = child.get("pipelineTaskName", child.get("name", "?"))
            stages.append(StageSummary(name=tname, status="see-taskrun"))
        summaries.append(PipelineSummary(name=name, overall=overall, stages=stages))
    return summaries or [_mock_pipeline()]


def read_argocd_apps() -> list[dict[str, Any]]:
    """Lee las Application de Argo CD (ns argocd) y su sync/health.

    TOOL DE LECTURA (segura). Sin cluster, devuelve un ejemplo (is_mock=True).
    """
    client = _k8s_client()
    if client is None:
        return [_mock_argocd_app()]
    try:
        api = client.CustomObjectsApi()
        apps = api.list_namespaced_custom_object(
            group="argoproj.io", version="v1alpha1", namespace="argocd",
            plural="applications",
        )
    except Exception:
        return [_mock_argocd_app()]

    out: list[dict[str, Any]] = []
    for item in apps.get("items", []):
        st = item.get("status", {})
        out.append({
            "name": item.get("metadata", {}).get("name", "?"),
            "sync": st.get("sync", {}).get("status", "Unknown"),
            "health": st.get("health", {}).get("status", "Unknown"),
            "is_mock": False,
        })
    return out or [_mock_argocd_app()]


def propose_actions(summaries: list[PipelineSummary]) -> list[dict[str, Any]]:
    """A partir del estado, PROPONE acciones. NO ejecuta nada (solo texto).

    Cada propuesta lleva: id, titulo, por que, y 'danger' (si cambia el cluster).
    El humano decide cual confirmar. Reglas simples y explicables (la charla valora
    la transparencia por encima de la "inteligencia"):
      - si una etapa fallo  -> proponer re-run del pipeline.
      - si gate aprobo pero deploy esta bloqueado (Kyverno) -> proponer
        aprobar-con-anotacion (REVISION HUMANA) o abrir ticket.
    """
    proposals: list[dict[str, Any]] = []
    for s in summaries:
        failed = [st for st in s.stages if st.status == "Failed"]
        if failed or s.overall in ("Failed", "PipelineRunTimeout"):
            proposals.append({
                "id": f"rerun:{s.name}",
                "title": f"Re-ejecutar el pipeline {s.name}",
                "why": "Hay etapas fallidas; re-correr tras corregir la causa.",
                "danger": "media",  # crea un PipelineRun nuevo
            })
        # El caso central del duelo: el deploy lo frena Kyverno por falta de la
        # anotacion humana. Proponer aprobar CON REVISION (no automatico).
        proposals.append({
            "id": f"approve:{s.name}",
            "title": "Aprobar el deploy con revision humana",
            "why": (
                "Pone la anotacion duel.redteam/human-approved=true que Kyverno "
                "exige. SOLO tras revision humana real del PR: el agente la PROPONE, "
                "el humano la confirma. Es la mitigacion clave de la charla."
            ),
            "danger": "alta",  # desbloquea un deploy real
        })
        proposals.append({
            "id": f"ticket:{s.name}",
            "title": "Abrir un ticket de revision",
            "why": "Si no hay confianza para aprobar, escalar a revision formal.",
            "danger": "baja",
        })
    return proposals


class HumanApprovalRequired(Exception):
    """Se lanza cuando se intenta ejecutar una accion sin el token humano valido."""


def execute_action(action_id: str, human_token: str | None) -> dict[str, Any]:
    """EJECUTA una propuesta. EXIGE token humano valido ANTES de hacer nada.

    ===================================================================
    HUMAN-IN-THE-LOOP (LA MITIGACION): este es el UNICO punto donde el agente
    puede cambiar algo. La primera linea valida el token humano; si falta o no
    coincide con HUMAN_APPROVAL_TOKEN, se RECHAZA y no se toca el cluster. El
    agente nunca llega aqui por su cuenta: lo dispara un humano desde Backstage
    pasando su token. Un agente con poder de accion es el riesgo; este gate es
    la defensa.
    ===================================================================
    """
    expected = os.getenv("HUMAN_APPROVAL_TOKEN", "")
    # GATE HUMANO: sin token valido no se ejecuta NADA. Mitigacion central.
    if not expected or not human_token or human_token != expected:
        raise HumanApprovalRequired(
            "Accion RECHAZADA: requiere aprobacion humana. El agente propone pero "
            "no actua solo. Pasa un token humano valido (HUMAN_APPROVAL_TOKEN) para "
            "confirmar. (Esta es la mitigacion human-in-the-loop de la charla.)"
        )

    kind, _, target = action_id.partition(":")
    # NOTA de honestidad: en esta demo la ejecucion real (crear PipelineRun, hacer
    # el commit con la anotacion al repo GitOps, abrir el ticket) la hace el
    # operador/pipeline con credenciales propias. El agente NO tiene RBAC de
    # escritura ni credenciales de git a proposito (misma frontera que duel-runner).
    # Aqui se devuelve la intencion confirmada; el efecto lo materializa el humano.
    return {
        "executed": True,
        "action": kind,
        "target": target,
        "note": (
            "Confirmado por humano. El efecto real lo aplica el operador/pipeline "
            "con sus credenciales (el agente no tiene RBAC de escritura). Para "
            "'approve', el humano añade duel.redteam/human-approved=true al "
            "manifiesto en git y Argo CD lo sincroniza; recien ahi Kyverno deja pasar."
        ),
    }


# --------------------------- DATOS DE EJEMPLO -------------------------------
# Representan el escenario del duelo para demo/tests SIN cluster. is_mock=True.

def _mock_pipeline() -> PipelineSummary:
    return PipelineSummary(
        name="duel-devsecops-run-demo",
        overall="Completed",
        is_mock=True,
        stages=[
            StageSummary("sast", "Succeeded", "semgrep/gitleaks informativo: sin hallazgos bloqueantes"),
            StageSummary("build", "Succeeded", "kaniko construyo la imagen (tar, sin registry)"),
            StageSummary("sbom", "Succeeded", "syft genero CycloneDX + SPDX"),
            StageSummary("trivy-scan", "Succeeded", "sin HIGH/CRITICAL bloqueantes"),
            StageSummary("sign", "Succeeded", "cosign firmo el blob del tar"),
            StageSummary("gate-blue", "Succeeded", "el agente azul APROBO el PR (enganado por el PR envenenado)"),
            StageSummary("verify", "Succeeded", "cosign verifico la firma (valida: el ataque solo toca config)"),
            StageSummary("deploy-gitops", "Failed", "RECHAZADO por Kyverno: falta duel.redteam/human-approved"),
        ],
    )


def _mock_argocd_app() -> dict[str, Any]:
    return {
        "name": "ai-red-vs-blue-devsecops-sample-app",
        "sync": "OutOfSync",
        "health": "Degraded",
        "is_mock": True,
    }
