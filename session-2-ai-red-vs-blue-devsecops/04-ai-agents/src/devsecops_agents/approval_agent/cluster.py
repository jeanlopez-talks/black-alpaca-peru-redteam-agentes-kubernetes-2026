"""Lectura del estado (solo lectura): PipelineRun/TaskRun del duelo y Application de Argo CD.

  - Tekton: API de Kubernetes con la ServiceAccount del pod. Su Role solo permite
    get/list/watch de pipelineruns y taskruns en el namespace del duelo.
  - Argo CD: API de Argo CD con el token de un ROL DE PROYECTO que solo puede leer las
    Application de su proyecto; el agente no tiene RBAC en el namespace argocd.

Sin clúster (laptop, tests) devuelve un escenario de ejemplo marcado `is_mock=True`.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

DUEL_NAMESPACE = os.getenv("DUEL_NAMESPACE", "devsecops-duel")
ARGOCD_SERVER = os.getenv("ARGOCD_SERVER", "http://argocd-server.argocd.svc.cluster.local")
ARGOCD_PROJECT = os.getenv("ARGOCD_PROJECT", "ai-red-vs-blue-devsecops")


@dataclass
class Stage:
    name: str
    status: str  # Succeeded | Failed | Running | Skipped | Unknown
    reason: str = ""


@dataclass
class PipelineRunSummary:
    name: str
    overall: str
    stages: list[Stage] = field(default_factory=list)
    is_mock: bool = False


def _custom_objects_api() -> Any | None:
    try:
        from kubernetes import client, config

        config.load_incluster_config()
        return client.CustomObjectsApi()
    except Exception as exc:  # noqa: BLE001 - fuera del clúster no hay config
        log.info("sin acceso in-cluster a Kubernetes (%s); datos de ejemplo", exc)
        return None


_STATUS_BY_CONDITION = {"True": "Succeeded", "False": "Failed"}


def _condition(obj: dict[str, Any]) -> tuple[str, str]:
    """Estado normalizado (Succeeded | Failed | Running) y detalle.

    Se usa `status` y no `reason`: el motivo varía según el caso y la versión de Tekton
    (un paso que falla deja `StepFailed`, no `Failed`), y compararlo con un texto fijo
    hacía pasar un deploy rechazado por algo que no había fallado.
    """
    condition = (obj.get("status", {}).get("conditions") or [{}])[0]
    status = _STATUS_BY_CONDITION.get(condition.get("status", ""), "Running")
    detail = ": ".join(p for p in (condition.get("reason", ""), condition.get("message", "")) if p)
    return status, detail


def read_pipelineruns() -> list[PipelineRunSummary]:
    api = _custom_objects_api()
    if api is None:
        return [_mock_pipelinerun()]
    try:
        runs = api.list_namespaced_custom_object("tekton.dev", "v1", DUEL_NAMESPACE, "pipelineruns")
        taskruns = api.list_namespaced_custom_object("tekton.dev", "v1", DUEL_NAMESPACE, "taskruns")
    except Exception as exc:  # noqa: BLE001
        log.warning("no se pudieron leer los PipelineRun (%s); datos de ejemplo", exc)
        return [_mock_pipelinerun()]

    by_name = {tr["metadata"]["name"]: tr for tr in taskruns.get("items", [])}
    summaries = []
    for run in runs.get("items", []):
        overall, _ = _condition(run)
        stages = []
        for child in run.get("status", {}).get("childReferences", []):
            status, message = _condition(by_name.get(child.get("name", ""), {}))
            stages.append(Stage(child.get("pipelineTaskName", "?"), status, message[:200]))
        for skipped in run.get("status", {}).get("skippedTasks", []):
            stages.append(Stage(skipped.get("name", "?"), "Skipped", skipped.get("reason", "")))
        summaries.append(PipelineRunSummary(run["metadata"]["name"], overall, stages))
    return summaries or [_mock_pipelinerun()]


def read_argocd_apps() -> list[dict[str, Any]]:
    token = os.getenv("ARGOCD_TOKEN", "")
    if not token:
        return [_mock_argocd_app()]
    query = urllib.parse.urlencode({"projects": ARGOCD_PROJECT})
    request = urllib.request.Request(  # noqa: S310 - URL interna fija por configuración
        f"{ARGOCD_SERVER}/api/v1/applications?{query}",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310
            apps = json.load(response)
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        log.warning("no se pudo leer Argo CD (%s); datos de ejemplo", exc)
        return [_mock_argocd_app()]
    return [
        {
            "name": item.get("metadata", {}).get("name", "?"),
            "sync": item.get("status", {}).get("sync", {}).get("status", "Unknown"),
            "health": item.get("status", {}).get("health", {}).get("status", "Unknown"),
            "is_mock": False,
        }
        for item in apps.get("items") or []
    ] or [_mock_argocd_app()]


def _mock_pipelinerun() -> PipelineRunSummary:
    """Escenario del duelo: el azul aprueba, la firma es válida, Kyverno frena el deploy."""
    stages = [
        Stage("sast", "Succeeded", "semgrep/gitleaks informativo, sin hallazgos bloqueantes"),
        Stage("build", "Succeeded", "kaniko construyó y empujó la imagen a Zot"),
        Stage("sbom", "Succeeded", "Syft generó CycloneDX + SPDX"),
        Stage("trivy-scan", "Succeeded", "sin HIGH/CRITICAL"),
        Stage("sign", "Succeeded", "cosign firmó la imagen por digest"),
        Stage(
            "gate-blue", "Succeeded", "el agente azul APROBÓ el PR (engañado por el PR envenenado)"
        ),
        Stage("verify", "Succeeded", "firma válida: el ataque solo toca config"),
        Stage(
            "deploy-gitops",
            "Failed",
            "RECHAZADO por Kyverno: sin aprobación humana y no viene de GitOps",
        ),
    ]
    return PipelineRunSummary("act3-prompt-injected-pr", "Failed", stages, is_mock=True)


def _mock_argocd_app() -> dict[str, Any]:
    return {
        "name": "ai-red-vs-blue-devsecops-sample-app",
        "sync": "OutOfSync",
        "health": "Degraded",
        "is_mock": True,
    }
