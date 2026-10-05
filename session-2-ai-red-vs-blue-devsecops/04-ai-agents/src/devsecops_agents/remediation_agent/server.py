"""Agente de remediación como servidor A2A, con dos puertas separadas por red.

  :8080  Backstage (chat con la persona): latest-report, chat, confirm-action, cancel-action
  :8081  pipeline (etapa `remediation`):   advise

El pipeline corre en `devsecops-duel`, donde se ejecuta código no confiable del PR: por
eso solo alcanza la puerta de `advise` (NetworkPolicy) y nunca la de confirmar acciones.

Petición (texto del Message): JSON {"skill": ..., ...}. Un texto que no es JSON en la
puerta de Backstage se trata como mensaje de chat. Respuesta: JSON de la skill.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from datetime import UTC, datetime
from typing import Any

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.types import AgentCard, AgentSkill

from devsecops_agents import __version__
from devsecops_agents.common import llm
from devsecops_agents.common.a2a_server import build_agent_card, text_reply
from devsecops_agents.common.backstage_mcp import GuidelineClient
from devsecops_agents.remediation_agent import conversation, llm_analysis
from devsecops_agents.remediation_agent.analysis import Analysis, analyze, rules_explanation
from devsecops_agents.remediation_agent.facts import image_facts
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


def _dicts(value: Any) -> list[dict[str, Any]]:
    return [x for x in value if isinstance(x, dict)] if isinstance(value, list) else []


def _clean_trivy(raw: Any) -> list[dict[str, Any]]:
    """La forma de los informes de Trivy, garantizada una sola vez a la entrada: listas de
    objetos donde se esperan. Lo demás se descarta (la puerta acepta cualquier JSON)."""
    reports = []
    for report in _dicts(raw):
        results = []
        for result in _dicts(report.get("Results")):
            results.append(
                {
                    **result,
                    "Vulnerabilities": _dicts(result.get("Vulnerabilities")),
                    "Misconfigurations": _dicts(result.get("Misconfigurations")),
                    "Packages": _dicts(result.get("Packages")),
                }
            )
        meta = report.get("Metadata")
        reports.append(
            {**report, "Results": results, "Metadata": meta if isinstance(meta, dict) else {}}
        )
    return reports


class RemediationAgent:
    """Lógica compartida por las dos puertas (un solo estado en memoria)."""

    def __init__(
        self, guidelines: GuidelineClient | None = None, policies: PolicyReader | None = None
    ) -> None:
        self.state = conversation.State()
        self.guidelines = guidelines or GuidelineClient()
        self.policies = policies or PolicyReader()
        self.repo = os.getenv("REMEDIATION_REPO", "")
        # Cada advise abre una "generación"; el análisis del modelo solo se publica si
        # sigue siendo la última (si no, llegó otro PipelineRun mientras pensaba).
        self._lock = threading.Lock()
        self._generation = 0
        # Generación vigente de cada corrida y corrida de cada generación.
        self._run_generation: dict[str, int] = {}
        self._model_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="model")

    def _attach_guidelines(self, recs: list[Any]) -> tuple[list[str], list[str]]:
        """Lineamiento de cada recomendación, contrastado con la política de Kyverno."""
        missing, poisoned = [], []
        for rec in recs:
            if rec.guideline_entity:
                catalog = self.guidelines.get(rec.guideline_entity)
                if catalog is None:
                    missing.append(rec.guideline_entity)
                # El catálogo se contrasta con la política que Kyverno aplica (Acto 5).
                rec.guideline = verify(rec.guideline_entity, catalog, self.policies)
                if rec.guideline and rec.guideline.get("integrity") == MISMATCH:
                    poisoned.append(rec.guideline["id"])
                    rec.detail = f"{rec.guideline['warning']} {rec.detail}"
        return missing, poisoned

    @staticmethod
    def _with_warnings(explanation: str, missing: list[str], poisoned: list[str]) -> str:
        if poisoned:
            explanation = (
                f"⚠ Posible envenenamiento de lineamientos: {', '.join(sorted(set(poisoned)))} "
                "no coincide con la política vigente; uso la política. " + explanation
            )
        if missing:
            explanation += f" (No pude leer del catálogo: {', '.join(sorted(set(missing)))}.)"
        return explanation

    def advise(self, req: dict[str, Any]) -> dict[str, Any]:
        # Lo envía la etapa del pipeline, donde corre código del PR: se acepta solo lo que
        # tiene la forma esperada, sin lanzar excepciones por una entrada mal formada.
        raw_cf = req.get("containerfile", "")
        containerfile = raw_cf if isinstance(raw_cf, str) else ""
        trivy = _clean_trivy(req.get("trivy"))
        vulnerable = [
            v.get("PkgName", "")
            for r in trivy
            for res in r.get("Results") or []
            for v in res.get("Vulnerabilities") or []
        ]
        facts = image_facts(trivy, containerfile, vulnerable)
        result = analyze(
            trivy,
            containerfile,
            image=str(req.get("image", "")),
            containerfile_path=str(req.get("containerfile_path", "Containerfile")),
            facts=facts,
        )
        missing, poisoned = self._attach_guidelines(result.recommendations)
        use_model = llm.llm_configured() and not req.get("rules_only")
        report = {
            "pipeline_run": str(req.get("pipeline_run", "manual")),
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "image": result.image,
            "target": {
                **result.target,
                # Lo que el escaneo NO mira: severidades fuera del filtro no aparecen.
                "severity_filter": str(req.get("severity_filter", "")),
            },
            "facts": facts,
            "vulnerabilities": [asdict(v) for v in result.vulnerabilities],
            "summary": result.summary,
            "recommendations": [r.as_dict() for r in result.recommendations],
            "explanation": self._with_warnings(rules_explanation(result), missing, poisoned),
            "engine": "rules",
            # El modelo analiza en segundo plano; la etapa del pipeline no lo espera.
            "analysis_status": "pending" if use_model else "rules-only",
            "llm": None,
        }
        run = report["pipeline_run"]
        with self._lock:
            self._generation += 1
            generation = self._generation
            self._run_generation[run] = generation
            # La corrida pasa a ser la más reciente del historial (se guardan MAX_RUNS).
            self.state.runs.pop(run, None)
            self.state.runs[run] = conversation.RunState(report, result, containerfile)
            while len(self.state.runs) > conversation.MAX_RUNS:
                self.state.runs.pop(next(iter(self.state.runs)))
            self.state.report, self.state.analysis, self.state.containerfile = (
                report,
                result,
                containerfile,
            )
            # Un análisis nuevo de ESTA corrida invalida sus acciones preparadas; las de
            # otras corridas siguen valiendo.
            for action_id in [a for a, x in self.state.actions.items() if x.run == run]:
                self.state.actions.pop(action_id)
        log.info(
            "informe %s (reglas): %d recomendaciones, sin leer: %s, envenenados: %s",
            report["pipeline_run"],
            len(report["recommendations"]),
            missing or "ninguno",
            poisoned or "ninguno",
        )
        # Copia antes de lanzar el modelo: el pipeline recibe el informe de reglas tal
        # cual, aunque el modelo lo sustituya después en memoria.
        snapshot = copy.deepcopy(report)
        if use_model:
            # Un análisis del modelo a la vez, en cola: si llegan varias corridas seguidas,
            # se analizan todas (una tras otra). Solo se descarta el de una corrida que se
            # vuelve a analizar antes de que le toque (ver _analyze_with_model).
            self._model_pool.submit(
                self._analyze_with_model, generation, run, result, facts, containerfile
            )
        return snapshot

    def _analyze_with_model(
        self,
        generation: int,
        run: str,
        result: Analysis,
        facts: dict[str, Any],
        containerfile: str,
    ) -> None:
        """El análisis del modelo, verificado. Sustituye al de reglas si sigue vigente.

        El informe se SUSTITUYE (dict nuevo), nunca se modifica: quien lo esté leyendo
        (chat, latest-report) sigue con una versión entera y coherente.
        """
        with self._lock:
            if self._run_generation.get(run) != generation:
                return  # esta corrida se volvió a analizar: este resultado ya no vale
        try:
            verified = llm_analysis.run(result, facts, containerfile, self.guidelines)
            recs = llm_analysis.to_recommendations(verified, result)
            if not recs:
                raise ValueError("el modelo no dejó ninguna prioridad verificable")
        except Exception as exc:  # noqa: BLE001 - sin modelo, queda el análisis por reglas
            log.warning("el modelo no pudo analizar: %s", exc)
            with self._lock:
                current = self.state.runs.get(run)
                if self._run_generation.get(run) == generation and current:
                    failed = {
                        **current.report,
                        "analysis_status": "failed",
                        "llm_error": str(exc)[:300],
                    }
                    self._publish(run, failed, current.analysis)
            return
        missing, poisoned = self._attach_guidelines(recs)
        model_result = replace(result, recommendations=recs)
        with self._lock:
            current = self.state.runs.get(run)
            if self._run_generation.get(run) != generation or current is None:
                return  # la corrida se volvió a analizar (o salió del historial)
            report = {
                **current.report,
                "recommendations": [r.as_dict() for r in recs],
                "explanation": self._with_warnings(verified["overview"], missing, poisoned),
                "engine": "llm",
                "analysis_status": "done",
                "llm": {k: v for k, v in verified.items() if k != "patch"}
                | {"patch": {k: v for k, v in verified["patch"].items() if k != "patched"}},
            }
            self._publish(run, report, model_result)
            # Las acciones pendientes NO se borran: la persona puede tener una en pantalla
            # y sigue siendo válida (lleva su propio diff, del mismo PipelineRun).
        log.info(
            "informe %s (modelo %s, %.0f s): %d prioridades, %d correcciones del verificador",
            report["pipeline_run"],
            verified.get("model"),
            verified.get("duration_s", 0),
            len(recs),
            len(verified["corrections"]),
        )

    def _publish(self, run: str, report: dict[str, Any], analysis: Analysis) -> None:
        """Sustituye el informe de una corrida (con el lock tomado). Si es la última,
        también pasa a ser el de por defecto."""
        current = self.state.runs[run]
        self.state.runs[run] = conversation.RunState(report, analysis, current.containerfile)
        if (self.state.report or {}).get("pipeline_run") == run:
            self.state.report, self.state.analysis = report, analysis

    def _run_list(self) -> list[dict[str, Any]]:
        """Corridas del historial, de la más reciente a la más antigua (lo que lista Backstage)."""
        return [
            {
                "pipeline_run": name,
                "generated_at": r.report.get("generated_at", ""),
                "engine": r.report.get("engine", ""),
                "analysis_status": r.report.get("analysis_status", ""),
                "vulnerabilities": r.report.get("summary", {})
                .get("vulnerabilities", {})
                .get("total", 0),
                "recommendations": len(r.report.get("recommendations", [])),
            }
            for name, r in reversed(self.state.runs.items())
        ]

    def handle_chat_port(self, context_id: str, raw: str) -> dict[str, Any]:
        try:
            req = json.loads(raw)
            if not isinstance(req, dict):
                raise ValueError
        except ValueError:
            req = {"skill": "chat", "message": raw}
        skill = req.get("skill")
        if skill == "latest-report":
            with self._lock:  # el hilo del modelo puede estar sustituyéndolo
                chosen = self.state.runs.get(str(req.get("pipeline_run") or ""))
                report = chosen.report if chosen else self.state.report
                return {"report": copy.deepcopy(report), "runs": self._run_list()}
        if skill == "chat":
            view = conversation.for_run(self.state, str(req.get("pipeline_run") or ""))
            return conversation.chat(view, context_id, str(req.get("message", "")), self.repo)
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
