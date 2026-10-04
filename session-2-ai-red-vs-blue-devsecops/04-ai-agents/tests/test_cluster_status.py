"""Normalización del estado de PipelineRun y TaskRun que lee el agente de aprobación."""

from devsecops_agents.approval_agent.cluster import _condition


def _obj(status: str, reason: str, message: str = "") -> dict:
    return {"status": {"conditions": [{"status": status, "reason": reason, "message": message}]}}


def test_step_failed_counts_as_failed() -> None:
    status, detail = _condition(_obj("False", "StepFailed", "denied by Kyverno"))
    assert status == "Failed"
    assert detail == "StepFailed: denied by Kyverno"


def test_completed_counts_as_succeeded() -> None:
    assert _condition(_obj("True", "Completed"))[0] == "Succeeded"


def test_unknown_or_missing_is_running() -> None:
    assert _condition(_obj("Unknown", "Running"))[0] == "Running"
    assert _condition({})[0] == "Running"
