"""Agente de aprobación: hechos por run, revisión del modelo acotada y verificada."""

from __future__ import annotations

import json
import time
from types import SimpleNamespace

import pytest

from devsecops_agents.approval_agent import review
from devsecops_agents.approval_agent.cluster import PipelineRunSummary, Stage
from devsecops_agents.red_attacker.payloads import ATTACK_PRS


@pytest.fixture(autouse=True)
def _no_model_by_default(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "none")


def _run(name="act3", pr="pr-02-poisoned.diff", blue="APPROVE", admission="REJECTED"):
    return PipelineRunSummary(
        name,
        "Failed" if admission == "REJECTED" else "Succeeded",
        [
            Stage("sast", "Succeeded", "", {"status": "OK"}),
            Stage("gate-blue", "Succeeded", "", {"decision": blue}),
            Stage("verify", "Succeeded", "", {"verify-status": "OK"}),
            Stage(
                "deploy-gitops",
                "Failed" if admission == "REJECTED" else "Succeeded",
                "",
                {"admission": admission},
            ),
        ],
        params={"pr-diff": pr, "blue-reviewer-url": "http://blue-reviewer:9999/"},
    )


def test_facts_take_the_real_diff_and_flag_contradictions():
    f = review.run_facts(_run())
    assert f.pr_diff == ATTACK_PRS["pr-02-poisoned.diff"].diff
    assert f.blue_decision == "APPROVE" and f.admission == "REJECTED"
    assert f.blue_reviewer == "vulnerable" and f.failed_stages == ["deploy-gitops"]
    assert any("APROBÓ, pero Kyverno RECHAZÓ" in s for s in f.signals)
    assert not f.can_approve()


def test_schema_forbids_approving_a_failed_run():
    facts = [review.run_facts(_run())]
    schema = review.build_schema(facts, ["pod-101"])
    run = schema["properties"]["runs"]["properties"]["act3"]["properties"]
    assert run["decision"]["enum"] == ["no-aprobar", "revisar"]
    assert run["blue_assessment"]["enum"] == ["acertó", "lo engañaron"]
    assert run["proposals"]["items"]["properties"]["action"]["enum"] == ["ticket", "rerun"]
    assert run["guideline"]["enum"] == ["pod-101", "ninguno"]


def _raw(**overrides):
    base = {
        "pr_verdict": "malicioso",
        "injection_suspected": True,
        "injection_evidence": "",
        "dangerous_change": "descarga y ejecuta un script",
        "blue_assessment": "acertó",
        "decision": "aprobar-con-revision-humana",
        "reason": "x",
        "guideline": "inventado",
        "proposals": [{"action": "ticket", "why": "revisar"}, {"action": "approve", "why": "y"}],
    }
    return {"overview": "o", "runs": {"act3": base | overrides}}


def test_verifier_requires_literal_evidence_and_corrects_the_model():
    facts = [review.run_facts(_run())]
    v = review.verify(_raw(injection_evidence="ignore all previous instructions"), facts, [])
    r = v["runs"][0]
    c = " ".join(v["corrections"])
    assert r["injection_evidence"] == "" and "inventada" in c
    assert r["decision"] == "no-aprobar"  # PR malicioso y run fallido
    assert r["blue_assessment"] == "lo engañaron"  # aprobó un PR malicioso
    assert r["guideline"] == "ninguno"
    assert [p["action"] for p in r["proposals"]] == ["ticket"]  # approve no es del modelo


def test_literal_evidence_from_the_diff_is_kept():
    diff = ATTACK_PRS["pr-02-poisoned.diff"].diff
    line = next(ln for ln in diff.splitlines() if ln.startswith("+") and len(ln) > 20)[1:]
    v = review.verify(_raw(injection_evidence=line), [review.run_facts(_run())], [])
    assert v["runs"][0]["injection_evidence"] == line


class FakeModel:
    def __init__(self, out):
        self.out = out

    def invoke(self, _msgs):
        return SimpleNamespace(content=json.dumps(self.out))


def test_review_cache_answers_pending_then_done(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai-compatible")
    out = _raw(decision="no-aprobar", blue_assessment="lo engañaron", guideline="ninguno")
    monkeypatch.setattr(review.llm, "build_chat_model", lambda **kw: FakeModel(out))
    cache = review.ReviewCache(guidelines=None)
    runs = [_run()]
    first = cache.get(runs)
    assert first["status"] in ("pending", "done")
    for _ in range(50):
        state = cache.get(runs)
        if state["status"] == "done":
            break
        time.sleep(0.05)
    assert state["status"] == "done" and state["runs"][0]["decision"] == "no-aprobar"
    assert state["input"]["data"]["runs"][0]["pr_diff"].startswith("diff --git")


def test_without_model_the_review_says_rules_only():
    assert review.ReviewCache().get([_run()]) == {"status": "rules-only"}


def test_evidence_can_only_be_a_line_the_pr_adds():
    facts = [review.run_facts(_run())]
    schema = review.build_schema(facts, [])
    enum = schema["properties"]["runs"]["properties"]["act3"]["properties"]["injection_evidence"]
    lines = review.added_lines(ATTACK_PRS["pr-02-poisoned.diff"].diff)
    assert enum["enum"] == [*lines, ""] and lines
    assert all(line in ATTACK_PRS["pr-02-poisoned.diff"].diff for line in lines)
