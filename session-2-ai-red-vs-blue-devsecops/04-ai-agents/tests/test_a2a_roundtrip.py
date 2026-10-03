"""Comunicación A2A real: servidores uvicorn locales + cliente a2a-sdk."""

import json

import pytest

from devsecops_agents.approval_agent.server import ApprovalExecutor
from devsecops_agents.approval_agent.server import agent_card as approval_card
from devsecops_agents.common import a2a_client
from devsecops_agents.duel import runner


def test_duel_runs_over_a2a():
    report = runner.run_duel("rules")
    assert report["transport"] == "a2a"
    assert report["verdict"] == {
        "act1_blocked": True,
        "attacker_wins_act2": True,
        "contained_act4": True,
    }


@pytest.fixture
def approval_url(monkeypatch):
    monkeypatch.setenv("HUMAN_APPROVAL_TOKEN", "s3cret")
    import threading
    import time

    import uvicorn

    from devsecops_agents.common.a2a_server import build_app

    port = runner._free_port()
    url = f"http://127.0.0.1:{port}/"
    server = uvicorn.Server(
        uvicorn.Config(
            build_app(approval_card(url), ApprovalExecutor()),
            host="127.0.0.1",
            port=port,
            log_level="warning",
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)
    yield url
    server.should_exit = True
    thread.join(timeout=5)


async def _ask(url, payload, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else None
    return json.loads(await a2a_client.send_text(url, json.dumps(payload), headers=headers))


async def test_summary_is_read_only(approval_url):
    reply = await _ask(approval_url, {"skill": "summarize-pipeline"})
    assert reply["pipelineruns"][0]["is_mock"] is True
    assert "Kyverno" in reply["explanation"]


async def test_execute_without_token_is_rejected(approval_url):
    reply = await _ask(approval_url, {"skill": "execute-action", "action_id": "approve:run-1"})
    assert reply["error"] == "human_approval_required"


async def test_execute_with_wrong_token_is_rejected(approval_url):
    reply = await _ask(
        approval_url, {"skill": "execute-action", "action_id": "approve:run-1"}, token="nope"
    )
    assert reply["error"] == "human_approval_required"


async def test_execute_with_human_token(approval_url):
    reply = await _ask(
        approval_url, {"skill": "execute-action", "action_id": "approve:run-1"}, token="s3cret"
    )
    assert reply["executed"] == "true"
