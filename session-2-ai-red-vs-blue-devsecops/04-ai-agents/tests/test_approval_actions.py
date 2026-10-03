import pytest

from devsecops_agents.approval_agent import actions, cluster


def test_proposals_never_execute_anything():
    proposals = actions.propose_actions(cluster.read_pipelineruns())
    assert {p.id.split(":")[0] for p in proposals} == {"rerun", "approve", "ticket"}


@pytest.mark.parametrize("token", ["", "wrong", "s3cret-but-longer"])
def test_execute_requires_the_human_token(monkeypatch, token):
    monkeypatch.setenv("HUMAN_APPROVAL_TOKEN", "s3cret")
    with pytest.raises(actions.HumanApprovalRequiredError):
        actions.execute_action("approve:run-1", token)


def test_execute_without_configured_token_is_denied(monkeypatch):
    monkeypatch.delenv("HUMAN_APPROVAL_TOKEN", raising=False)
    with pytest.raises(actions.HumanApprovalRequiredError):
        actions.execute_action("approve:run-1", "")


def test_execute_with_the_human_token(monkeypatch):
    monkeypatch.setenv("HUMAN_APPROVAL_TOKEN", "s3cret")
    assert actions.execute_action("approve:run-1", "s3cret")["action"] == "approve"


def test_unknown_action_is_rejected(monkeypatch):
    monkeypatch.setenv("HUMAN_APPROVAL_TOKEN", "s3cret")
    with pytest.raises(ValueError):
        actions.execute_action("delete:everything", "s3cret")
