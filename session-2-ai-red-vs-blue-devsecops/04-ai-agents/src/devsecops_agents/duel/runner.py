"""Orquestador del duelo: los actos pasan SIEMPRE por A2A (rojo cliente -> azul servidor).

  Acto 1    PR obvio contra el azul vulnerable        -> se espera BLOCK
  Acto 2/3  PR envenenado contra el azul vulnerable   -> se espera APPROVE (gana el atacante)
  Acto 4    el mismo PR contra el azul ENDURECIDO     -> se espera BLOCK (se contiene)

Cada azul corre como servidor A2A real (uvicorn) en un puerto local efímero.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import uvicorn

from devsecops_agents.blue_reviewer.review import BlueReviewer, ReviewResult
from devsecops_agents.blue_reviewer.server import BlueReviewExecutor, agent_card
from devsecops_agents.common.a2a_server import build_app
from devsecops_agents.red_attacker.attacker import submit_pr
from devsecops_agents.red_attacker.payloads import ATTACK_PRS


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextlib.contextmanager
def blue_server(reviewer: BlueReviewer) -> Iterator[str]:
    """Levanta un agente azul A2A en 127.0.0.1 y devuelve su URL."""
    port = _free_port()
    url = f"http://127.0.0.1:{port}/"
    app = build_app(agent_card(url), BlueReviewExecutor(reviewer))
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("el agente azul no arrancó a tiempo")
        time.sleep(0.05)
    try:
        yield url
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def run_duel(mode: str = "rules") -> dict[str, Any]:
    obvious, poisoned = ATTACK_PRS["pr-01-obvious.diff"], ATTACK_PRS["pr-02-poisoned.diff"]
    with blue_server(BlueReviewer(hardened=False, mode=mode)) as vulnerable:
        act1 = asyncio.run(submit_pr(vulnerable, obvious))
        act2 = asyncio.run(submit_pr(vulnerable, poisoned))
    with blue_server(BlueReviewer(hardened=True, mode="rules")) as hardened:
        act4 = asyncio.run(submit_pr(hardened, poisoned))
    return build_report(mode, act1, act2, act4)


def build_report(mode: str, act1: ReviewResult, act2: ReviewResult, act4: ReviewResult) -> dict:
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "agent_mode": mode,
        "transport": "a2a",
        "acts": {
            "act1_obvious": act1.as_dict(),
            "act2_poisoned_vulnerable": act2.as_dict(),
            "act4_poisoned_hardened": act4.as_dict(),
        },
        "verdict": {
            "act1_blocked": act1.decision == "BLOCK",
            "attacker_wins_act2": act2.decision == "APPROVE",
            "contained_act4": act4.decision == "BLOCK",
        },
    }
