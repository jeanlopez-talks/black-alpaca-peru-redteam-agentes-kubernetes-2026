"""Arranca el agente azul como servidor A2A: `blue-reviewer`."""

from __future__ import annotations

import logging
import os

from devsecops_agents.blue_reviewer.server import DEFAULT_PORT, BlueReviewExecutor, agent_card
from devsecops_agents.common.a2a_server import build_app, listen_address, serve


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    host, port = listen_address(DEFAULT_PORT)
    public_url = os.getenv("PUBLIC_URL", f"http://127.0.0.1:{port}/")
    serve(build_app(agent_card(public_url), BlueReviewExecutor()), host, port)


if __name__ == "__main__":
    main()
