"""Arranca el agente de remediación: `remediation-agent` (dos puertas, un solo estado)."""

from __future__ import annotations

import asyncio
import logging
import os

import uvicorn

from devsecops_agents.common.a2a_server import build_app
from devsecops_agents.remediation_agent.server import (
    ADVISE_PORT,
    CHAT_PORT,
    RemediationAgent,
    advise_card,
    advise_executor,
    chat_card,
    chat_executor,
)


async def _serve() -> None:
    agent = RemediationAgent()
    host = os.getenv("HOST", "0.0.0.0")  # noqa: S104 - el kubelet sondea por la IP del pod
    chat_port = int(os.getenv("PORT", str(CHAT_PORT)))
    advise_port = int(os.getenv("ADVISE_PORT", str(ADVISE_PORT)))
    chat_url = os.getenv("PUBLIC_URL", f"http://127.0.0.1:{chat_port}/")
    advise_url = os.getenv("ADVISE_PUBLIC_URL", f"http://127.0.0.1:{advise_port}/")
    servers = [
        uvicorn.Server(
            uvicorn.Config(
                build_app(chat_card(chat_url), chat_executor(agent)),
                host=host,
                port=chat_port,
                log_level="info",
                access_log=False,
            )
        ),
        uvicorn.Server(
            uvicorn.Config(
                build_app(advise_card(advise_url), advise_executor(agent)),
                host=host,
                port=advise_port,
                log_level="info",
                access_log=False,
            )
        ),
    ]
    await asyncio.gather(*(s.serve() for s in servers))


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    asyncio.run(_serve())


if __name__ == "__main__":
    main()
