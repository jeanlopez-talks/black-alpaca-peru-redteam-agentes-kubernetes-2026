"""CLI del agente rojo.

red-attacker submit --blue-url URL --pr pr-02-poisoned.diff
    Envía el PR al azul por A2A. stdout: SOLO la decisión (APPROVE|BLOCK), para el
    resultado de Tekton; stderr: el acta legible. Exit 0 siempre: un APPROVE del PR
    envenenado es el resultado esperado de la demo, no un error.

red-attacker export --dir DIR
    Escribe los diffs del ataque en DIR (para el SAST o para mostrarlos en la charla).
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from devsecops_agents.red_attacker.attacker import get_pr, submit_pr
from devsecops_agents.red_attacker.payloads import ATTACK_PRS


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="[red] %(message)s")
    parser = argparse.ArgumentParser(prog="red-attacker")
    sub = parser.add_subparsers(dest="command", required=True)
    submit = sub.add_parser("submit", help="envía un PR al azul por A2A")
    submit.add_argument("--blue-url", required=True)
    submit.add_argument("--pr", required=True, choices=sorted(ATTACK_PRS))
    export = sub.add_parser("export", help="escribe los diffs del ataque")
    export.add_argument("--dir", required=True, type=Path)
    args = parser.parse_args(argv)

    if args.command == "export":
        args.dir.mkdir(parents=True, exist_ok=True)
        for pr in ATTACK_PRS.values():
            (args.dir / pr.pr_id).write_text(pr.diff, encoding="utf-8")
        logging.info("diffs escritos en %s", args.dir)
        return 0

    pr = get_pr(args.pr)
    logging.info("abro %s (%s) y se lo envío al azul por A2A: %s", pr.pr_id, pr.act, args.blue_url)
    result = asyncio.run(submit_pr(args.blue_url, pr))
    logging.info(
        "azul -> %s (motor=%s, score=%.6f, nota obedecida=%s): %s",
        result.decision,
        result.engine,
        result.injection_score,
        result.reviewer_note_honored,
        result.reason,
    )
    sys.stdout.write(result.decision)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
