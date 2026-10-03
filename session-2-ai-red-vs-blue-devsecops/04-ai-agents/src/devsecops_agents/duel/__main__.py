"""Corre el duelo completo en local por A2A: `run-duel [--llm] [--out FILE]`."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from devsecops_agents.duel.runner import run_duel


def _mark(ok: bool) -> str:
    return "[OK]" if ok else "[XX]"


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.WARNING)
    parser = argparse.ArgumentParser(prog="run-duel")
    parser.add_argument("--llm", action="store_true", help="azul con LLM (cae a reglas si no hay)")
    parser.add_argument("--out", type=Path, default=Path("results/duel-results.json"))
    args = parser.parse_args(argv)

    report = run_duel("llm" if args.llm else "rules")
    acts = report["acts"]
    for title, key in (
        ("Acto 1   PR obvio, azul vulnerable", "act1_obvious"),
        ("Acto 2/3 PR envenenado, azul vulnerable", "act2_poisoned_vulnerable"),
        ("Acto 4   PR envenenado, azul endurecido", "act4_poisoned_hardened"),
    ):
        act = acts[key]
        print(f"{title}: {act['decision']} (motor={act['engine']}) — {act['reason']}")
    verdict = report["verdict"]
    print(
        f"\nActo 1 bloqueado {_mark(verdict['act1_blocked'])} | "
        f"atacante gana el Acto 2 {_mark(verdict['attacker_wins_act2'])} | "
        f"Acto 4 contenido {_mark(verdict['contained_act4'])}"
    )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Resultados: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
