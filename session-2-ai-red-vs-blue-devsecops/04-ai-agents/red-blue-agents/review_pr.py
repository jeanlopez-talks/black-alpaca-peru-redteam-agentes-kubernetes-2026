#!/usr/bin/env python3
"""
Revisa UN PR y emite la decision del agente azul (entrypoint simple del step).

Pensado para correr dentro del runner del cluster (Tekton) de dos formas:

  (1) DIRECTO (por defecto): invoca BlueAgent en proceso. En MODO rules
      (AGENT_MODE=rules) usa el detector por reglas, que NO descarga el modelo
      deberta ni necesita API key — compatible con el egress deny-by-default.
      En MODO llm (AGENT_MODE=llm) el azul razona con un LLM (si hay API key).

  (2) CLIENTE A2A (--a2a <url>): actua como A2A client y le manda el diff al
      azul (A2A server, blue_a2a_server.py) que escucha en esa URL. Es el camino
      que usa el step del rojo en el pipeline cuando el azul corre como servicio.

Contrato de salida (para que el pipeline lo consuma):
    - stderr: acta legible (motor, score, reglas, nota al revisor, razon).
    - stdout: EXCLUSIVAMENTE la decision (APPROVE | BLOCK), sin salto de linea.
    - exit code: 0 siempre (un APPROVE del PR envenenado es resultado esperado).

Uso:
    python review_pr.py <nombre-del-diff>               # directo, en proceso
    python review_pr.py <nombre-del-diff> --a2a <url>    # como cliente A2A
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from blue_agent import BlueAgent, load_diff


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Revisa un PR (agente azul).")
    parser.add_argument("pr", help="Nombre del diff en diffs/ (p.ej. pr-02-poisoned.diff).")
    parser.add_argument(
        "--a2a",
        metavar="URL",
        default=None,
        help="Si se da, actua como cliente A2A contra el azul en esa URL.",
    )
    args = parser.parse_args(argv[1:])

    diff_path = Path("diffs") / args.pr
    if not diff_path.exists():
        print(f"ERROR: no existe {diff_path}", file=sys.stderr)
        return 2
    diff_text = load_diff(diff_path)

    if args.a2a:
        # Camino A2A: delega en el cliente del rojo (reusa su envio A2A).
        import red_agent

        verdict = asyncio.run(red_agent.send_pr_via_a2a(args.a2a, args.pr, diff_text))
        decision = verdict.get("decision", "BLOCK")
        print(
            f"[blue] (A2A) motor={verdict.get('mode', '?')} "
            f"decision={decision} razon={verdict.get('reason', '')}",
            file=sys.stderr,
        )
        sys.stdout.write(decision)
        return 0

    # Camino directo: azul VULNERABLE (Actos 1-3), obedece notas al revisor.
    blue = BlueAgent(honor_reviewer_notes=True)
    res = blue.review(args.pr, diff_text)

    print(
        f"[blue] motor={res.mode} score={res.injection_score:.6f} "
        f"reglas={[h.rule for h in res.rule_hits]} "
        f"nota_revisor=detectada:{res.reviewer_note_detected}/obedecida:{res.reviewer_note_honored}",
        file=sys.stderr,
    )
    print(f"[blue] razon: {res.reason}", file=sys.stderr)

    # stdout = solo la decision (la consume el Result de Tekton / el log del Job).
    sys.stdout.write(res.decision)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
