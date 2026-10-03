#!/usr/bin/env python3
"""
Acto 4 — las fronteras que contienen el ataque (demo antes/despues).

run_duel.py ya incluye el Acto 4 inline; este modulo lo aisla para la charla:
compara, sobre el MISMO PR envenenado, el azul VULNERABLE vs el azul ENDURECIDO,
y enumera las fronteras de infraestructura que convierten el APPROVE en BLOCK.

La tesis (ver CONCEPTO.md, Acto 4): lo que para el ataque NO es un mejor prompt
del azul, sino DONDE estan las fronteras:

  1. El diff del atacante se trata como DATO no confiable, nunca como instruccion
     para el LLM (honor_reviewer_notes=False).
  2. Human-in-the-loop para el merge: el agente nunca mergea solo; una senal de
     riesgo (clasificador o reglas) fuerza aprobacion humana.
  3. El clasificador/reglas son SENAL, no gate unico: su ausencia no implica
     "seguro". El merge sigue requiriendo humano.
  4. Separacion de credenciales + runner aislado (uid 1000, caps dropped, egress
     deny): aunque el PR pase, el radio de explosion esta acotado. Esta cuarta
     frontera vive en ../../03-gitops/devsecops-pipeline/base/ (ServiceAccount del runner + NetworkPolicies).

Uso:
    python defenses.py            # antes/despues con el detector por reglas
    python defenses.py --model    # con el clasificador real (laptop)
"""

from __future__ import annotations

import argparse
from pathlib import Path

from blue_agent import (
    MODEL_ID,
    BlueAgent,
    build_classifier_scorer,
    heuristic_scorer,
    load_diff,
)

DUEL_DIR = Path(__file__).resolve().parent
PR_POISONED = DUEL_DIR / "diffs" / "pr-02-poisoned.diff"

FRONTERAS = [
    "Diff = DATO no confiable: el revisor nunca obedece instrucciones del contenido.",
    "Human-in-the-loop: el agente no mergea solo; el merge final lo aprueba un humano.",
    "Clasificador/reglas = SENAL, no gate unico: su silencio no significa 'seguro'.",
    "Runner aislado + credenciales separadas (../../03-gitops/devsecops-pipeline): acota el radio de explosion.",
]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Acto 4: fronteras que contienen el ataque.")
    parser.add_argument("--model", action="store_true", help="Usa el clasificador real deberta.")
    args = parser.parse_args(argv)

    if args.model:
        print(f"[*] Cargando {MODEL_ID} (CPU)...")
        scorer = build_classifier_scorer()
    else:
        scorer = heuristic_scorer

    if not PR_POISONED.exists():
        raise SystemExit(f"Falta {PR_POISONED}. Genera los PRs: python red_agent.py")
    diff = load_diff(PR_POISONED)

    antes = BlueAgent(scorer=scorer, honor_reviewer_notes=True).review(PR_POISONED.name, diff)
    despues = BlueAgent(scorer=scorer, honor_reviewer_notes=False).review(PR_POISONED.name, diff)

    print("\n=== Acto 4 — mismo PR envenenado, antes/despues de las fronteras ===")
    print(f"ANTES  (azul vulnerable) : {antes.decision}  <- {antes.reason}")
    print(f"DESPUES(azul endurecido) : {despues.decision}  <- {despues.reason}")
    print("\nFronteras que lo paran (no un mejor prompt del azul):")
    for i, f in enumerate(FRONTERAS, 1):
        print(f"  {i}. {f}")

    contenido = antes.decision == "APPROVE" and despues.decision == "BLOCK"
    print(f"\nResultado: el endurecimiento {'CONTIENE' if contenido else 'NO contiene'} el ataque del Acto 2.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
