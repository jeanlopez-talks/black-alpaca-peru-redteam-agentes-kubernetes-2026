"""Cliente de la etapa `remediation` del pipeline: `remediation-request`.

Lee los informes JSON de Trivy y el Containerfile del workspace, los recorta a lo que el
agente usa (los informes completos pesan cientos de KB) y llama a la skill `advise`. Deja
el informe en el log del PipelineRun y en un archivo. Es INFORMATIVO: siempre termina con
código 0 para no cambiar el resultado del pipeline.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from devsecops_agents.common.a2a_client import send_text

_VULN_FIELDS = (
    "VulnerabilityID",
    "PkgName",
    "InstalledVersion",
    "FixedVersion",
    "Status",
    "Severity",
    "Title",
)
_MISCONF_FIELDS = ("ID", "AVDID", "Title", "Description", "Message", "Resolution", "Severity")


def slim(report: dict[str, Any]) -> dict[str, Any]:
    results = []
    for r in report.get("Results") or []:
        results.append(
            {
                "Target": r.get("Target", ""),
                "Class": r.get("Class", ""),
                "Vulnerabilities": [
                    {k: v.get(k) for k in _VULN_FIELDS} for v in r.get("Vulnerabilities") or []
                ],
                "Misconfigurations": [
                    {k: m.get(k) for k in _MISCONF_FIELDS} for m in r.get("Misconfigurations") or []
                ],
            }
        )
    return {"ArtifactName": report.get("ArtifactName", ""), "Results": results}


def _print_report(report: dict[str, Any]) -> None:
    v = report["summary"]["vulnerabilities"]
    print(f"[remediation] {report['explanation']}")
    print(
        f"[remediation] vulnerabilidades: {v['total']} (críticas {v['critical']}, "
        f"altas {v['high']}, con corrección {v['fixable']}, sin ella {v['unfixed']})"
    )
    for r in report["recommendations"]:
        g = (
            f" | lineamiento {r['guideline']['id']}: {r['guideline']['url']}"
            if r.get("guideline")
            else ""
        )
        print(f"[remediation] {r['id']} [{r['severity']}] {r['title']}{g}")
        if r.get("fix"):
            print(f"[remediation]    corrección: {r['fix']['summary']}")
            if r["fix"].get("diff"):
                print(
                    "\n".join(f"[remediation]    {line}" for line in r["fix"]["diff"].splitlines())
                )
    print(
        "[remediation] Pregunta al agente y confirma los cambios en Backstage "
        "(sistema duel-devsecops)."
    )


def _build_request(args: argparse.Namespace) -> dict[str, Any]:
    trivy = []
    for path in args.trivy:
        p = Path(path)
        if p.is_file() and p.stat().st_size:
            try:
                trivy.append(slim(json.loads(p.read_text())))
            except ValueError:
                print(f"[remediation] AVISO: {path} no es JSON válido; se ignora.")
        else:
            print(f"[remediation] AVISO: falta {path} (¿Trivy sin DB?); se ignora.")
    cf = Path(args.containerfile)
    return {
        "skill": "advise",
        "pipeline_run": args.pipeline_run,
        "image": args.image,
        "containerfile": cf.read_text() if cf.is_file() else "",
        "containerfile_path": args.containerfile_path,
        "trivy": trivy,
    }


async def _ask(agent_url: str, request: dict[str, Any]) -> dict[str, Any] | None:
    try:
        return json.loads(await send_text(agent_url, json.dumps(request), timeout_s=120))
    except Exception as exc:  # noqa: BLE001 - informativo: el pipeline no falla por esto
        print(f"[remediation] AVISO: el agente no respondió ({exc}). Etapa informativa.")
        return None


def _run(args: argparse.Namespace) -> int:
    report = asyncio.run(_ask(args.agent_url, _build_request(args)))
    if report is None:
        return 0
    if "error" in report:
        print(f"[remediation] AVISO: {report['error']}")
        return 0
    if args.output:
        Path(args.output).write_text(json.dumps(report, ensure_ascii=False, indent=2))
    _print_report(report)
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Etapa remediation: pide el informe al agente.")
    parser.add_argument("--agent-url", required=True)
    parser.add_argument(
        "--trivy", action="append", default=[], help="Informe JSON de Trivy (repetible)"
    )
    parser.add_argument(
        "--containerfile", required=True, help="Containerfile analizado (ruta local)"
    )
    parser.add_argument(
        "--containerfile-path", required=True, help="Ruta del Containerfile en el repo"
    )
    parser.add_argument("--pipeline-run", default="manual")
    parser.add_argument("--image", default="")
    parser.add_argument("--output", default="")
    sys.exit(_run(parser.parse_args()))


if __name__ == "__main__":
    main()
