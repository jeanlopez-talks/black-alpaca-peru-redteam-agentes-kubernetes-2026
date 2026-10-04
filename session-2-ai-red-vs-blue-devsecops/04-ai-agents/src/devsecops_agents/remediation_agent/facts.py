"""Hechos de la imagen calculados por código, para que el modelo analice sin adivinar.

Un modelo pequeño, sin datos, adivina qué usa la imagen (en la prueba dijo que nginx no
carga openssl). Aquí se calcula, a partir del propio informe de Trivy:

- quién corre: el último USER del Containerfile o, si no hay, el de la imagen base
  (Trivy marca AVD-DS-0002 por el Containerfile, sin mirar la base: puede ser un falso
  positivo, y este dato lo demuestra);
- qué corre: el CMD/ENTRYPOINT y el paquete que provee ese binario;
- para cada paquete vulnerable, si el proceso principal lo carga (grafo `DependsOn` de
  `trivy image --list-all-pkgs`), si solo lo usa un módulo opcional, o si nada lo usa,
  y qué paquetes lo traen.

El modelo razona sobre estos hechos; el verificador los usa para corregirlo.
"""

from __future__ import annotations

import json
import re
from collections import deque
from typing import Any

_USER_RE = re.compile(r"^\s*USER\s+(\S+)", re.IGNORECASE | re.MULTILINE)
_CMD_RE = re.compile(r"^\s*(?:CMD|ENTRYPOINT)\s+(.+)$", re.IGNORECASE | re.MULTILINE)
_ROOT_USERS = {"root", "0", "0:0", "root:root"}

RUNTIME_DIRECT = "carga-directa"  # el binario principal depende de él
RUNTIME_INDIRECT = "carga-indirecta"  # dependencia de una dependencia del binario
OPTIONAL_MODULE = "modulo-opcional"  # solo lo usa un módulo que hay que activar
NOT_USED = "no-lo-usa"  # está en la imagen, pero el proceso principal no lo necesita
UNKNOWN = "sin-datos"  # Trivy no dio el grafo de dependencias


def _name(ref: str) -> str:
    """'openssl-libs@3.5.8-1.el9_8.x86_64' -> 'openssl-libs'."""
    return ref.split("@", 1)[0]


def _packages(trivy: list[dict[str, Any]]) -> dict[str, list[str]]:
    graph: dict[str, list[str]] = {}
    for report in trivy:
        for result in report.get("Results") or []:
            for p in result.get("Packages") or []:
                deps = [_name(d) for d in p.get("DependsOn") or []]
                graph.setdefault(p.get("Name", ""), deps)
    graph.pop("", None)
    return graph


def _image_config(trivy: list[dict[str, Any]]) -> dict[str, Any]:
    for report in trivy:
        config = ((report.get("Metadata") or {}).get("ImageConfig") or {}).get("config") or {}
        if config:
            return config
    return {}


def _command(containerfile: str, config: dict[str, Any]) -> str:
    """Binario principal: el último CMD/ENTRYPOINT del Containerfile, o el de la base."""
    found = _CMD_RE.findall(containerfile)
    if found:
        raw = found[-1].strip()
        try:
            parts = json.loads(raw) if raw.startswith("[") else raw.split()
        except ValueError:
            parts = raw.split()
        return str(parts[0]).rsplit("/", 1)[-1] if parts else ""
    cmd = config.get("Entrypoint") or config.get("Cmd") or []
    return str(cmd[0]).rsplit("/", 1)[-1] if cmd else ""


def _closure(
    graph: dict[str, list[str]], roots: list[str], stop: frozenset[str] = frozenset()
) -> dict[str, int]:
    """Paquetes alcanzables desde las raíces, con su distancia (1 = dependencia directa).

    `stop`: paquetes que no se recorren (un módulo depende del paquete principal, y por
    él de todo lo que este instala; eso no es lo que carga el módulo).
    """
    dist: dict[str, int] = {}
    queue = deque((r, 0) for r in roots)
    while queue:
        pkg, d = queue.popleft()
        for dep in graph.get(pkg, []):
            if dep in stop:
                continue
            if dep not in dist:
                dist[dep] = d + 1
                queue.append((dep, d + 1))
    return dist


def image_facts(
    trivy: list[dict[str, Any]], containerfile: str, vulnerable: list[str]
) -> dict[str, Any]:
    graph = _packages(trivy)
    config = _image_config(trivy)
    users = _USER_RE.findall(containerfile)
    user = users[-1] if users else str(config.get("User") or "")
    user_source = "Containerfile" if users else ("imagen base" if user else "nadie lo define")
    command = _command(containerfile, config)

    # El binario suele venir en "<cmd>-core" (nginx-core); el paquete "<cmd>" solo lo
    # instala y arrastra lo que pide la instalación (systemd, bash), no lo que carga.
    main = [p for p in (f"{command}-core", command) if p in graph][:1]
    installer = frozenset(p for p in (command, f"{command}-core") if p in graph)
    main_closure = _closure(graph, main)
    modules = [p for p in graph if p.startswith(f"{command}-mod-")]
    module_closure = {m: _closure(graph, [m], stop=installer) for m in modules}
    required_by: dict[str, list[str]] = {}
    for pkg, deps in graph.items():
        for dep in deps:
            required_by.setdefault(dep, []).append(pkg)

    usage = {}
    for pkg in sorted(set(vulnerable)):
        if not graph:
            kind = UNKNOWN
        elif pkg in main:
            kind = RUNTIME_DIRECT
        elif pkg in main_closure:
            kind = RUNTIME_DIRECT if main_closure[pkg] == 1 else RUNTIME_INDIRECT
        elif any(pkg in c for c in module_closure.values()):
            kind = OPTIONAL_MODULE
        else:
            kind = NOT_USED
        usage[pkg] = {
            "runtime": kind,
            "via_modules": sorted(m for m, c in module_closure.items() if pkg in c)
            if kind in (OPTIONAL_MODULE, NOT_USED)
            else [],
            "required_by": sorted(required_by.get(pkg, []))[:8],
        }

    return {
        "user": user or "root",
        "user_source": user_source,
        "runs_as_root": (user or "root").lower() in _ROOT_USERS,
        "command": command,
        "main_packages": main,
        "dependency_graph": bool(graph),
        "package_usage": usage,
    }
