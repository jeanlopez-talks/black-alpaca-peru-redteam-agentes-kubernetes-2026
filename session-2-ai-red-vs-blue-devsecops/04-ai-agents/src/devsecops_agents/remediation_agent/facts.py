"""Hechos de la imagen calculados por código, para que el modelo analice sin adivinar.

Un modelo pequeño, sin datos, adivina qué usa la imagen (en la prueba dijo que nginx no
carga openssl). Aquí se calcula, a partir del propio informe de Trivy:

- quién corre: el último USER del Containerfile o, si no hay, el de la imagen base
  (Trivy marca AVD-DS-0002 por el Containerfile, sin mirar la base: puede ser un falso
  positivo, y este dato lo demuestra);
- qué corre: el CMD/ENTRYPOINT y el paquete que provee ese binario;
- para cada paquete vulnerable, si el proceso principal lo carga (grafo `DependsOn` de
  `trivy image --list-all-pkgs`), si lo carga un módulo instalado, o si nada lo usa, y
  qué paquetes lo traen.

Los módulos instalados cuentan como cargados: el nginx.conf de UBI hace
`include /usr/share/nginx/modules/*.conf`, así que nginx carga TODOS al arrancar (se
comprobó en la imagen). Quitar una librería de un módulo sin quitar el módulo impediría
arrancar a nginx; por eso los hechos dicen qué módulo carga cada librería.

El modelo razona sobre estos hechos; el verificador los usa para corregirlo.
"""

from __future__ import annotations

import json
import re
from collections import deque
from typing import Any

_USER_RE = re.compile(r"^\s*USER\s+(\S+)", re.IGNORECASE | re.MULTILINE)
_FROM_LINE = re.compile(r"^\s*FROM\s", re.IGNORECASE | re.MULTILINE)
_INSTR_RE = re.compile(r"^\s*(CMD|ENTRYPOINT)\s+(.+)$", re.IGNORECASE | re.MULTILINE)
# Un usuario que no cumple esto (variables, saltos de línea...) no se puede verificar: se
# trata como root, y nunca se copia a un Containerfile.
_SAFE_USER = re.compile(r"[A-Za-z0-9._-]+(:[A-Za-z0-9._-]+)?")
# Envoltorios que lanzan al proceso real: se saltan para encontrar el binario principal.
_WRAPPERS = {"sh", "bash", "env", "exec", "tini", "dumb-init", "container-entrypoint"}
UNKNOWN_USER = "desconocido"
_ENV_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=\S*")

RUNTIME_DIRECT = "carga-directa"  # el binario principal depende de él
RUNTIME_INDIRECT = "carga-indirecta"  # dependencia de una dependencia del binario
VIA_MODULE = "via-modulo"  # lo carga un módulo instalado (que el proceso carga al arrancar)
NOT_USED = "no-lo-usa"  # está en la imagen, pero el proceso principal no lo necesita
UNKNOWN = "sin-datos"  # Trivy no dio el grafo de dependencias


def _name(ref: str) -> str:
    """'openssl-libs@3.5.8-1.el9_8.x86_64' -> 'openssl-libs'."""
    return ref.split("@", 1)[0]


def _packages(trivy: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Grafo de paquetes del SISTEMA (rpm). Los de lenguaje (package.json, METADATA...) los
    controla quien construye la imagen: no pueden pasar por paquetes ni por módulos."""
    graph: dict[str, list[str]] = {}
    for report in trivy:
        for result in report.get("Results") or []:
            if not isinstance(result, dict) or result.get("Class") != "os-pkgs":
                continue
            for p in result.get("Packages") or []:
                if not isinstance(p, dict):
                    continue
                deps = [_name(d) for d in p.get("DependsOn") or []]
                graph.setdefault(p.get("Name", ""), deps)
    graph.pop("", None)
    return graph


def _image_config(trivy: list[dict[str, Any]]) -> dict[str, Any]:
    for report in trivy:
        meta = report.get("Metadata") if isinstance(report.get("Metadata"), dict) else {}
        image_config = meta.get("ImageConfig") if isinstance(meta.get("ImageConfig"), dict) else {}
        config = image_config.get("config")
        if isinstance(config, dict) and config:
            return config
    return {}


def _final_stage(containerfile: str) -> str:
    """Solo la última etapa cuenta: es la que produce la imagen que se despliega."""
    starts = [m.start() for m in _FROM_LINE.finditer(containerfile)]
    return containerfile[starts[-1] :] if starts else containerfile


def _argv(raw: str) -> list[str]:
    raw = raw.strip()
    if raw.startswith("["):
        try:
            value = json.loads(raw)
            return [str(x) for x in value] if isinstance(value, list) else []
        except ValueError:
            return []
    return raw.split()


def _command(containerfile: str, config: dict[str, Any], nginx_image: bool = False) -> str:
    """Binario principal, con la semántica de Docker: ENTRYPOINT + CMD (CMD son sus
    argumentos si hay ENTRYPOINT), de la etapa final o, si no los define, de la base.
    Se saltan los envoltorios (`sh -c "nginx ..."`, `container-entrypoint`)."""
    found: dict[str, list[str]] = {}
    for instr, raw in _INSTR_RE.findall(_final_stage(containerfile)):
        found[instr.upper()] = _argv(raw)

    def as_list(value: Any) -> list[str]:
        return [str(x) for x in value] if isinstance(value, list) else []

    entrypoint = found.get("ENTRYPOINT", as_list(config.get("Entrypoint")))
    cmd = found.get("CMD", [] if "ENTRYPOINT" in found else as_list(config.get("Cmd")))
    argv = entrypoint + cmd
    while argv:
        head = argv[0].rsplit("/", 1)[-1].strip(";&")
        # Envoltorios, flags, `VAR=valor` y `cd dir;` delante del proceso real.
        if head in _WRAPPERS or head.startswith("-") or _ENV_ASSIGN.fullmatch(head):
            argv.pop(0)
            continue
        if head == "cd":
            argv = argv[2:]
            continue
        if head == "run" and "/s2i/" in argv[0] and nginx_image:
            return "nginx"  # el run de s2i de ubi9/nginx-* acaba en nginx
        if " " in argv[0]:  # `sh -c "nginx -g ..."`: el proceso está dentro de la cadena
            argv = argv[0].split() + argv[1:]
            continue
        return head
    return ""


def _effective_user(containerfile: str, config: dict[str, Any]) -> tuple[str, str, bool]:
    """(usuario, de dónde sale, ¿root?). Manda el usuario de la imagen construida (ya
    resuelve multi-stage y herencia); el Containerfile solo dice de dónde viene."""
    stage_users = _USER_RE.findall(_final_stage(containerfile))
    user = str(config.get("User") or "") or (stage_users[-1] if stage_users else "")
    source = "Containerfile" if stage_users else ("imagen base" if user else "nadie lo define")
    if not user:
        return "root", source, True
    if not _SAFE_USER.fullmatch(user):
        return UNKNOWN_USER, "no verificable", True
    uid = user.split(":", 1)[0]
    return user, source, uid.lower() == "root" or (uid.isdigit() and int(uid) == 0)


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
    user, user_source, runs_as_root = _effective_user(containerfile, config)
    command = _command(containerfile, config, nginx_image="nginx-core" in graph)

    # El binario suele venir en "<cmd>-core" (nginx-core); el paquete "<cmd>" solo lo
    # instala y arrastra lo que pide la instalación (systemd, bash), no lo que carga.
    main = [p for p in (f"{command}-core", command) if command and p in graph][:1]
    installer = frozenset(p for p in (command, f"{command}-core") if command and p in graph)
    main_closure = _closure(graph, main)
    modules = [p for p in graph if p.startswith(f"{command}-mod-")]
    module_closure = {m: _closure(graph, [m], stop=installer) for m in modules}
    required_by: dict[str, list[str]] = {}
    for pkg, deps in graph.items():
        for dep in deps:
            required_by.setdefault(dep, []).append(pkg)

    usage = {}
    for pkg in sorted(set(vulnerable)):
        if not graph or not main:
            # Sin grafo, o sin saber qué binario corre, no se puede afirmar que algo
            # no se usa: nada se marca como removible.
            kind = UNKNOWN
        elif pkg in main:
            kind = RUNTIME_DIRECT
        elif pkg in main_closure:
            kind = RUNTIME_DIRECT if main_closure[pkg] == 1 else RUNTIME_INDIRECT
        elif any(pkg in c for c in module_closure.values()):
            kind = VIA_MODULE
        else:
            kind = NOT_USED
        usage[pkg] = {
            "runtime": kind,
            "via_modules": sorted(m for m, c in module_closure.items() if pkg in c)
            if kind in (VIA_MODULE, NOT_USED)
            else [],
            "required_by": sorted(required_by.get(pkg, []))[:8],
        }

    vulnerable_set = set(vulnerable)
    meta = f"{command}-all-modules"
    return {
        "user": user,
        "user_source": user_source,
        "runs_as_root": runs_as_root,
        "command": command,
        "main_packages": main,
        # Módulos instalados del proceso principal y qué paquetes vulnerables carga cada uno.
        "modules": {
            m: sorted(p for p in c if p in vulnerable_set)
            for m, c in sorted(module_closure.items())
        }
        if main
        else {},
        "modules_meta_package": meta if main and meta in graph else None,
        "dependency_graph": bool(graph),
        "package_usage": usage,
    }
