"""Aplicar una corrección confirmada: rama `remediation/<run>` con el cambio, nunca `main`.

Solo lo llama el servidor después de que una persona pulse "Confirmar" en Backstage. El
agente sube una rama al repositorio de la demo con su deploy key (solo ese repositorio;
la rama `main` está protegida por un ruleset que la deploy key no puede saltarse) y
devuelve el enlace para abrir el PR: el merge, y con él el despliegue por GitOps, sigue
siendo de la persona.

Límites fijos por entorno, no por lo que diga el modelo ni el mensaje:
  REMEDIATION_REPO          owner/repo destino
  REMEDIATION_ALLOWED_PATH  único archivo que el agente puede modificar
  REMEDIATION_SSH_KEY       ruta de la clave privada (Secret montado)
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

BRANCH_PREFIX = "remediation/"
GIT_BIN = "/usr/bin/git"  # ruta absoluta: no depende del PATH
# Huella publicada por GitHub (https://api.github.com/meta): sin TOFU.
GITHUB_KNOWN_HOST = (
    "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
)
_SAFE_BRANCH = re.compile(r"[^a-z0-9._/-]+")


class ApplyError(RuntimeError):
    pass


@dataclass(frozen=True)
class ApplyResult:
    branch: str
    compare_url: str
    commit: str


def safe_branch(name: str) -> str:
    slug = re.sub(r"-{2,}", "-", _SAFE_BRANCH.sub("-", name.lower())).strip("-/")
    return BRANCH_PREFIX + (slug or "fix")


def _git(args: list[str], cwd: str, env: dict[str, str]) -> str:
    proc = subprocess.run(  # noqa: S603 - argumentos fijos, sin shell
        [GIT_BIN, *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=60, check=False
    )
    if proc.returncode != 0:
        raise ApplyError(f"git {args[0]} falló: {proc.stderr.strip()[-300:]}")
    return proc.stdout.strip()


def push_fix(
    *, path: str, expected_before: str, patched: str, branch: str, message: str
) -> ApplyResult:
    repo = os.getenv("REMEDIATION_REPO", "")
    allowed = os.getenv("REMEDIATION_ALLOWED_PATH", "")
    key = os.getenv("REMEDIATION_SSH_KEY", "")
    if not (repo and allowed and key):
        raise ApplyError("aplicar no está configurado (REMEDIATION_REPO/ALLOWED_PATH/SSH_KEY)")
    if path != allowed:
        raise ApplyError(f"el agente solo puede modificar {allowed}, no {path}")
    if not branch.startswith(BRANCH_PREFIX):
        raise ApplyError("la rama debe empezar por remediation/")

    with tempfile.TemporaryDirectory(prefix="remediation-") as work:
        known_hosts = Path(work) / "known_hosts"
        known_hosts.write_text(GITHUB_KNOWN_HOST + "\n")
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": work,
            "GIT_SSH_COMMAND": (
                f"ssh -i {key} -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes "
                f"-o UserKnownHostsFile={known_hosts}"
            ),
            "GIT_AUTHOR_NAME": "DevSecOps remediation agent",
            "GIT_AUTHOR_EMAIL": "remediation-agent@labjp.xyz",
            "GIT_COMMITTER_NAME": "DevSecOps remediation agent",
            "GIT_COMMITTER_EMAIL": "remediation-agent@labjp.xyz",
        }
        clone = str(Path(work) / "repo")
        _git(
            ["clone", "--depth", "1", "--branch", "main", f"git@github.com:{repo}.git", clone],
            work,
            env,
        )
        target = Path(clone) / path
        if not target.is_file():
            raise ApplyError(f"{path} no existe en main")
        if target.read_text() != expected_before:
            raise ApplyError(
                f"{path} cambió en main desde el análisis: relanza el pipeline y vuelve a pedirlo"
            )
        target.write_text(patched)
        _git(["checkout", "-b", branch], clone, env)
        _git(["add", path], clone, env)
        _git(["commit", "-m", message], clone, env)
        commit = _git(["rev-parse", "--short", "HEAD"], clone, env)
        _git(["push", "origin", f"HEAD:refs/heads/{branch}"], clone, env)
    return ApplyResult(
        branch=branch,
        compare_url=f"https://github.com/{repo}/compare/main...{branch}?expand=1",
        commit=commit,
    )
