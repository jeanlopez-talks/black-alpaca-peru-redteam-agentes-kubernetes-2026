"""Análisis determinista del agente de remediación: hallazgos → recomendaciones priorizadas.

Entrada: el JSON de Trivy (`trivy fs` / `trivy image --format json`, ya recortado por
`remediation-request`) y el Containerfile analizado. Todo lo que el informe afirma sale
de esos datos: versiones que corrigen, severidades y conteos vienen de Trivy, nunca del
modelo de lenguaje. El modelo, si lo hay, solo redacta la explicación.

Cada hallazgo de configuración se ata a su lineamiento del homelab por ID (la regla
Kyverno publicada en Backstage), no a texto libre: el agente lee la regla aplicable.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

# Hallazgo de Trivy → entidad del lineamiento en el catálogo de Backstage
# (homelab-security-policies). El agente trae de ahí el ID, el remedio y el enlace.
TRIVY_TO_GUIDELINE = {
    "AVD-DS-0002": "pod-101-require-run-as-nonroot",  # sin USER: corre como root
    "AVD-DS-0001": "img-001-disallow-latest-tag",  # FROM con :latest
}
# Control propio (Trivy no lo reporta): FROM sin digest.
UNPINNED_BASE_GUIDELINE = "img-002-require-image-checksum"

# Qué significa cada estado de Trivy para quien tiene que decidir (sin versión que corrija,
# el estado lo pone el proveedor del paquete, p. ej. Red Hat para UBI).
STATUS_ACTION = {
    "will_not_fix": "No se va a corregir: el proveedor decidió no publicar parche. Quitar el "
    "paquete si la app no lo usa o cambiar de imagen base; si no, aceptar el riesgo con una "
    "excepción documentada.",
    "fix_deferred": "Corrección aplazada por el proveedor: aún no hay parche. Vigilar el aviso "
    "y reducir la imagen base.",
    "affected": "Afectada y sin parche publicado todavía: vigilar el aviso del proveedor y "
    "reducir la imagen base mientras tanto.",
    "under_investigation": "El proveedor aún la investiga: sin parche todavía. Vigilar.",
    "end_of_life": "El sistema operativo de la imagen ya no recibe parches: cambiar de imagen "
    "base.",
}
DEFAULT_UNFIXED_ACTION = (
    "Sin versión que la corrija: reducir la imagen base o aceptarla con una excepción."
)

# Usuario no root de las imágenes s2i de UBI (nginx-120 sirve como uid 1001).
DEFAULT_NONROOT_USER = "1001"

_FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", re.IGNORECASE | re.MULTILINE)
_USER_RE = re.compile(r"^\s*USER\s+\S+", re.IGNORECASE | re.MULTILINE)
_FINAL_RE = re.compile(r"^\s*(CMD|ENTRYPOINT)\b", re.IGNORECASE)


@dataclass
class Fix:
    type: str  # containerfile-patch | package-update | base-image
    summary: str
    diff: str | None = None
    patched: str | None = None  # Containerfile corregido completo (no sale en el informe)


@dataclass
class Recommendation:
    id: str
    priority: int
    severity: str
    kind: str  # misconfiguration | vulnerability | base-image
    title: str
    detail: str
    evidence: list[str] = field(default_factory=list)
    guideline_entity: str | None = None  # nombre de la entidad en el catálogo
    guideline: dict[str, str] | None = None  # se rellena con los datos del catálogo
    fix: Fix | None = None

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("guideline_entity")
        if data["fix"]:
            data["fix"].pop("patched")
        return data


@dataclass
class Vulnerability:
    id: str
    package: str
    installed: str
    fixed: str
    severity: str
    status: str
    title: str
    url: str
    fixable: bool
    action: str  # qué hacer con ella, en una frase


@dataclass
class Analysis:
    image: str
    containerfile_path: str
    summary: dict[str, Any]
    recommendations: list[Recommendation]
    target: dict[str, Any] = field(default_factory=dict)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)


def _vulnerabilities(trivy: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for report in trivy:
        for result in report.get("Results") or []:
            for v in result.get("Vulnerabilities") or []:
                seen.setdefault((v.get("VulnerabilityID", ""), v.get("PkgName", "")), v)
    return list(seen.values())


def _vulnerability(v: dict[str, Any]) -> Vulnerability:
    fixed = v.get("FixedVersion") or ""
    status = (v.get("Status") or ("fixed" if fixed else "unknown")).lower()
    pkg, installed = v.get("PkgName", ""), v.get("InstalledVersion", "")
    if fixed:
        action = (
            f"Se corrige: actualizar {pkg} de {installed} a {fixed} "
            "(o reconstruir sobre la imagen base actualizada)."
        )
    else:
        action = STATUS_ACTION.get(status, DEFAULT_UNFIXED_ACTION)
    return Vulnerability(
        id=v.get("VulnerabilityID", ""),
        package=pkg,
        installed=installed,
        fixed=fixed,
        severity=_sev(v.get("Severity")),
        status=status,
        title=v.get("Title") or "",
        url=v.get("PrimaryURL") or "",
        fixable=bool(fixed),
        action=action,
    )


def _target(
    trivy: list[dict[str, Any]], containerfile: str, image: str, containerfile_path: str
) -> dict[str, Any]:
    """Qué se analizó: imagen, digest, sistema operativo, imagen base y origen de cada escaneo."""
    os_name, digest, scans = "", "", []
    for report in trivy:
        meta = report.get("Metadata") or {}
        osinfo = meta.get("OS") or {}
        if osinfo and not os_name:
            os_name = " ".join(x for x in (osinfo.get("Family"), osinfo.get("Name")) if x)
        if meta.get("RepoDigests") and not digest:
            digest = str(meta["RepoDigests"][0]).rsplit("@", 1)[-1]
        for result in report.get("Results") or []:
            scans.append({"target": result.get("Target", ""), "class": result.get("Class", "")})
    return {
        "image": image,
        "digest": digest,
        "os": os_name,
        "base_images": _FROM_RE.findall(containerfile),
        "containerfile_path": containerfile_path,
        "scans": scans,
    }


def _misconfigurations(trivy: list[dict[str, Any]]) -> list[dict[str, Any]]:
    found = []
    for report in trivy:
        for result in report.get("Results") or []:
            found.extend(result.get("Misconfigurations") or [])
    return found


def _sev(value: str | None) -> str:
    value = (value or "UNKNOWN").upper()
    return value if value in SEVERITY_ORDER else "UNKNOWN"


def _unified_diff(path: str, before: str, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        )
    )


def add_nonroot_user(containerfile: str, user: str = DEFAULT_NONROOT_USER) -> str:
    """Inserta `USER <user>` antes del CMD/ENTRYPOINT final (o al final si no hay)."""
    lines = containerfile.splitlines()
    insert_at = len(lines)
    for i in range(len(lines) - 1, -1, -1):
        if _FINAL_RE.match(lines[i]):
            insert_at = i
            break
    patched = [
        *lines[:insert_at],
        "# Sin root: un proceso con uid 0 está a una vulnerabilidad de ser root en el nodo.",
        f"USER {user}",
        "",
        *lines[insert_at:],
    ]
    return "\n".join(patched).rstrip("\n") + "\n"


def analyze(
    trivy: list[dict[str, Any]],
    containerfile: str,
    *,
    image: str = "",
    containerfile_path: str = "Containerfile",
) -> Analysis:
    recs: list[Recommendation] = []

    # 1. Configuración del Containerfile atada a un lineamiento (con corrección automática
    #    cuando es segura).
    for m in sorted(
        _misconfigurations(trivy), key=lambda m: SEVERITY_ORDER[_sev(m.get("Severity"))]
    ):
        avd = m.get("AVDID") or m.get("ID", "")
        rec = Recommendation(
            id="",
            priority=0,
            severity=_sev(m.get("Severity")),
            kind="misconfiguration",
            title=m.get("Title") or avd,
            detail=m.get("Description") or m.get("Message") or "",
            evidence=[f"{avd}: {m.get('Message') or m.get('Title', '')}"],
            guideline_entity=TRIVY_TO_GUIDELINE.get(avd),
        )
        if avd == "AVD-DS-0002" and not _USER_RE.search(containerfile):
            patched = add_nonroot_user(containerfile)
            rec.fix = Fix(
                type="containerfile-patch",
                summary=f"Añadir `USER {DEFAULT_NONROOT_USER}` antes del arranque.",
                diff=_unified_diff(containerfile_path, containerfile, patched),
                patched=patched,
            )
        elif m.get("Resolution"):
            rec.fix = Fix(type="containerfile-patch", summary=m["Resolution"])
        recs.append(rec)

    # 2. Imagen base sin digest (IMG-002): un tag se puede mover; el digest no.
    unpinned = [ref for ref in _FROM_RE.findall(containerfile) if "@sha256:" not in ref]
    if unpinned:
        recs.append(
            Recommendation(
                id="",
                priority=0,
                severity="MEDIUM",
                kind="misconfiguration",
                title="Imagen base sin digest",
                detail="El FROM usa un tag: si el tag se mueve, se construye otra imagen sin "
                "que cambie el Containerfile, y la firma deja de describir lo desplegado.",
                evidence=[f"FROM {ref}" for ref in unpinned],
                guideline_entity=UNPINNED_BASE_GUIDELINE,
                fix=Fix(
                    type="base-image",
                    summary="Fijar el FROM por digest (`imagen:tag@sha256:<digest>`; el digest "
                    "se obtiene con `skopeo inspect docker://<imagen:tag>`).",
                ),
            )
        )

    # 3. Vulnerabilidades con versión que las corrige: actualizar esos paquetes.
    vulns = _vulnerabilities(trivy)
    fixable = [v for v in vulns if v.get("FixedVersion")]
    unfixed = [v for v in vulns if not v.get("FixedVersion")]
    if fixable:
        worst = min((_sev(v.get("Severity")) for v in fixable), key=SEVERITY_ORDER.get)
        by_pkg: dict[str, dict[str, Any]] = {}
        for v in fixable:
            p = by_pkg.setdefault(
                v["PkgName"],
                {
                    "installed": v.get("InstalledVersion", ""),
                    "fixed": v["FixedVersion"],
                    "cves": [],
                },
            )
            p["cves"].append(v.get("VulnerabilityID", ""))
        recs.append(
            Recommendation(
                id="",
                priority=0,
                severity=worst,
                kind="vulnerability",
                title=f"{len(fixable)} vulnerabilidades con corrección publicada",
                detail="Hay versiones que las corrigen: reconstruir sobre la última imagen base "
                "o actualizar estos paquetes.",
                evidence=[
                    f"{pkg} {d['installed']} → {d['fixed']} ({', '.join(sorted(d['cves']))})"
                    for pkg, d in sorted(by_pkg.items())
                ],
                fix=Fix(
                    type="package-update", summary="Actualizar a las versiones indicadas por Trivy."
                ),
            )
        )

    # 4. Vulnerabilidades sin corrección: no se arreglan actualizando; se reduce la base.
    if unfixed:
        worst = min((_sev(v.get("Severity")) for v in unfixed), key=SEVERITY_ORDER.get)
        pkgs: dict[str, int] = {}
        for v in unfixed:
            pkgs[v.get("PkgName", "?")] = pkgs.get(v.get("PkgName", "?"), 0) + 1
        top = sorted(pkgs.items(), key=lambda kv: (-kv[1], kv[0]))
        recs.append(
            Recommendation(
                id="",
                priority=0,
                severity=worst,
                kind="base-image",
                title=f"{len(unfixed)} vulnerabilidades sin corrección en la imagen base",
                detail="No hay versión que las corrija: vienen de paquetes de la imagen base. "
                "Se reducen usando una base mínima con solo lo que la app necesita, o se "
                "aceptan con una excepción documentada.",
                evidence=[f"{pkg}: {n} CVE" for pkg, n in top],
                fix=Fix(
                    type="base-image",
                    summary="Evaluar una base mínima (p. ej. ubi9-minimal + nginx).",
                ),
            )
        )

    # Prioridad: severidad; a igual severidad, primero lo que se corrige con un cambio
    # concreto (parche) y después lo que pide decisión.
    def _rank(r: Recommendation) -> tuple[int, int]:
        actionable = 0 if (r.fix and r.fix.diff) else 1
        return SEVERITY_ORDER[r.severity], actionable

    recs.sort(key=_rank)
    for i, r in enumerate(recs, start=1):
        r.id, r.priority = f"R{i}", i

    sev_count = {s: sum(1 for v in vulns if _sev(v.get("Severity")) == s) for s in SEVERITY_ORDER}
    summary = {
        "vulnerabilities": {
            "total": len(vulns),
            "critical": sev_count["CRITICAL"],
            "high": sev_count["HIGH"],
            "fixable": len(fixable),
            "unfixed": len(unfixed),
        },
        "misconfigurations": len(_misconfigurations(trivy)),
    }
    # Todas, una por una: primero las que se corrigen, y dentro de cada grupo por severidad.
    detail = sorted(
        (_vulnerability(v) for v in vulns),
        key=lambda x: (not x.fixable, SEVERITY_ORDER[x.severity], x.package, x.id),
    )
    return Analysis(
        image=image,
        containerfile_path=containerfile_path,
        summary=summary,
        recommendations=recs,
        target=_target(trivy, containerfile, image, containerfile_path),
        vulnerabilities=detail,
    )


def rules_explanation(analysis: Analysis) -> str:
    """Explicación sin modelo: los hechos del informe en una frase."""
    v = analysis.summary["vulnerabilities"]
    image = analysis.target.get("image") or analysis.image
    parts = [
        f"{v['total']} vulnerabilidades ({v['critical']} críticas, {v['high']} altas; "
        f"{v['fixable']} con corrección, {v['unfixed']} sin ella)",
        f"{analysis.summary['misconfigurations']} problemas de configuración en el Containerfile",
    ]
    patchable = [r.id for r in analysis.recommendations if r.fix and r.fix.diff]
    tail = (
        f" Puedo proponer el cambio para {', '.join(patchable)}; "
        "nada se aplica sin tu confirmación."
        if patchable
        else ""
    )
    where = f"En la imagen {image} encontré " if image else "Encontré "
    return where + " y ".join(parts) + "." + tail
