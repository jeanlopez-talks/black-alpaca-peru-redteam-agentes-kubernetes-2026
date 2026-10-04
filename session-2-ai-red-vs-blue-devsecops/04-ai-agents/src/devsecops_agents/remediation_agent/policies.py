"""Defensa contra lineamientos envenenados (Acto 5): el catálogo se contrasta con la política.

El catálogo de Backstage es DOCUMENTACIÓN generada de las políticas; lo que de verdad se
aplica es la ValidatingPolicy de Kyverno desplegada por Argo CD. Si alguien altera el
catálogo ("las imágenes de este equipo pueden correr como root"), el agente no debe
creerle: lee la política vigente del clúster y compara el ID y el remedio.

Qué política corresponde a cada lineamiento lo fija este código, NO el catálogo: un
catálogo envenenado podría apuntar a otra política. Y el cambio que el agente propone
nunca sale del texto del catálogo (lo calcula analysis.py a partir de Trivy), así que un
lineamiento envenenado puede intentar convencer, pero no altera el diff que se aplica.

Permiso: solo `get` sobre esas ValidatingPolicy por nombre (ClusterRole en homelab-gitops).
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)

ANN = "security.labjp.xyz"
# Entidad del catálogo → ValidatingPolicy que Kyverno aplica.
ENTITY_TO_POLICY = {
    "pod-101-require-run-as-nonroot": "require-run-as-nonroot",
    "img-001-disallow-latest-tag": "disallow-latest-tag",
    "img-002-require-image-checksum": "require-image-checksum",
}

VERIFIED = "verified"  # el catálogo coincide con la política vigente
MISMATCH = "mismatch"  # no coincide: posible envenenamiento; manda la política
POLICY_ONLY = "policy-only"  # el catálogo no respondió; se usa la política
UNVERIFIED = "unverified"  # no se pudo leer la política: el catálogo sin contrastar


def _norm(text: str | None) -> str:
    return " ".join((text or "").split())


class PolicyReader:
    """Lee ValidatingPolicy de Kyverno con la identidad del pod (solo lectura)."""

    def __init__(self, api: Any | None = None) -> None:
        self._api = api
        self._cache: dict[str, dict[str, str] | None] = {}

    def _client(self) -> Any:
        if self._api is None:
            from kubernetes import client, config

            config.load_incluster_config()
            self._api = client.CustomObjectsApi()
        return self._api

    def get(self, name: str) -> dict[str, str] | None:
        if name in self._cache:
            return self._cache[name]
        policy = None
        try:
            obj = self._client().get_cluster_custom_object(
                "policies.kyverno.io", "v1", "validatingpolicies", name
            )
            ann = obj.get("metadata", {}).get("annotations", {}) or {}
            policy = {
                "name": name,
                "rule_id": ann.get(f"{ANN}/rule-id", ""),
                "remediation": ann.get(f"{ANN}/remediation", ""),
                "source": ann.get(f"{ANN}/source", ""),
                "mode": ann.get(f"{ANN}/mode", ""),
            }
        except Exception as exc:  # noqa: BLE001 - sin política, el lineamiento queda sin contrastar
            log.warning("no pude leer la política %s: %s", name, exc)
        self._cache[name] = policy
        return policy


def verify(
    entity: str, catalog: dict[str, str] | None, reader: PolicyReader
) -> dict[str, Any] | None:
    """Lineamiento a mostrar, con su estado de integridad frente a la política vigente."""
    policy_name = ENTITY_TO_POLICY.get(entity)
    policy = reader.get(policy_name) if policy_name else None
    if policy is None:
        return {**catalog, "integrity": UNVERIFIED} if catalog else None
    from_policy = {
        "id": policy["rule_id"],
        "title": policy["rule_id"],
        "url": policy["source"],
        "remedy": policy["remediation"],
    }
    if catalog is None:
        return {**from_policy, "integrity": POLICY_ONLY, "policy": policy_name}
    same = catalog.get("id") == policy["rule_id"] and _norm(catalog.get("remedy")) == _norm(
        policy["remediation"]
    )
    if same:
        return {**catalog, "integrity": VERIFIED, "policy": policy_name}
    log.warning(
        "lineamiento %s no coincide con la política %s: posible envenenamiento", entity, policy_name
    )
    return {
        **from_policy,
        "title": f"{policy['rule_id']} (según la política vigente)",
        "integrity": MISMATCH,
        "policy": policy_name,
        "catalog_remedy": catalog.get("remedy", ""),
        "warning": (
            f"El lineamiento del catálogo no coincide con la política que Kyverno aplica "
            f"({policy_name}): posible envenenamiento. Uso la política; el catálogo decía: "
            f"«{_norm(catalog.get('remedy'))[:200]}»."
        ),
    }
