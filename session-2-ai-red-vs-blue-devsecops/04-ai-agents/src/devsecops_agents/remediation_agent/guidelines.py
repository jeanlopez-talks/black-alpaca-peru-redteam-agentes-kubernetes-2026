"""Lineamientos del homelab leídos por MCP: Backstage `catalog-read` vía agentgateway.

El agente se identifica con su propio cliente de Keycloak (`client_credentials`) y llama
a `backstage_catalog.get-catalog-entity` por el nombre de la entidad de la regla. Que
pueda llamar esa herramienta lo deciden agentgateway (rol `mcp:tool:*` del JWT) y OpenFGA
(relación `can_call`); el agente no tiene ninguna credencial de Backstage.

Si el gateway o el catálogo no responden, el informe sale igual, sin el lineamiento, y lo
indica: un fallo de lectura no debe tumbar el análisis.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

import httpx

log = logging.getLogger(__name__)

TOOL_GET_ENTITY = "backstage_catalog.get-catalog-entity"
_TOKEN_MARGIN_S = 30


class GuidelineClient:
    def __init__(
        self,
        *,
        mcp_url: str | None = None,
        token_url: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        timeout_s: float = 20.0,
    ) -> None:
        self.mcp_url = mcp_url or os.getenv("MCP_URL", "")
        self.token_url = token_url or os.getenv("OIDC_TOKEN_URL", "")
        self.client_id = client_id or os.getenv("OIDC_CLIENT_ID", "")
        self.client_secret = client_secret or os.getenv("OIDC_CLIENT_SECRET", "")
        self.timeout_s = timeout_s
        self._token = ""
        self._token_expiry = 0.0
        self._cache: dict[str, dict[str, str] | None] = {}

    @property
    def configured(self) -> bool:
        return all((self.mcp_url, self.token_url, self.client_id, self.client_secret))

    def _access_token(self, http: httpx.Client) -> str:
        if self._token and time.monotonic() < self._token_expiry:
            return self._token
        resp = http.post(
            self.token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
        )
        resp.raise_for_status()
        body = resp.json()
        self._token = body["access_token"]
        self._token_expiry = time.monotonic() + max(
            0, int(body.get("expires_in", 60)) - _TOKEN_MARGIN_S
        )
        return self._token

    @staticmethod
    def _rpc_result(resp: httpx.Response) -> dict[str, Any]:
        """Resultado JSON-RPC de una respuesta MCP (JSON directo o stream SSE)."""
        resp.raise_for_status()
        text = resp.text
        if "application/json" in resp.headers.get("content-type", ""):
            payload = json.loads(text)
        else:
            data = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")]
            payload = json.loads(data[-1]) if data else {}
        if "error" in payload:
            raise RuntimeError(payload["error"].get("message", "error MCP"))
        return payload.get("result", {})

    def _call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        with httpx.Client(timeout=self.timeout_s) as http:
            headers = {
                "Authorization": f"Bearer {self._access_token(http)}",
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
            }
            init = http.post(
                self.mcp_url,
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "devsecops-remediation-agent", "version": "1"},
                    },
                },
            )
            self._rpc_result(init)
            session = init.headers.get("mcp-session-id")
            if session:
                headers["Mcp-Session-Id"] = session
            http.post(
                self.mcp_url,
                headers=headers,
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            )
            call = http.post(
                self.mcp_url,
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments},
                },
            )
            return self._rpc_result(call)

    def get(self, entity_name: str) -> dict[str, str] | None:
        """Lineamiento {id, title, url, remedy} de la entidad, o None si no se pudo leer."""
        if entity_name in self._cache:
            return self._cache[entity_name]
        guideline = None
        if self.configured:
            try:
                result = self._call_tool(
                    TOOL_GET_ENTITY,
                    {"kind": "Resource", "namespace": "default", "name": entity_name},
                )
                guideline = to_guideline(json.loads(result["content"][0]["text"]))
            except Exception as exc:  # noqa: BLE001 - un fallo de lectura no tumba el informe
                log.warning("no pude leer el lineamiento %s: %s", entity_name, exc)
        self._cache[entity_name] = guideline
        return guideline


def to_guideline(entity: dict[str, Any]) -> dict[str, str]:
    """Campos del lineamiento a partir de la entidad Resource del catálogo."""
    meta = entity.get("metadata", {})
    ann = meta.get("annotations", {})
    link = next((lk["url"] for lk in meta.get("links", []) if lk.get("title") == "Lineamiento"), "")
    return {
        "id": ann.get("security.labjp.xyz/rule-id", meta.get("name", "")),
        "title": meta.get("title", meta.get("name", "")),
        "url": link,
        "remedy": ann.get("security.labjp.xyz/remediation", ""),
    }
