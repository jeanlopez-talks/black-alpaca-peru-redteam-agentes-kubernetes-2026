"""Agente de remediación: hallazgos del pipeline → recomendaciones con su lineamiento.

Lee los lineamientos del homelab por MCP (Backstage vía agentgateway, autorizado por
OpenFGA), conversa con la persona en Backstage y solo aplica una corrección cuando ella
la confirma.
"""
