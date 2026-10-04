# Agentes y human in the loop

## Agente de remediación (pestaña «Agente de remediación»)

1. **Lanza el pipeline.** La etapa `remediation` le envía los hallazgos de Trivy y el
   Containerfile. El informe aparece en la pestaña: recomendaciones por prioridad, cada
   una con su lineamiento (POD-101, IMG-002…) y, cuando es posible, el diff que la corrige.
2. **Pregunta.** «¿Qué es lo más urgente?», «¿qué dice POD-101?». El modelo solo
   conversa: no aplica nada.
3. **Pide el cambio.** Escribe «aplica R1». El agente prepara una **acción pendiente** con
   el diff exacto, el destino y la hora en que caduca (15 minutos).
4. **Decide tú.** Solo el botón **Confirmar y aplicar** la ejecuta: el agente sube la rama
   `remediation/<pipeline-run>-r1` y te da el enlace para abrir el PR. Con **Cancelar** no
   se aplica nada. El merge es tuyo y el despliegue sigue por GitOps.

## Controles

| Riesgo | Control |
|--------|---------|
| Un texto del chat (o un prompt injection) intenta confirmar | Confirmar solo existe como botón; los intentos por texto reciben una respuesta fija |
| El modelo afirma haber aplicado algo | Si no hubo confirmación real, su respuesta se sustituye por la verdad |
| El pipeline, que ejecuta código del PR, intenta confirmar | Llega solo a la puerta `advise` del agente (otro puerto, por NetworkPolicy) |
| El agente escribe en `main` | Su deploy key solo sirve para este repo y `main` está protegida (ruleset sin excepción para ella) |
| Un lineamiento del catálogo está envenenado | El agente lo contrasta con la política que Kyverno aplica; si no coinciden, avisa y usa la política |
| El agente usa herramientas que no le tocan | agentgateway: rol de Keycloak + relación `can_call` en OpenFGA por herramienta |

## Lineamientos

Los lineamientos salen de las políticas Kyverno de
[homelab-security-policies](https://github.com/labjp-homelab/homelab-security-policies):
Argo CD las aplica en el clúster y el mismo repo genera su documentación y el catálogo.
El agente los lee por MCP (catálogo de Backstage) y los contrasta con la política vigente.
