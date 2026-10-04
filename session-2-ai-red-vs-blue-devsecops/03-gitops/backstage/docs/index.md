# Agentes de IA en DevSecOps (rojo vs azul)

Demo de la sesión 2 de Black Alpaca 2026: un pipeline Tekton donde dos agentes de IA se
enfrentan (el rojo ataca, el azul revisa) y otros dos ayudan a la persona, que es quien
decide.

## El flujo

```
PR ─► sast ─► build ─► sbom ─► trivy-scan ─► remediation ─► sign ─► gate-blue ─► verify ─► deploy-gitops
                                                  │                                            │
                                     agente de remediación                         Kyverno: sin aprobación
                                     (informe + chat en Backstage)                 humana ni GitOps, no entra
```

| Etapa | Qué hace |
|-------|----------|
| `trivy-scan` | Escanea la imagen y el Containerfile; deja los informes en JSON |
| `remediation` | El agente de remediación convierte los hallazgos en recomendaciones con su lineamiento (informativa) |
| `gate-blue` | El agente rojo envía el PR al azul por A2A; el azul decide APPROVE o BLOCK |
| `deploy-gitops` | El agente intenta desplegar con su credencial; Kyverno lo rechaza si no hay aprobación humana y no viene de Argo CD |

## Dónde mirar en esta página

| Pestaña | Qué muestra |
|---------|-------------|
| **Overview** | Asistente DevSecOps: resumen de los PipelineRuns y acciones propuestas |
| **Agente de remediación** | Último análisis del pipeline y chat con el agente |
| **ArgoCD** | Las Applications de la demo (`black-alpaca.session=ai-red-vs-blue-devsecops`) |
| **TechDocs** | Esta documentación |

Código y manifiestos: [repo de la charla](https://github.com/jeanlopez-talks/black-alpaca-peru-redteam-agentes-kubernetes-2026/tree/main/session-2-ai-red-vs-blue-devsecops).
