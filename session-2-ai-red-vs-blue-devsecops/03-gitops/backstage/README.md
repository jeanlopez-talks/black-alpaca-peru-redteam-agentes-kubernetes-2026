# Backstage — lo propio de la charla

El portal Backstage es **plataforma del homelab** (chart oficial + PostgreSQL, en
`labjp-homelab/homelab-gitops`). Aquí solo vive lo que pertenece a la charla:

```
backstage/
├── catalog-info.yaml        entidades del catálogo (System, Components, API)
└── devsecops-agent/         agente human-in-the-loop (namespace devsecops-agent)
```

## Catálogo

`catalog-info.yaml` es un archivo estándar de Backstage. El portal lo registra como
`Location` apuntando a este archivo en el repo; como el repo es privado, la integración
de GitHub del portal necesita un token de solo lectura (gestionado por la plataforma).

## Agente DevSecOps

Resume el pipeline, explica por qué se aprobó o rechazó y **propone** acciones. Solo
ejecuta una acción si un humano presenta su token (`/approve`, comparación en tiempo
constante).

| Archivo | Qué es |
|---------|--------|
| `serviceaccount-backstage-devsecops-agent.yaml` | identidad del agente |
| `role-read-pipelineruns.yaml` + `rolebinding-...` | lectura de PipelineRun **solo** en `devsecops-duel` |
| `serviceaccount-openbao-reader.yaml` | identidad del SecretStore ante OpenBao (no se monta en pods) |
| `secretstore-openbao.yaml` | `SecretStore` propio: rol de OpenBao limitado a `apps/black-alpaca/*` |
| `externalsecret-backstage-devsecops-agent.yaml` | token humano y token de Argo CD |
| `deployment-backstage-devsecops-agent.yaml` | imagen propia, raíz de solo lectura, sin privilegios |
| `service-backstage-devsecops-agent.yaml` | Service interno (puerto 80 → 8080) |
| `networkpolicy-backstage-devsecops-agent.yaml` | entra solo Backstage; sale solo a DNS, API server, Argo CD y vLLM |

## Secretos (se siembran una vez en OpenBao, nunca en Git)

```bash
# Token del rol de proyecto de Argo CD (solo lectura de las Application del proyecto)
argocd proj role create-token ai-red-vs-blue-devsecops backstage-devsecops-agent-read --expires-in 90d

# Guardar ambos valores en OpenBao
bao kv put homelab/apps/black-alpaca/backstage-devsecops-agent \
  human-approval-token="$(openssl rand -hex 32)" \
  argocd-token="<token del paso anterior>"
```

## Pendiente

- **Imagen de los agentes**: `ghcr.io/labjp-homelab/devsecops-agents:0.1.0`, publicada por
  versión con la etiqueta `agents-v0.1.0` (ver `../../04-ai-agents/README.md`).
- **LLM**: la plataforma solo admite en vLLM a agentgateway, kagent, kserve y gastos. Lo
  correcto es que el agente consuma el LLM vía **agentgateway**; mientras tanto degrada a
  modo plantilla.
