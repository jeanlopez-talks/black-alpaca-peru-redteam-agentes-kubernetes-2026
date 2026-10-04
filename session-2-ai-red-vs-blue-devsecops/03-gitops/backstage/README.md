# Backstage — lo propio de la charla

El portal Backstage es **plataforma del homelab** (chart oficial + PostgreSQL, en
`labjp-homelab/homelab-gitops`, login con Keycloak). Aquí solo vive lo que pertenece a la
charla:

```
backstage/
├── catalog-info.yaml        entidades del catálogo (System, Components, API)
└── devsecops-agent/         agente human-in-the-loop (namespace devsecops-agent)
```

## Catálogo

`catalog-info.yaml` es un archivo estándar de Backstage. El portal lo registra como
`Location` (`app-config.production.yaml` del homelab) apuntando a este archivo en GitHub.
En la página del sistema `duel-devsecops` aparecen:

| Pestaña / tarjeta | De dónde sale |
|-------------------|---------------|
| Kubernetes | pods con `backstage.io/kubernetes-id` (agentes y PipelineRuns del duelo) |
| CI/CD (Tekton) | PipelineRuns con `backstage.io/kubernetes-id: duel-pipeline` |
| Argo CD | `ai-red-vs-blue-devsecops-sample-app`, con token de solo lectura |
| **Asistente DevSecOps** | el agente de aprobación, por el proxy `/devsecops-agent` del portal |

## Agente de aprobación

Resume el pipeline, explica por qué se aprobó o rechazó y **propone** acciones. Solo
ejecuta una acción si un humano presenta su token en la cabecera `X-Human-Approval`
(comparación en tiempo constante). Aun así no tiene RBAC de escritura: la aprobación real
es un commit en Git que Argo CD sincroniza (ver `../admission-policies/README.md`).

| Archivo | Qué es |
|---------|--------|
| `serviceaccount-backstage-devsecops-agent.yaml` | identidad del agente (con pull secret de GHCR) |
| `role-read-pipelineruns.yaml` + `rolebinding-...` | lectura de PipelineRun **solo** en `devsecops-duel` |
| `serviceaccount-openbao-reader.yaml` | identidad del SecretStore ante OpenBao (no se monta en pods) |
| `secretstore-openbao.yaml` | `SecretStore` propio: rol de OpenBao `black-alpaca-duel-agent` |
| `externalsecret-backstage-devsecops-agent.yaml` | token humano y token de Argo CD |
| `externalsecret-ghcr-pull.yaml` | pull de la imagen privada de los agentes |
| `deployment-backstage-devsecops-agent.yaml` | imagen propia, raíz de solo lectura, sin privilegios |
| `service-backstage-devsecops-agent.yaml` | Service interno (puerto 80 → 8080) |
| `networkpolicy-backstage-devsecops-agent.yaml` | entra solo Backstage; sale solo a DNS, API server, Argo CD y vLLM |

## Secretos (se siembran una vez en OpenBao, nunca en Git)

```bash
# Token del rol de proyecto de Argo CD (solo lectura de las Application del proyecto)
argocd proj role create-token ai-red-vs-blue-devsecops backstage-devsecops-agent-read -e 2160h

# Guardar ambos valores en OpenBao
bao kv put homelab/apps/black-alpaca/backstage-devsecops-agent \
  human-approval-token="$(openssl rand -hex 32)" \
  argocd-token="<token del paso anterior>"
```

El humano lee su `human-approval-token` en OpenBao (login con Keycloak) cuando va a aprobar.
