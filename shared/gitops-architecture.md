# GitOps — arquitectura de repos (dónde vive cada cosa)

Dos repos, separados por responsabilidad:

## Repo del homelab (`labjp-homelab/homelab-gitops`) — PLATAFORMA reutilizable
Infra base compartida, gestionada por el app-of-apps `homelab-root`:
- `components/platform/registry/`   → registry interno Zot (lo usan los pipelines)
- `components/platform/backstage/`  → Backstage (la plataforma IDP, reutilizable)
- `components/platform/tekton/`     → Tekton (ya existe)
- (otros: cert-manager, cloudflared, argocd...)

## Repo del laboratorio / charla (este repo) — CONFIGURACIÓN específica de la demo
Lo propio de las dos propuestas de Black Alpaca, cada una con su Argo CD:
- `../session-1-ai-agent-isolation/03-gitops/` → PROPUESTA 1 (OpenShift): AppProject `black-alpaca-isolation`
  + ApplicationSet (4 posturas) + operator Kata.
- `../session-2-ai-red-vs-blue-devsecops/03-gitops/`      → PROPUESTA 2 (k3s): AppProject `duel-devsecops`
  + pipeline DevSecOps + supply chain + Kyverno.
  - La **config particular de Backstage para la charla** (catálogo del duelo, componente
    `duel-devsecops`, el agente interactivo) vive AQUÍ, NO en el homelab. La PLATAFORMA
    Backstage está en el homelab; aquí solo su configuración específica de la demo.

## Regla
- Plataforma reutilizable (registry, Backstage, Tekton) → repo del homelab.
- Configuración específica de la demo (pipelines del duelo, catálogo Backstage de la charla,
  posturas, agente) → este repo.
- Todo gestionado por Argo CD (GitOps); nada de kubectl apply manual en el estado final.
