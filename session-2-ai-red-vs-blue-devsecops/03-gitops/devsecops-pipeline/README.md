# DevSecOps pipeline — duelo rojo vs azul (k3s)

Pipeline Tekton de 8 etapas donde dos agentes de IA se enfrentan dentro de un flujo
DevSecOps con supply chain real. El agente rojo abre un PR envenenado; el azul (revisor
LLM) decide el merge. Se comunican por **A2A**. Lo sincroniza la Application
`ai-red-vs-blue-devsecops-pipeline` (`../argocd/application-devsecops-pipeline.yaml`).

## Estructura

```
devsecops-pipeline/
├── kustomization.yaml
├── base/                              infraestructura del namespace
│   ├── namespace-openclaw-duel.yaml
│   ├── serviceaccount-duel-runner.yaml    runner SIN token de API ni RBAC
│   ├── networkpolicies-egress.yaml        deny-by-default + DNS, vLLM, Zot, 443 por task
│   ├── llm-config.yaml                    ConfigMap + Secret dummy del LLM local (vLLM)
│   └── cosign-secret.local.yaml           (local, ignorado por Git)
├── tekton/
│   ├── pipeline-devsecops.yaml            Pipeline `duel-devsecops` (8 etapas)
│   └── pipelinerun-poisoned-pr.yaml       corre el pipeline contra el PR envenenado
├── sample-app/                        la app objetivo ("la carga útil" del atacante)
│   ├── Containerfile, index.html          fuente de la imagen (ConfigMap sample-app-src)
│   ├── deployment-sample-app.yaml         usa la imagen firmada de Zot
│   ├── service-sample-app.yaml
│   ├── kustomization.yaml                 lo que sincroniza la Application de abajo
│   └── application-sample-app.yaml        Application que aplica la etapa deploy-gitops
└── fixtures/
    └── deploy-notes.md                    el config del PR envenenado, entrada del SAST
```

Las `ClusterPolicy` de Kyverno viven aparte, en `../admission-policies/`.

## Las 8 etapas

| # | Etapa | Herramienta | Qué hace | ¿Bloquea? |
|---|-------|-------------|----------|-----------|
| 1 | `sast` | semgrep 1.90 + gitleaks 8.21 | SAST y secretos sobre la fuente del PR | Informativo (`sast-blocking`) |
| 2 | `build` | kaniko 1.23 | construye la imagen y la **empuja a Zot**; guarda el digest | Sí |
| 3 | `sbom` | Syft 1.18 | SBOM CycloneDX + SPDX | No |
| 4 | `trivy-scan` | Trivy 0.58 | escanea la imagen de Zot (`HIGH,CRITICAL`) | Informativo |
| 5 | `sign` | cosign 2.4.1 | firma la imagen **por digest**; la firma queda en Zot | Sí |
| 6 | `gate-blue` | agentes A2A | rojo (step, cliente A2A) → azul (sidecar, servidor A2A) → `APPROVE`/`BLOCK` | Su decisión alimenta el `when` |
| 7 | `verify` | cosign 2.4.1 | verifica la firma por digest con la clave pública | Sí |
| 8 | `deploy-gitops` | — | solo si `APPROVE` **y** `verify-status == OK` (fail-closed) | — |

Después, en la **admisión**, Kyverno verifica la firma (`duel-verify-images`) y exige la
aprobación humana (`duel-require-human-approval`).

## Defensa en capas (el ángulo de la charla)

El PR envenenado modifica **config** (`config/deploy-notes.md`), no la imagen:

1. La supply chain pasa: la imagen se firma y **verifica OK**. La firma no detecta el ataque.
2. El azul es engañado por prompt injection indirecta y **aprueba**.
3. Kyverno **rechaza** el Deployment: falta `duel.redteam/human-approved: "true"`, y el
   agente no puede ponerla (no tiene RBAC).

> Una capa falla, la otra atrapa.

## Qué es real y qué es simulado

| Pieza | Estado |
|-------|--------|
| SAST, build + push, SBOM, Trivy, firma y verificación | **Reales** contra Zot (evidencia: `../../04-ai-agents/red-blue-agents/cluster-evidence/k3s-supply-chain-run.md`) |
| Gate del azul (A2A) | **Real**: modo `rules` siempre; modo `llm` si vLLM responde |
| Merge del PR | **Simulado**: el `duel-runner` no tiene RBAC de merge (frontera human-in-the-loop) |
| `deploy-gitops` | Muestra el manifiesto real de la Application; el `kubectl apply` lo hace el operador (el runner no tiene credenciales) |
| Admisión Kyverno | **Real** |

## Requisitos de plataforma (repo del homelab, no este)

- Tekton Pipelines, Argo CD (ns `argocd`) y Kyverno con `--allowInsecureRegistry=true`.
- Registry Zot en `zot.registry.svc.cluster.local:5000` (HTTP interno).
- **Los nodos deben poder descargar imágenes de Zot** para que el Deployment arranque: el
  kubelet no resuelve nombres `*.svc.cluster.local`, así que hace falta exponer el registry
  y declararlo como mirror en `registries.yaml` de k3s. Hoy **no está configurado**.
- StorageClass `nfs-writable` (workspace RWX) y vLLM `qwen3-8b` en el ns `inference` (modo `llm`).
- El repo es **privado**: Argo CD necesita credenciales de solo lectura para el `repoURL`.

## Ejecutar

El material **no está desplegado** en el clúster; estos son los pasos para la demo.

```bash
kubectl create namespace openclaw-duel

# Clave cosign: nunca va a Git (ver «Clave cosign»)
cosign generate-key-pair k8s://openclaw-duel/duel-cosign-keys

# Código de los agentes como ConfigMap (fuente única: 04-ai-agents/red-blue-agents)
kubectl -n openclaw-duel create configmap duel-agent-src \
  --from-file=../../04-ai-agents/red-blue-agents/ --dry-run=client -o yaml | kubectl apply -f -

# Pipeline + PipelineRun (o las Applications de ../argocd/)
kubectl apply -k .
tkn pipelinerun logs duel-devsecops-poisoned -n openclaw-duel -f
```

- **Acto 1** (el azul bloquea, no hay deploy): en `tekton/pipelinerun-poisoned-pr.yaml` pon `pr-diff: pr-01-obvious.diff`.
- **Modo `llm`** (A2A + vLLM local): `agent-mode: llm`. Si el LLM no responde, cae a `rules`.
- **Repetir**: `kubectl -n openclaw-duel delete pipelinerun duel-devsecops-poisoned` y vuelve a aplicar.

## Clave cosign

El par de claves **no se versiona**. `cosign generate-key-pair k8s://openclaw-duel/duel-cosign-keys`
crea el Secret con `cosign.key`, `cosign.pub` y `cosign.password` (el pipeline lee el password
del Secret). Copia `cosign.pub` en `../admission-policies/clusterpolicy-verify-images.yaml`
para que la admisión verifique con la misma clave. En producción: KMS (`--key kms://...`) o
firma keyless (OIDC + Fulcio/Rekor).

## SecurityContext

En k3s no hay SCC: los steps fijan `runAsNonRoot`, `runAsUser/Group: 1000`,
`allowPrivilegeEscalation: false`, `drop: ["ALL"]` y `seccompProfile: RuntimeDefault`, con
`fsGroup: 1000` para el workspace NFS (`0770`, sin permisos para "others"). Excepción
documentada: kaniko corre como root dentro de su task, con capabilities mínimas
(`CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETUID`, `SETGID`, `SETFCAP`).
