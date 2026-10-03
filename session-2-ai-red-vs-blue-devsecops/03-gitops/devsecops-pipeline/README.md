# DevSecOps pipeline — duelo rojo vs azul (k3s)

Pipeline Tekton de 8 etapas donde dos agentes de IA se enfrentan dentro de un flujo
DevSecOps con supply chain real. El agente rojo abre un PR envenenado; el azul (revisor
LLM) decide el merge. Se comunican por **A2A**. Lo sincroniza la Application
`ai-red-vs-blue-devsecops-pipeline` (`../argocd/application-devsecops-pipeline.yaml`).

## Estructura

```
devsecops-pipeline/
├── kustomization.yaml
├── base/                              infraestructura del namespace (lo crea admission-policies)
│   ├── serviceaccount-duel-runner.yaml    runner SIN token de API ni RBAC
│   ├── networkpolicies-egress.yaml        deny-by-default + DNS, vLLM, Zot, 443 por task
│   ├── llm-config.yaml                    ConfigMap del LLM local (vLLM, sin secreto)
│   ├── serviceaccount-openbao-reader.yaml identidad del SecretStore (no se monta en pods)
│   ├── secretstore-openbao.yaml           rol de OpenBao que solo lee la clave de firma
│   └── externalsecret-duel-cosign-keys.yaml  par de claves cosign desde OpenBao
├── agents/                            agente azul como servicio A2A en sandbox
│   ├── deployment-blue-reviewer.yaml       postura vulnerable (Actos 1-3)
│   ├── deployment-blue-reviewer-hardened.yaml  postura endurecida (Acto 4)
│   ├── service-*.yaml, serviceaccount-blue-reviewer.yaml (sin token de API)
│   └── networkpolicy-blue-reviewer.yaml   entra solo el rojo; sale solo a DNS y LLM
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

Las policies de Kyverno (namespaced) viven aparte, en `../admission-policies/`.

## Las 8 etapas

| # | Etapa | Herramienta | Qué hace | ¿Bloquea? |
|---|-------|-------------|----------|-----------|
| 1 | `sast` | semgrep 1.90 + gitleaks 8.21 | SAST y secretos sobre la fuente del PR | Informativo (`sast-blocking`) |
| 2 | `build` | kaniko 1.23 | construye la imagen y la **empuja a Zot**; guarda el digest | Sí |
| 3 | `sbom` | Syft 1.18 | SBOM CycloneDX + SPDX | No |
| 4 | `trivy-scan` | Trivy 0.58 | escanea la imagen de Zot (`HIGH,CRITICAL`) | Informativo |
| 5 | `sign` | cosign 2.4.1 | firma la imagen **por digest**; la firma queda en Zot | Sí |
| 6 | `gate-blue` | agentes A2A | el rojo (step, cliente A2A) envía el PR al azul (servicio A2A en sandbox) → `APPROVE`/`BLOCK` | Su decisión alimenta el `when` |
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
| SAST, build + push, SBOM, Trivy, firma y verificación | **Reales** contra Zot (evidencia: `../../04-ai-agents/evidence/k3s-supply-chain-run.md`) |
| Gate del azul (A2A) | **Real**: modo `rules` siempre; modo `llm` si vLLM responde |
| Merge del PR | **Simulado**: el `duel-runner` no tiene RBAC de merge (frontera human-in-the-loop) |
| `deploy-gitops` | Muestra el manifiesto real de la Application; el `kubectl apply` lo hace el operador (el runner no tiene credenciales) |
| Admisión Kyverno | **Real** |

## Requisitos de plataforma (repo del homelab, no este)

- Tekton Pipelines, Argo CD (ns `argocd`), Kyverno v1.19 y External Secrets.
- Registry Zot: el pipeline escribe por la ruta interna (`zot.registry.svc.cluster.local:5000`)
  y los nodos y Kyverno leen por `registry.labjp.xyz` (Gateway interno, TLS de Let's Encrypt).
- **OpenBao**: rol `black-alpaca-duel-pipeline` (auth kubernetes) ligado a
  `devsecops-duel/openbao-reader`, con política de solo lectura sobre
  `homelab/data/apps/black-alpaca/duel-cosign-keys`.
- StorageClass `nfs-writable` (workspace RWX) y vLLM `qwen3-8b` en el ns `inference` (modo `llm`).
- El repo es **privado**: Argo CD necesita credenciales de solo lectura para el `repoURL`.

## Ejecutar

El material **no está desplegado** en el clúster. Para la demo se despliega con Argo CD
(`../argocd/`: `kubectl apply -k ../argocd`) y se sincroniza a mano la Application del
pipeline, que lanza el PipelineRun:

```bash
argocd app sync ai-red-vs-blue-devsecops-pipeline
tkn pipelinerun logs duel-devsecops-poisoned -n devsecops-duel -f
```

- **Acto 1** (el azul bloquea, no hay deploy): en `tekton/pipelinerun-poisoned-pr.yaml` pon `pr-diff: pr-01-obvious.diff`.
- **Acto 4** (el azul endurecido contiene el ataque): `blue-reviewer-url` apuntando a
  `http://blue-reviewer-hardened.devsecops-duel.svc.cluster.local:9999/`.
- **Modo `llm`** (el azul razona con el vLLM local): `AGENT_MODE: llm` en el Deployment del
  azul. Si el LLM no responde, cae a reglas.

## Agentes en sandbox

Los agentes corren desde una imagen propia (`../../04-ai-agents/Containerfile`), sin
`pip install` en runtime ni código montado por ConfigMap, y cada uno con lo mínimo:

| Agente | Dónde corre | Identidad | Red |
|--------|-------------|-----------|-----|
| Azul (vulnerable y endurecido) | Deployment propio | SA sin token de API | entra solo el rojo; sale solo a DNS y al LLM |
| Rojo | step `red-open-pr` de `gate-blue` | `duel-runner` sin token ni RBAC | sale solo hacia el azul (puerto A2A) |

Todos: uid no-root, raíz de solo lectura, `drop: ALL`, `seccompProfile: RuntimeDefault`.

## Clave cosign

El par de claves **no se versiona ni se crea a mano en el clúster**: vive en OpenBao y
llega por `ExternalSecret`. Se genera una vez fuera del clúster y se siembra:

```bash
COSIGN_PASSWORD="$(openssl rand -hex 32)" cosign generate-key-pair
bao kv put homelab/apps/black-alpaca/duel-cosign-keys \
  cosign.key=@cosign.key cosign.pub=@cosign.pub cosign.password="$COSIGN_PASSWORD"
shred -u cosign.key
```

Copia `cosign.pub` en `../admission-policies/namespacedimagevalidatingpolicy-verify-images.yaml`
para que la admisión verifique con la misma clave. En producción: KMS (`--key kms://...`) o
firma *keyless* (OIDC + Fulcio/Rekor).

## SecurityContext

En k3s no hay SCC: los steps fijan `runAsNonRoot`, `runAsUser/Group: 1000`,
`allowPrivilegeEscalation: false`, `drop: ["ALL"]` y `seccompProfile: RuntimeDefault`, con
`fsGroup: 1000` para el workspace NFS (`0770`, sin permisos para "others"). Excepción
documentada: kaniko corre como root dentro de su task, con capabilities mínimas
(`CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETUID`, `SETGID`, `SETFCAP`).
