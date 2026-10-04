# DevSecOps pipeline — duelo rojo vs azul (k3s)

Pipeline Tekton de 8 etapas donde dos agentes de IA se enfrentan dentro de un flujo
DevSecOps con supply chain real. El agente rojo abre un PR envenenado; el azul (revisor)
decide el merge. Se comunican por **A2A**.

Lo despliega el **Argo CD del homelab**: el AppProject y las Applications viven en
`homelab-gitops` (`bootstrap/applications/talks/black-alpaca-2026/`), no aquí, para que
quien escribe en este repo no pueda ampliar sus propios permisos.

## Estructura

```
devsecops-pipeline/                    Application ai-red-vs-blue-devsecops-pipeline (automática)
├── kustomization.yaml
├── base/                              identidades, red y secretos del namespace
│   ├── serviceaccount-duel-runner.yaml        runner SIN token de API ni RBAC
│   ├── serviceaccount-sample-app-deployer.yaml credencial de despliegue (solo etapa deploy)
│   ├── role-/rolebinding-sample-app-deployer.yaml  crear/parchear el Deployment sample-app
│   ├── networkpolicies-egress.yaml        deny-by-default + DNS, Zot, 443 por task, API solo deploy
│   ├── llm-config.yaml                    ConfigMap del LLM local (vLLM, sin secreto)
│   ├── serviceaccount-openbao-reader.yaml identidad del SecretStore (no se monta en pods)
│   ├── secretstore-openbao.yaml           rol de OpenBao acotado a la clave de firma y al pull
│   ├── externalsecret-duel-cosign-keys.yaml  par de claves cosign
│   └── externalsecret-ghcr-pull.yaml      pull de la imagen privada de los agentes
├── agents/                            agente azul como servicio A2A en sandbox
│   ├── deployment-blue-reviewer.yaml           postura vulnerable (Actos 1-3)
│   ├── deployment-blue-reviewer-hardened.yaml  postura endurecida (Acto 4)
│   ├── service-*.yaml, serviceaccount-blue-reviewer.yaml (sin token de API)
│   └── networkpolicy-blue-reviewer.yaml   entra solo el rojo; sale solo a DNS y LLM
├── tekton/
│   └── pipeline-devsecops.yaml            Pipeline `duel-devsecops` (8 etapas)
├── pipeline-runs/                     Application …-pipeline-runs (sync MANUAL = lanzar el acto)
│   ├── pipelinerun-act1-obvious-pr.yaml       el azul bloquea el ataque obvio
│   ├── pipelinerun-act3-poisoned-pr.yaml      el azul aprueba; Kyverno frena al agente
│   └── pipelinerun-act4-hardened-reviewer.yaml el azul endurecido bloquea
├── sample-app/                        Application …-sample-app (la app objetivo, solo por GitOps)
│   ├── Containerfile, index.html          fuente de la imagen (ConfigMap sample-app-src)
│   ├── deployment-sample-app.yaml         SIN aprobación humana: la admisión lo rechaza
│   ├── service-sample-app.yaml
│   └── kustomization.yaml
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
| 8 | `deploy-gitops` | kubectl | solo si `APPROVE` **y** `verify-status == OK`: el agente intenta desplegar con su credencial | La admisión |

## Defensa en capas (el ángulo de la charla)

El PR envenenado modifica **config** (`config/deploy-notes.md`), no la imagen:

1. La supply chain pasa: la imagen se firma y **verifica OK**. La firma no detecta el ataque.
2. El azul es engañado por prompt injection indirecta y **aprueba**.
3. El agente tiene una credencial de despliegue (`sample-app-deployer`) y lo intenta dos
   veces. Kyverno (`duel-require-human-approval`) **rechaza las dos**:
   - con el manifiesto del PR: falta `duel.redteam/human-approved: "true"`;
   - falsificando la anotación: no la aplica Argo CD, es decir, no viene de un commit
     revisado. La anotación sola sería un texto que cualquiera con RBAC puede poner.
4. El único camino que entra es el humano: revisar el diff, añadir la anotación al
   Deployment en Git y dejar que Argo CD lo sincronice. Ahí actúa también
   `duel-verify-images`, que exige la firma cosign.

> Una capa falla, la otra atrapa.

## Qué es real y qué es simulado

| Pieza | Estado |
|-------|--------|
| SAST, build + push, SBOM, Trivy, firma y verificación | **Reales** contra Zot |
| Gate del azul (A2A) | **Real**: modo `rules` siempre; modo `llm` si vLLM responde |
| Merge del PR | **Simulado**: el runner no tiene credenciales de Git |
| Intento de despliegue del agente | **Real**: `kubectl apply` con su credencial |
| Admisión Kyverno | **Real** |
| Despliegue aprobado por un humano | **Real**: commit en Git + Argo CD |

## Requisitos de plataforma (repo del homelab, no este)

- Tekton Pipelines, Argo CD, Kyverno v1.19 y External Secrets.
- Namespaces `devsecops-duel` (PSA `baseline`) y `devsecops-agent` (PSA `restricted`),
  declarados en la gobernanza del homelab.
- Registry Zot: el pipeline escribe por la ruta interna (`zot.registry.svc.cluster.local:5000`)
  y los nodos y Kyverno leen por `registry.labjp.xyz` (Gateway interno, TLS de Let's Encrypt).
- **OpenBao**: rol `black-alpaca-duel-pipeline` (auth kubernetes, declarado en el rol
  `openbao_access` de homelab-ansible) ligado a `devsecops-duel/openbao-reader`, con
  lectura solo de `apps/black-alpaca/duel-cosign-keys` y `apps/ghcr-pull`.
- StorageClass `nfs-writable` (workspace RWX) y vLLM `qwen3-8b` en el ns `inference` (modo `llm`).
- Imagen `ghcr.io/labjp-homelab/devsecops-agents`, que publica el CI del homelab al
  etiquetar este repo con `agents-v<semver>` (firmada por Tekton Chains).

## Ejecutar la demo

Cada acto es un PipelineRun de la Application `ai-red-vs-blue-devsecops-pipeline-runs`
(sync manual). Desde la interfaz de Argo CD: *Sync* → marcar solo el PipelineRun del acto.
Por CLI:

```bash
argocd app sync ai-red-vs-blue-devsecops-pipeline-runs \
  --resource tekton.dev:PipelineRun:duel-act3-poisoned-pr
tkn pipelinerun logs duel-act3-poisoned-pr -n devsecops-duel -f
```

| Acto | PipelineRun | Resultado esperado |
|------|-------------|--------------------|
| 1 | `duel-act1-obvious-pr` | el azul **bloquea**; no hay deploy |
| 2-3 | `duel-act3-poisoned-pr` | el azul **aprueba**, la firma verifica, Kyverno **rechaza** los dos intentos del agente |
| 4 | `duel-act4-hardened-reviewer` | el azul endurecido **bloquea** |
| Humano | commit con `duel.redteam/human-approved: "true"` en `sample-app/deployment-sample-app.yaml` | Argo CD despliega la app firmada |

**Modo `llm`** (el azul razona con el vLLM local): `AGENT_MODE: llm` en el Deployment del
azul. Si el LLM no responde, cae a reglas.

## Agentes en sandbox

Los agentes corren desde una imagen propia (`../../04-ai-agents/Containerfile`), sin
`pip install` en runtime ni código montado por ConfigMap, y cada uno con lo mínimo:

| Agente | Dónde corre | Identidad | Red |
|--------|-------------|-----------|-----|
| Azul (vulnerable y endurecido) | Deployment propio | SA sin token de API | entra solo el rojo; sale solo a DNS y al LLM |
| Rojo | step `red-open-pr` de `gate-blue` | `duel-runner` sin token ni RBAC | sale solo hacia el azul (puerto A2A) |
| Etapa deploy | step `agent-deploy` de `deploy-gitops` | `sample-app-deployer`: solo el Deployment `sample-app` | sale solo al API server |

Todos: uid no-root, `drop: ALL`, `seccompProfile: RuntimeDefault`.

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
