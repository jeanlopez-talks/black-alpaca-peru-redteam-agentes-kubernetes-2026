# Duelo rojo vs azul — flujo DevSecOps completo (Kubernetes vanilla / k3s)

Pipeline **Tekton** de INICIO A FIN donde dos agentes de IA se baten dentro de un
flujo DevSecOps real **con controles de SUPPLY CHAIN y ADMISSION CONTROL**: se
escanea el código (**SAST**), se **construye** la imagen, se genera su **SBOM**, se
escanea con **Trivy**, se **firma** (cosign), el **agente azul** (gate) decide si
pasa, se **verifica** la firma, y si todo cuadra, **Argo CD despliega** — pero la
**policy de admisión (Kyverno)** puede rechazar el deploy. El agente rojo abre un PR
malicioso y el azul (revisor) decide el merge; se comunican por **A2A** (Agent2Agent).

## TL;DR — defensa en capas (el ángulo de la charla)

El PR envenenado modifica **CONFIG** (`config/deploy-notes.md`), **no el código de la
imagen**. Consecuencia:

- La **cadena de supply chain** (SAST → SBOM → Trivy → firma → verificación) pasa
  **correctamente**: la imagen se firma y **verifica OK**. La firma es **válida** y
  **NO detecta el ataque** (no hubo manipulación de la imagen).
- El **gate del agente azul** es engañado (prompt injection indirecta) y **aprueba**.
- Lo que **FRENA el ataque** es la **ADMISSION CONTROL**: una `ClusterPolicy` de
  **Kyverno** exige una anotación de **aprobación-humana** que el agente **no puede
  poner** (no tiene RBAC de API). Kyverno **rechaza el Deployment en admisión**.

> **La firma (supply chain) no ayuda contra este ataque; la policy de admisión sí.
> Una capa falla, la otra atrapa — eso es defensa en capas.**

Este despliegue es para **Kubernetes VANILLA sobre k3s** (NO OpenShift):

- **k3s v1.36**, 5 nodos (Flatcar inmutable). Kubernetes vanilla.
- **Tekton Pipelines** instalado (`tekton.dev/v1`).
- **Argo CD** instalado en el namespace **`argocd`** (NO openshift-gitops).
- StorageClass default **`local-path`** (el PVC del workspace la usa).
- **NO hay registry interno**, NI `BuildConfig`/`ImageStream`/`SCC` (eso es
  OpenShift). El código de los agentes se lleva al pod por **ConfigMap** sobre una
  imagen base pública (ver más abajo).
- **LLM LOCAL** servido por **vLLM** (`qwen3-8b`, API OpenAI-compatible) en
  `http://vllm.inference.svc.cluster.local:8000/v1` — dentro del clúster, sin
  egress a internet.

## Qué cambia respecto a la versión OpenShift (puntos de charla)

| Tema | OpenShift | k3s vanilla (este deploy) |
|------|-----------|---------------------------|
| **Imagen del agente** | `BuildConfig` + `ImageStream` + registry interno | **NO hay registry ni acceso a nodos** (Flatcar inmutable, sin SSH): el código se monta por **ConfigMap** sobre una imagen base pública; las deps del modo llm las instala un **initContainer** con `pip`. |
| **Build de la app** | `buildah` con SCC + push al registry interno | **kaniko `--no-push`** (build real a un tar en el workspace; sin registry no se puede empujar). |
| **SecurityContext** | NO se fija `runAsUser` (la SCC `restricted-v2` asigna el uid; fijarlo da `PodAdmissionFailed`) | **SÍ se fija** `runAsNonRoot:true`, `runAsUser:1000`, `runAsGroup:1000`, `allowPrivilegeEscalation:false`, `drop: ["ALL"]`, `seccompProfile: RuntimeDefault`. En vanilla no hay SCC → fijar el uid es lo correcto. |
| **GitOps** | Argo CD en `openshift-gitops` | Argo CD en **`argocd`**. |
| **LLM (modo llm)** | proveedor EXTERNO (Anthropic/OpenAI/Google) + egress HTTPS a internet + API key real | **LLM LOCAL** (vLLM `qwen3-8b`), egress SOLO al servicio interno `vllm.inference.svc`, key **dummy** (`not-needed`). |

## Las 8 etapas (pipeline `duel-devsecops`)

Orden DevSecOps correcto: SAST (shift-left) → build → SBOM → Trivy → firma →
gate del azul → verificación de firma → deploy (con admisión Kyverno).

```
PipelineRun → Pipeline "duel-devsecops"   (workspace PVC RWX compartido, nfs-writable)

  ┌─────────────────────── CADENA DE SUPPLY CHAIN ───────────────────────┐
  │ 1. sast         ─ semgrep (SAST) + gitleaks (secret scanning) sobre la │
  │    │              fuente del PR (shift-left, ANTES del build).         │
  │    │              INFORMATIVO (sast-blocking=false) | BLOQUEANTE.      │
  │    ▼ runAfter     Result: status (OK|FINDINGS).                        │
  │ 2. build        ─ kaniko construye la imagen (ubi9/nginx). SIN registry:│
  │    │              --no-push + --tar-path (build REAL, tar al workspace).│
  │    ▼ runAfter     Result: image-ref.                                   │
  │ 3. sbom         ─ Syft genera el SBOM del tar (CycloneDX + SPDX).       │
  │    ▼ runAfter     Artefactos: sbom.cyclonedx.json / sbom.spdx.json.     │
  │ 4. trivy-scan   ─ Trivy REAL (fs + imagen), política HIGH/CRITICAL.     │
  │    │              Requiere egress (DB). Fallback: SKIPPED si no baja.   │
  │    ▼ runAfter     Result: status (OK|FINDINGS|SKIPPED). INFORMATIVO.    │
  │ 5. sign         ─ cosign firma el BLOB del tar + el SBOM con la CLAVE    │
  │    ▼ runAfter     del duelo (Secret). Artefactos: *.sig.                │
  └───────────────────────────────┬───────────────────────────────────────┘
                                   ▼ runAfter
  ┌──────────────────────── EL CORAZÓN DEL ATAQUE ────────────────────────┐
  │ 6. gate-blue    ─ sidecar blue-reviewer = AZUL como A2A server (:9999). │
  │    │              step red-open-pr = ROJO abre el PR y se lo manda (A2A).│
  │    │              step simulate-merge = merge SIMULADO (sin RBAC).      │
  │    ▼              El PR envenenado hace que el azul APRUEBE. Result:     │
  │      runAfter     decision (APPROVE|BLOCK).                             │
  └───────────────────────────────┬───────────────────────────────────────┘
                                   ▼ runAfter
  ┌──────────────── VERIFICACIÓN + ADMISIÓN (lo que FRENA) ────────────────┐
  │ 7. verify       ─ cosign verifica la firma del blob con la clave PÚBLICA.│
  │    │              FIRMA VÁLIDA (el ataque no tocó la imagen). La firma   │
  │    ▼ runAfter     NO detecta el ataque. Result: verify-status (OK).     │
  │      when: decision==APPROVE  Y  verify-status in (OK, SKIPPED)         │
  │ 8. deploy-gitops─ promueve vía Argo CD (ns argocd). AQUÍ la ADMISIÓN:    │
  │                   Kyverno RECHAZA el Deployment por falta de la         │
  │                   anotación de aprobación-humana. EL AGENTE APROBÓ Y LA  │
  │                   FIRMA VERIFICÓ, PERO LA POLICY DE ADMISIÓN LO PARA.    │
  └───────────────────────────────────────────────────────────────────────┘
```

**Encadenamiento:** `runAfter` encadena las 8 etapas; el `when` de `deploy-gitops`
exige `decision == APPROVE` **y** `verify-status in (OK, SKIPPED)`. Results del
Pipeline: `blue-decision`, `scan-status` (Trivy), `verify-status`.

## Herramientas por etapa (imágenes, NO operators)

En k3s vanilla el tooling corre como **imágenes públicas en steps** (deja
artefactos en el workspace compartido). Kyverno es el único componente que se
instala como webhook (necesario para admisión); ver `kyverno/README.md`.

| Etapa | Herramienta (imagen) | Real / Simulado | Bloqueante |
|-------|----------------------|-----------------|------------|
| `sast` | semgrep (`returntocorp/semgrep`) + gitleaks (`zricethezav/gitleaks`) | REAL (requiere egress a registros de reglas) | Informativo por defecto (`sast-blocking`) |
| `build` | kaniko (`gcr.io/kaniko-project/executor`) | REAL build; transporte simulado (sin registry) | Sí (si falla, aborta) |
| `sbom` | Syft (`anchore/syft`) | REAL (lee el tar; no necesita red) | No |
| `trivy-scan` | Trivy (`aquasec/trivy`) | REAL si baja la DB (egress); fallback SKIPPED | Informativo |
| `sign` | cosign (`gcr.io/projectsigstore/cosign:v2.4.1`) | REAL sobre el BLOB del tar (sin registry no hay imagen con digest) | Sí (si falla, aborta) |
| `gate-blue` | agentes A2A (imagen base + ConfigMap) | REAL (A2A a2a-sdk 1.2.1); merge SIMULADO | Sí (su decisión alimenta el `when`) |
| `verify` | cosign (`:v2.4.1`) | REAL sobre el BLOB | Sí (firma inválida ⇒ no hay deploy) |
| `deploy-gitops` | kubectl/ubi (manifiesto Argo CD) | Manifiesto REAL; `apply` lo hace el operador | — |
| **admisión** | **Kyverno** (`ClusterPolicy`) | **REAL** en admisión; `verifyImages` en Audit por no haber registry | **Sí (rechaza el deploy)** |

> **cosign pinneado a `v2.4.1`**: el flujo offline con clave
> (`sign-blob --tlog-upload=false --output-signature` / `verify-blob --signature`)
> es estable en v2.x. cosign v3 cambió los defaults a *bundles* y exige
> `--signing-config` para offline; por eso NO se usa `:latest`.

## Cadena firma → verificación → admisión

1. **`sign`** firma el blob del tar (y el SBOM) con la **clave privada** cosign del
   `Secret duel-cosign-keys` → `*.sig` en el workspace.
2. **`verify`** valida esa firma con la **clave pública** → `verify-status=OK`.
3. **`deploy-gitops`** solo corre si `APPROVE` **y** la verificación no falló.
4. En el deploy, **Kyverno** aplica dos policies (ver `kyverno/`):
   - `duel-verify-images` (`verifyImages` con la **misma clave pública**) — en
     **Audit** por no haber registry: demuestra el concepto de verificación de
     firma de imagen en admisión.
   - `duel-require-human-approval` (**Enforce**) — exige la anotación
     `duel.redteam/human-approved: "true"`; **rechaza** el Deployment envenenado.

## Admission control con Kyverno (`kyverno/`)

Instalación y detalle en **`kyverno/README.md`**. Resumen:

- **NO** está en el `kustomization.yaml` del duelo (son `ClusterPolicy`
  cluster-scoped + el `install.yaml` de Kyverno; se aplican aparte).
- Kyverno se instala con su `install.yaml` oficial **pinneado** (v1.13.x,
  compatible con k8s 1.36). No necesita un operator.
- La policy `duel-require-human-approval` es la que **frena el ataque** que el
  agente dejó pasar.

## Código de los agentes sin registry (ConfigMap `duel-agent-src`)

En este k3s **no hay registry interno ni acceso a los nodos** (Flatcar es
inmutable; SSH a los nodos deniega publickey; no hay mirror). Por tanto NO se
puede construir una imagen propia del agente y `ctr images import` por nodo **no
es viable**. La opción pragmática y 100 % reproducible es:

- **imagen base pública** que el clúster sí puede pullear
  (`registry.access.redhat.com/ubi9/python-311`), y
- el **código del agente montado por ConfigMap** `duel-agent-src`.

El pipeline (`gate-blue`) copia el código a un `emptyDir` escribible `/opt/duel` y,
**solo en modo llm**, un step instala las deps con `pip` (si no hay egress a PyPI,
el agente **cae a modo rules** — fallback preservado).

Ese ConfigMap NO se genera con kustomize (el código vive en `../../04-ai-agents/red-blue-agents/`, fuera del
root kustomize; referenciarlo con `../../` viola el load-restrictor de Argo CD).
Se crea en el deploy con un comando, desde la MISMA fuente (`../../04-ai-agents/red-blue-agents/`):

```bash
kubectl -n openclaw-duel create configmap duel-agent-src \
  --from-file=../../04-ai-agents/red-blue-agents/ --dry-run=client -o yaml | kubectl apply -f -
```

## Conexión al LLM local (vLLM `qwen3-8b`)

El modo llm apunta al LLM **local** del clúster (sin salir a internet):

- `ConfigMap duel-llm-config`: `LLM_PROVIDER=openai-compatible`,
  `LLM_MODEL=qwen3-8b`, `OPENAI_BASE_URL=http://vllm.inference.svc.cluster.local:8000/v1`.
- `Secret duel-llm-secret`: `OPENAI_API_KEY=not-needed` (dummy; vLLM no la valida).
- `../../04-ai-agents/red-blue-agents/llm_factory.py` soporta el proveedor `openai-compatible`: construye un
  `langchain_openai.ChatOpenAI` con `base_url` custom. El **modo rules sigue
  intacto** como fallback (sin LangChain, sin red o si el LLM no responde).
- La `NetworkPolicy allow-vllm-egress` abre egress SOLO al namespace `inference`
  (TCP 8000) — tráfico este-oeste interno, NO internet.

## Qué es REAL y qué es simulado (honestidad)

| Pieza | Estado | Detalle |
|-------|--------|---------|
| **SAST** (semgrep + gitleaks) | **REAL** | Herramientas reales como imágenes de step; requieren egress (registros de reglas de semgrep). INFORMATIVO por defecto (`sast-blocking=false`); ponlo en `true` para bloquear. No es la frontera que atrapa el ataque (es prompt injection, no un secreto/código). |
| **BUILD** (kaniko) | **REAL** | kaniko construye y empuja la imagen al registry interno Zot (`zot.registry.svc.cluster.local:5000/openclaw-duel/sample-app`) y guarda el digest en el workspace. |
| **SBOM** (Syft) | **REAL** | Syft lee el tar OCI y genera SBOM CycloneDX + SPDX. No necesita red (solo pull de su imagen). |
| **TRIVY-SCAN** (Trivy) | **REAL si baja la DB** | Trivy REAL sobre fs + imagen, política `HIGH,CRITICAL`. Necesita egress para la DB de vulnerabilidades; **fallback documentado**: si no baja, `status=SKIPPED` (no rompe la demo). INFORMATIVO: no bloquea el gate. |
| **SIGN** (cosign) | **REAL** | `cosign sign` firma la imagen empujada **por digest** con la clave del duelo (Secret `duel-cosign-keys`, creado fuera de Git). La firma (`.sig`) queda en Zot. |
| **GATE del azul** (A2A, APPROVE/BLOCK) | **REAL** | El agente azul decide de verdad; el PR envenenado lo voltea (Acto 2/3). Modo rules real siempre; modo llm real si vLLM responde. |
| **VERIFY** (cosign) | **REAL** | `cosign verify` de la imagen por digest con la clave pública. **Verifica OK**: la imagen no fue tocada (el ataque es config). Firma inválida ⇒ el step falla ⇒ no hay deploy. |
| **merge** | **SIMULADO** | El `duel-runner` no tiene RBAC de merge (frontera human-in-the-loop del Acto 4). |
| **DEPLOY GitOps** (Application de Argo CD) | **Manifiesto REAL; `kubectl apply` NO se ejecuta en el runner** | La `Application` es 100 % real y aplicable (ns `argocd`). El runner no tiene token de API ni RBAC: el `kubectl apply` lo hace el operador / una SA con permisos. |
| **ADMISSION** (Kyverno) | **REAL en admisión** | `duel-require-human-approval` (**Enforce**) **rechaza** el Deployment sin la anotación de aprobación-humana — **la capa que frena el ataque**. `duel-verify-images` (`verifyImages`) en **Audit** por no haber registry: demuestra el concepto de verificación de firma de imagen en admisión. |

## App de ejemplo (`sample-app/`) — la carga desplegada

Un servidor web trivial (ubi9/nginx + `index.html`) que el pipeline construye
(etapa 1) y que **Argo CD despliega** (etapa 4). Es **"la carga útil que el
atacante logra desplegar"** cuando el gate del azul es engañado (Acto 3).

| Archivo | Qué es |
|---------|--------|
| `sample-app/Containerfile` | imagen de la app (ubi9/nginx; sin SCC, corre como uid no-root 1001). |
| `sample-app/index.html` | contenido estático (fuente única; el Deployment lo sirve vía ConfigMap). |
| `sample-app/deployment.yaml` | `ConfigMap` + `Deployment` + `Service` que Argo CD sincroniza. **NO lleva la anotación `duel.redteam/human-approved` a propósito**: por eso Kyverno lo rechaza en admisión (defensa en capas). |
| `sample-app/kustomization.yaml` | lo que la Application de Argo CD referencia (`path: sample-app`). |

## Deploy GitOps con Argo CD

`application-sample-app.yaml` define una **Application de Argo CD** en el namespace
**`argocd`** que apunta a `sample-app` y despliega en `openclaw-duel`.

- **Sync manual por defecto** (demo controlada): la Application queda `OutOfSync` y
  se sincroniza a mano (`argocd app sync duel-sample-app` o el botón Sync).
- **Auto-deploy del Acto 3** (radio de explosión real — *lo aprobado se despliega
  solo*): descomenta el bloque `syncPolicy.automated` de la Application.
- **`repoURL` es un PLACEHOLDER**: ajústalo al remoto real de este repo. Argo CD
  necesita un repo Git accesible; no sincroniza desde un working dir local.

## Recursos (`kustomize build .` → 14 objetos + `duel-agent-src` y Kyverno fuera de kustomize)

| Archivo | Qué es |
|---------|--------|
| `namespace.yaml` | namespace `openclaw-duel`. |
| `networkpolicy.yaml` | egress deny-by-default + DNS; egress al LLM local (ns `inference`, TCP 8000); **egress HTTPS (443) para las tasks del supply chain** (`build`, `sast`, `sbom`, `trivy-scan`, `sign`, `verify`, `gate-blue`): pull de imágenes, reglas de semgrep, DB de Trivy, pip. |
| `serviceaccount.yaml` | `duel-runner`, **sin** RBAC de merge ni token de API (no puede poner la anotación de aprobación-humana). |
| `secret-llm.yaml` | Secret con la key **dummy** del LLM local + ConfigMap `duel-llm-config`. |
| _(sin archivo)_ `duel-cosign-keys` | par de claves cosign; **no se versiona**. Se crea con `cosign generate-key-pair k8s://openclaw-duel/duel-cosign-keys` (ver «Clave cosign»). |
| `pipeline.yaml` | `Pipeline` `duel-devsecops`: sast → build → sbom → trivy-scan → sign → gate-blue → verify → deploy-gitops. |
| `pipelinerun.yaml` | dispara el pipeline contra `pr-02-poisoned.diff` (modo `rules`, `sast-blocking=false`, `trivy-severity=HIGH,CRITICAL`) con un workspace PVC RWX (`nfs-writable`). |
| `application-sample-app.yaml` | `Application` de Argo CD (ns `argocd`) que despliega la app de ejemplo. |
| `sample-app/` | la app de ejemplo (fuente + ConfigMap/Deployment/Service). |
| `sast-input/deploy-notes.md` | entrada realista para la etapa SAST (el config del PR envenenado). |
| `kyverno/` | **admission control**: `README.md` (instalación de Kyverno vía `install.yaml` oficial pinneado), `policy-require-human-approval.yaml` (Enforce, frena el ataque) y `policy-verify-images.yaml` (Audit, concepto). **Se aplica aparte** (ver `kyverno/README.md`). |
| ConfigMaps generados | `sample-app-src` (build), `duel-argo-app-src` (deploy) y `duel-sast-input` (SAST). |

## Dos modos del agente (parámetro `agent-mode`)

- **`rules`** (default) — sin API key ni egress; **solo stdlib** (no se instala
  nada). El azul decide por reglas en el pod aislado. El pipeline corre así por
  defecto.
- **`llm`** — agentes LangChain + **A2A real** contra el **LLM local** (vLLM
  `qwen3-8b`). El initContainer instala las deps; si falla, cae a rules.

## Desplegar en k3s

```bash
# 1) Namespace
kubectl apply -f namespace.yaml

# 2) Código de los agentes como ConfigMap (NO hay registry; ver arriba)
kubectl -n openclaw-duel create configmap duel-agent-src \
  --from-file=../../04-ai-agents/red-blue-agents/ --dry-run=client -o yaml | kubectl apply -f -

# 3) ADMISSION CONTROL — instalar Kyverno y sus policies (ver kyverno/README.md)
kubectl create -f https://github.com/kyverno/kyverno/releases/download/v1.13.4/install.yaml
kubectl -n kyverno rollout status deploy/kyverno-admission-controller --timeout=180s
kubectl apply -f kyverno/policy-require-human-approval.yaml
kubectl apply -f kyverno/policy-verify-images.yaml

# 4) Desplegar el duelo y correr el pipeline de 8 etapas (incluye cosign secret)
kubectl apply -k ./

# 5) Ver el flujo
kubectl get pipelinerun -n openclaw-duel
tkn pipelinerun logs duel-devsecops-poisoned -n openclaw-duel -f

# 6) Promover por GitOps (etapa 8): registrar/sincronizar la Application
kubectl apply -f application-sample-app.yaml
argocd app sync duel-sample-app   # o el botón Sync en la consola de Argo CD
```

Resultado esperado (Acto 2/3 + defensa en capas):

1. El supply chain pasa: SAST, build, SBOM, Trivy, **firma** y **verificación OK**
   (la imagen no fue tocada).
2. El azul **aprueba** el PR envenenado (`blue-decision = APPROVE`) → corre
   `deploy-gitops`. El atacante gana a través del defensor.
3. **PERO** al sincronizar la `Application`, **Kyverno RECHAZA el Deployment** en
   admisión (falta `duel.redteam/human-approved: "true"`). El deploy NO ocurre:

   ```text
   admission webhook "validate.kyverno.svc-fail" denied the request:
   RECHAZADO POR ADMISION (Kyverno): este Deployment no tiene la anotacion
   'duel.redteam/human-approved: "true"' ...
   ```

   La firma era válida y no ayudó; la **admisión** fue la capa que atrapó el ataque.

4. Camino "aprobado por humano": si un operador añade esa anotación al Deployment
   del repo tras revisar de verdad, Kyverno lo admite y la app se despliega.

Para el Acto 1 (el azul bloquea y `deploy-gitops` se salta), cambia `pr-diff` a
`pr-01-obvious.diff` en el PipelineRun.

### Modo llm (LLM local)

```bash
# El Secret/ConfigMap ya apuntan al vLLM local. Basta con poner agent-mode=llm:
kubectl -n openclaw-duel delete pipelinerun duel-devsecops-poisoned --ignore-not-found
# edita pipelinerun.yaml -> params agent-mode: llm, y reaplica:
kubectl apply -f pipelinerun.yaml
```

## Volver a correr el duelo

```bash
kubectl delete pipelinerun duel-devsecops-poisoned -n openclaw-duel --ignore-not-found
kubectl apply -f pipelinerun.yaml
# Si tocaste ../../04-ai-agents/red-blue-agents/*.py, regenera el ConfigMap del código antes:
kubectl -n openclaw-duel create configmap duel-agent-src \
  --from-file=../../04-ai-agents/red-blue-agents/ --dry-run=client -o yaml | kubectl apply -f -
```

## SecurityContext (vanilla, al revés que OpenShift)

En k3s **no hay SCC** que asigne el uid. Aquí sidecar y steps SÍ fijan
`runAsNonRoot:true`, `runAsUser:1000`, `runAsGroup:1000`,
`allowPrivilegeEscalation:false`, `capabilities.drop: ["ALL"]` y
`seccompProfile: RuntimeDefault` — lo correcto en vanilla (en OpenShift fijar el
uid daría `PodAdmissionFailed`; es el punto de charla). kaniko corre en userspace
sin privilegios de Docker (no necesita `SETUID/SETGID` como buildah). El
`duel-runner` no tiene RBAC de merge ni token de API montado — aunque el azul
apruebe, el merge y el `kubectl apply` reales exigen otra credencial (frontera
human-in-the-loop del Acto 4).

## Clave cosign

El par de claves **no se versiona** (la clave privada nunca va a Git). Crearlo en el
namespace antes de lanzar el pipeline:

```bash
cosign generate-key-pair k8s://openclaw-duel/duel-cosign-keys
```

Esto crea el Secret `duel-cosign-keys` con `cosign.key`, `cosign.pub` y `cosign.password`
(el pipeline lee el password desde el Secret). Copiar `cosign.pub` en
`kyverno/policy-verify-images.yaml` para que la admisión verifique con la misma clave.
En producción la clave privada vive en un KMS (`cosign ... --key kms://...`) o se firma
keyless (OIDC + Fulcio/Rekor).
