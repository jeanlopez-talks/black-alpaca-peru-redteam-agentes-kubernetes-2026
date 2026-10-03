# Backstage (IDP) + Agente DevSecOps — desplegado por Argo CD (GitOps)

Portal de developer (Backstage) sobre el flujo DevSecOps del duelo, mas un
**agente interactivo human-in-the-loop** que resume el pipeline y PROPONE
acciones que un humano confirma. **Todo gestionado por Argo CD** (GitOps): los
manifiestos viven aqui (`./`) y una Application de Argo CD los
sincroniza.

Versión **Kubernetes vanilla (k3s)**, igual que el duelo y las posturas: Argo CD
en el namespace `argocd`, MetalLB, sin registry interno.

---

## Narrativa (por qué esto importa en la charla)

El riesgo central de la charla es **un agente con poder de acción** sobre un
pipeline: si el agente puede desplegar, un prompt injection indirecto (el PR
envenenado) termina en producción. Backstage + este agente modelan la
**mitigación**: el agente es el **punto de interacción humano ↔ pipeline**, y su
diseño es **"propone pero NO actúa sin aprobación"**.

El flujo de aprobación:

1. El humano ve en Backstage el estado del pipeline (plugin Tekton) y de GitOps
   (plugin Argo CD).
2. El agente **resume** cada etapa (sast/build/sbom/trivy/sign/gate/verify/deploy)
   y **explica** por qué se aprobó/rechazó. En el duelo: el gate del azul aprueba,
   la firma cosign es válida, pero el **deploy lo frena Kyverno** por faltar la
   anotación de aprobación humana.
3. El agente **propone** acciones (re-run, aprobar-con-anotación, abrir ticket).
4. El humano **confirma** una propuesta (endpoint `/approve` con su token). Sólo
   entonces se pone la anotación `duel.redteam/human-approved` que Kyverno exige,
   y recién ahí el deploy pasa admisión.

El agente **no puede** poner esa anotación por su cuenta: no tiene RBAC de
escritura (sólo lectura de Tekton/Argo CD) y `/approve` exige un **token humano**.
Esa es la defensa en capas que la charla quiere mostrar.

---

## Estructura

```
../
  argocd/
    application-backstage.yaml   # Application `duel-backstage` (ns argocd) -> backstage/
  backstage/
    namespace.yaml               # ns `backstage`
    rbac.yaml                    # SA + ClusterRole SOLO LECTURA (Tekton/K8s)
    configmap-app-config.yaml    # app-config: plugins Argo CD + Tekton + k8s + catálogo
    configmap-catalog.yaml       # entidades del catálogo (System/Component/API)
    secret-integrations.yaml     # tokens Argo CD / K8s (PLACEHOLDERS)
    deployment.yaml              # Deployment + Service de Backstage
    service-lb.yaml              # LoadBalancer MetalLB (10.0.10.66)
    kustomization.yaml           # kustomize raíz (incluye agent/)
    agent/                       # el agente DevSecOps (human-in-the-loop)
      serviceaccount.yaml        #   SA + ClusterRole SOLO LECTURA (Tekton/Argo CD)
      secret-human-token.yaml    #   token humano de /approve (PLACEHOLDER)
      deployment.yaml            #   Deployment + Service (sin registry: código por ConfigMap)
      kustomization.yaml
```

El **código** del agente vive en `../../04-lab/backstage-agent/` (ver su README).

---

## Cómo se despliega vía Argo CD

```bash
# 1) (sin registry) crear el ConfigMap con el código del agente (ver abajo).
# 2) aplicar la Application de Argo CD al namespace argocd:
kubectl apply -f ../argocd/application-backstage.yaml
# 3) Argo CD sincroniza ./ -> crea ns backstage, Backstage y el agente.
```

> **AJUSTAR `repoURL`**: en `application-backstage.yaml` es un *placeholder* (la
> charla aún no está publicada). Cámbialo al remoto real del repo. Argo CD lee de
> un repo Git accesible; no sincroniza desde un working dir local.

### Código del agente sin registry (paso manual)

k3s vanilla no tiene registry interno ni acceso a los nodos. Igual que el duelo,
el código del agente se monta por ConfigMap. El `kustomization` **no** lo genera
(load-restrictor: el código está fuera del dir). Lo crea el operador:

```bash
kubectl create namespace backstage --dry-run=client -o yaml | kubectl apply -f -
kubectl -n backstage create configmap backstage-agent-src \
  --from-file=../../04-lab/backstage-agent/ --dry-run=client -o yaml | kubectl apply -f -
```

El `initContainer` del Deployment instala las deps (fastapi/uvicorn + opcional
langchain/kubernetes) y el contenedor arranca `server.py`.

---

## Cómo se accede

- **Portal Backstage**: `http://10.0.10.66` (Service LoadBalancer MetalLB).
  Ajusta la IP si 10.0.10.66 ya está usada (pool 10.0.10.60-79).
- **Agente** (interno): `http://backstage-devsecops-agent.backstage.svc/` con
  `/summary`, `/propose`, `/approve`. Backstage lo consume como API del catálogo;
  para probarlo a mano, `kubectl -n backstage port-forward svc/backstage-devsecops-agent 8080:80`.

Alternativa de exposición: en vez del Service LoadBalancer se puede usar un
HTTPRoute de Envoy Gateway (presente en el cluster). Se dejó LoadBalancer por
simplicidad de la demo.

---

## Plugins

- **Argo CD** (`roadiehq/backstage-plugin-argo-cd`): muestra las Application del
  cluster (duel, posturas, backstage) y su sync/health por componente del catálogo.
- **Tekton** (`backstage-plugin-tekton`): muestra los PipelineRun/TaskRun del
  pipeline `duel-devsecops` en `openclaw-duel`.
- **Kubernetes** (core): descubre los recursos de cada componente por label.

El catálogo trae el **System `duel-devsecops`** con los componentes `duel-pipeline`
y `backstage-devsecops-agent`, más la API del agente.

---

## Desplegable-ya vs requiere-build

| Pieza | Estado | Nota |
|---|---|---|
| Namespace, RBAC, Secrets, catálogo, agente | **Desplegable-ya** | se aplican tal cual |
| Backstage (portal base) | **Desplegable-ya** | imagen oficial `ghcr.io/backstage/backstage` (catálogo + plugin k8s) |
| Plugins **Argo CD / Tekton** en la UI | **Requiere-build** | no vienen en la imagen base; hace falta un build custom de Backstage que los declare en `package.json`. El `app-config` ya está listo: cuando exista el build, sólo se cambia la `image` del Deployment |
| Agente (imagen propia) | opcional | por defecto va **sin registry** (código por ConfigMap). El `Containerfile` cubre el build opcional |

> **Build custom de Backstage** (fuera del alcance de los manifiestos): crear una
> app Backstage con `npx @backstage/create-app`, añadir
> `@roadiehq/backstage-plugin-argo-cd` y `@janus-idp/backstage-plugin-tekton`,
> construir la imagen y empujarla a un registry que el cluster pueda pullear.
> Luego cambiar `image:` en `deployment.yaml`. El resto no cambia.

---

## Validación

```bash
kustomize build .      # -> 16 recursos, sin error
oc kustomize .         # consistencia
```

La `Application` (`application-backstage.yaml`) **no** está en el `kustomization`:
va al namespace `argocd` y se aplica aparte (igual que la del duelo).
