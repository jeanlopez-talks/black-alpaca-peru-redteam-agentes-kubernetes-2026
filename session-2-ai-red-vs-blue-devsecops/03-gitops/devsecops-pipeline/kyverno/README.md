# Admission control con Kyverno — la capa que SI frena el ataque

Esta carpeta añade **control de admisión** al flujo DevSecOps del duelo. Es el
núcleo del ángulo **"defensa en capas / qué lo habría parado"**: aunque el agente
azul (el gate del pipeline) **apruebe** el PR envenenado, el **admission webhook de
Kyverno RECHAZA el deploy** porque falta la aprobación humana real.

## Por qué Kyverno (y no otra cosa) en este k3s

El clúster es **k3s vanilla**: NO hay Kyverno, NI Tekton Chains, NI
Sigstore/policy-controller, NI Gatekeeper preinstalados (kuadrant existe pero es un
API gateway, no hace admisión de imágenes). Kyverno se instala como un conjunto de
Deployments + webhooks (NO necesita un operator), con un `install.yaml` oficial — es
la vía más directa para tener `verifyImages` y `validate` en admisión sin construir
un operator a mano.

## Instalación (el coordinador la ejecuta por SSH; NO se corre desde aquí)

```bash
# Kyverno 1.13.x es compatible con Kubernetes 1.29–1.32+ (k8s 1.36 incluido).
# install.yaml oficial (pinneado a una versión, NO 'latest', por reproducibilidad):
kubectl create -f https://github.com/kyverno/kyverno/releases/download/v1.13.4/install.yaml

# Esperar a que los webhooks estén listos antes de aplicar policies:
kubectl -n kyverno rollout status deploy/kyverno-admission-controller --timeout=180s

# Aplicar las policies del duelo:
kubectl apply -f policy-require-human-approval.yaml
kubectl apply -f policy-verify-images.yaml
```

> **Egress:** el `install.yaml` se descarga desde GitHub (HTTPS). El clúster tiene
> egress a registries/GitHub, así que el pull de las imágenes de Kyverno
> (`ghcr.io/kyverno/...`) funciona. No requiere acceso a los nodos.

## Las dos policies

### 1. `policy-require-human-approval.yaml` — LA QUE FRENA EL ATAQUE

`ClusterPolicy` en modo **Enforce** que, para cualquier `Deployment` del namespace
`openclaw-duel`, **exige la anotación**
`duel.redteam/human-approved: "true"`. Esa anotación modela la **aprobación humana**:

- El **agente** (duel-runner) **NO puede ponerla**: no tiene RBAC de API (su SA es
  `automountServiceAccountToken: false` y sin RoleBinding — ver `serviceaccount.yaml`).
- Solo un **humano** (o una SA con permisos explícitos) la añade al manifiesto del
  repo tras revisar de verdad el cambio.

Resultado: el PR envenenado hace que el **gate del azul apruebe** (el pipeline
pasa), pero cuando Argo CD intenta aplicar el `Deployment` **sin** la anotación,
**Kyverno lo rechaza en admisión**. El ataque que el agente dejó pasar lo para la
policy. Esta es la demostración de **defensa en capas**.

### 2. `policy-verify-images.yaml` — la firma que NO ayuda aquí

`ClusterPolicy` con `verifyImages` (clave pública cosign) que exigiría que las
imágenes del namespace estén **firmadas** con la clave del duelo.

- **Por qué NO atrapa el ataque:** el PR envenenado modifica **CONFIG/documentación**
  (`config/deploy-notes.md`), **no el código de la imagen**. La imagen se construye,
  firma y verifica **correctamente** — la firma es **válida**. La supply chain de la
  imagen está intacta; el ataque va por otro canal (prompt injection en el config que
  revisa el agente). **La firma es necesaria pero NO suficiente.**
- **Limitación honesta en este clúster:** sin registry interno no hay una imagen con
  digest desplegable, así que esta policy queda en modo **Audit** (documentada) y
  demuestra el *concepto*. En un entorno real con registry estaría en **Enforce** y
  verificaría la imagen empujada contra la clave pública. La cadena
  firma→verificación SÍ es real en el pipeline (etapas `sign`/`verify` sobre el blob).

## La narrativa en una frase

> **La firma (supply chain) no ayuda contra este ataque porque el atacante no tocó
> la imagen; lo que lo frena es la policy de admisión que exige aprobación humana
> para el cambio de config. Defensa en capas: una capa falla, la otra atrapa.**
