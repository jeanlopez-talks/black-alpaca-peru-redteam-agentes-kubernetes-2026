# Matriz de Estandarización y Guía de Auditoría de Seguridad GitOps

> **Documento canónico de especificación técnica para agentes de IA y desarrolladores.**  
> Define los estándares obligatorios de seguridad, nomenclaturas, compatibilidad de APIs y verificación declarativa para todos los repositorios GitOps del homelab y los laboratorios de seguridad (`homelab-gitops` y `black-alpaca-peru-redteam-agentes-kubernetes-2026`).

---

## 1. Reglas y Estándares de Arquitectura (Checklist Automatizable)

Cualquier agente de IA o pipeline de CI debe verificar los siguientes 7 pilares antes de admitir o generar manifiestos:

### Regla 1: Kustomize Moderno y Declarativo
- **Versión de API:** Obligatorio `apiVersion: kustomize.config.k8s.io/v1beta1`.
- **Directivas estrictamente PROHIBIDAS (Deprecadas):**
  - ❌ `commonLabels:` (mutaba selectores inmutables en Deployments/StatefulSets).
  - ❌ `bases:` (sustituido por `resources:`).
  - ❌ `patchesJson6902:` y `patchesStrategicMerge:` (sustituidos por el bloque moderno `patches:`).
  - ❌ `vars:` (deprecado en favor de reemplazos estructurados).
- **Inyección de etiquetas:** Usar `labels:` con `includeSelectors: false`:
  ```yaml
  labels:
    - pairs:
        app.kubernetes.io/part-of: <nombre>
      includeSelectors: false
  ```
- **Comando de verificación:** `kubectl kustomize <directorio> > /dev/null` debe salir con código `0` y 0 advertencias stderr.

### Regla 2: Gestión de Helm y Charts
- **Versión de especificación:** Todos los `Chart.yaml` deben usar `apiVersion: v2` (estándar de Helm 3 y Helm 4).
- **Fijación de versión en Argo CD (`targetRevision`):**
  - Prohibido el uso de `latest`, `HEAD`, `master` o `main` en `spec.source.targetRevision`.
  - Debe especificarse siempre una versión semántica fija (ej. `2.10.2`, `v1.21.2`, `3.9.1`).
- **Valores de Seguridad en Charts Upstream:** Si el chart de terceros lo admite, sus `values:` deben configurar explícitamente `runAsNonRoot: true`, `drop: ["ALL"]` y recursos (requests/limits).

### Regla 3: Pod Security Standards (Restricted)
Todo Pod o Workload (`Deployment`, `StatefulSet`, `Job`, `CronJob`) de aplicación debe implementar:
```yaml
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000 # o UID no-root dedicado (ej. 65532 para distroless)
        runAsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: <app>
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            # Si la app requiere escribir temporales o sockets:
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: tmp
          emptyDir: {}
```
**Excepciones justificadas únicamente:**
- Drivers de almacenamiento del host (`csi-nfs`): requieren privilegios de montaje en nodo.
- Daemons de mantenimiento de nodo (`kured`, `node-exporter`): requieren reinicio y lectura de `/proc` del host.
- Binarios legados con *file capabilities* fijadas en la imagen (ej. Caddy Alpine con `cap_net_bind_service=+ep`): documentar explícitamente en el archivo.

### Regla 4: Hardening de Red (NetworkPolicies)
- **Política por defecto:** Cada namespace debe contar con una regla `default-deny` (`ingress` y `egress`).
- **Resiliencia de resolución DNS:** La regla de salida para DNS en `kube-system` no debe usar un `matchLabels` rígido; debe soportar tanto `kube-dns` como `coredns`:
  ```yaml
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchExpressions:
              - key: k8s-app
                operator: In
                values: [kube-dns, coredns]
      ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
  ```

### Regla 5: Gestión de Secretos Zero-Trust
- **Prohibición absoluta:** Cero objetos `Secret` con credenciales reales en Git.
- **Flujo autorizado:** Todo secreto fluye mediante `ExternalSecret` conectado a `OpenBao` con `SecretStore` o `ClusterSecretStore` namespaced.
- **Mínimo privilegio de API:** `automountServiceAccountToken: false` obligatorio en todos los Pods que no consuman directamente el Kubernetes API Server.

### Regla 6: Nomenclatura y Convenciones Técnicas
- **Idioma:** Inglés para todo artefacto técnico (carpetas, archivos, recursos k8s, campos de plantillas, labels).
- **Estilo:** `kebab-case` para carpetas, archivos y recursos k8s. `snake_case` para Python. `PascalCase` para clases.
- **Etiquetas estándar obligatorias:**
  - `app.kubernetes.io/name`
  - `app.kubernetes.io/instance`
  - `app.kubernetes.io/component`
  - `app.kubernetes.io/part-of`
  - `homelab.labjp.xyz/family` (en homelab)

### Regla 7: Detección y Prohibición de APIs Obsoletas
No deben utilizarse APIs retiradas en versiones modernas de Kubernetes (v1.22 a v1.34):
- ❌ `extensions/v1beta1`
- ❌ `networking.k8s.io/v1beta1` (usar `networking.k8s.io/v1` o Gateway API `gateway.networking.k8s.io/v1`)
- ❌ `policy/v1beta1` (usar `policy/v1`)
- ❌ `batch/v1beta1` (usar `batch/v1`)
- ❌ `rbac.authorization.k8s.io/v1beta1` (usar `rbac.authorization.k8s.io/v1`)
- ❌ `autoscaling/v2beta1` o `v2beta2` (usar `autoscaling/v2`)

---

## 2. Registro Completo de Revisiones y Hallazgos Detectados

### A. Repositorio de la Charla (`black-alpaca-peru-redteam-agentes-kubernetes-2026`)

| ID | Componente / Archivo | Problema Detectado | Solución Aplicada | Estado |
|---|---|---|---|:---:|
| **BA-01** | `session-1-.../isolation-postures/{bare,bare-np,ssh,kata}/kustomization.yaml` | Uso de directiva obsoleta `commonLabels:` con advertencias de deprecación en Kustomize. | Migrado a `labels:` con `pairs:` e `includeSelectors: false`. | ✅ Resuelto |
| **BA-02** | `session-2-.../backstage/devsecops-agent/networkpolicy-*.yaml` | Selector de DNS rígido a `k8s-app: kube-dns`, vulnerable a rotaciones de CoreDNS en k3s. | Actualizado a `matchExpressions: [kube-dns, coredns]`. | ✅ Resuelto |
| **BA-03** | `session-2-.../04-ai-agents/pyproject.toml` | `uv run pytest` requería `PYTHONPATH=src` manual debido a falta de configuración en `tool.pytest`. | Añadido `pythonpath = ["src"]` a `[tool.pytest.ini_options]`. | ✅ Resuelto |

---

### B. Repositorio GitOps del Lab (`homelab-gitops`)

| ID | Componente / Archivo | Problema Detectado | Solución Aplicada | Estado |
|---|---|---|---|:---:|
| **HL-01** | `scripts/validate-gitops.py` & `scripts/validate-gitops-custom-gvks.json` | Fallo de validación por CRDs nuevas no registradas: `postgresql.cnpg.io/v1/Cluster` y `cilium.io/v2/CiliumNetworkPolicy`. | Registradas ambas definiciones en la lista blanca de excepciones de esquema. | ✅ Resuelto |
| **HL-02** | `components/apps/gastos/workloads/frontend.yaml` *(Caso A)* | Pod corría sin declarar `runAsNonRoot: true` ni `runAsUser` explícito. | Añadido `runAsNonRoot: true`, `runAsUser: 1000`, `runAsGroup: 1000` en pod securityContext. | ✅ Resuelto |
| **HL-03** | `components/apps/gastos/workloads/backend.yaml` *(Caso A)* | Deployment y CronJob de tipo de cambio sin `runAsNonRoot: true`. | Añadido `runAsNonRoot: true`, `runAsUser: 1000`, `runAsGroup: 1000` en ambos workloads. | ✅ Resuelto |
| **HL-04** | `components/apps/n8n/n8n.yaml` *(Caso B)* | Contenedor agregaba capacidades innecesarias (`CHOWN`, `SETUID`, `SETGID`, `NET_BIND_SERVICE`) heredadas de Podman. | Eliminadas capacidades añadidas; forzado `runAsNonRoot: true`, `runAsUser: 1000` y `drop: ["ALL"]`. | ✅ Resuelto |
| **HL-05** | `components/apps/landing/landing.yaml` *(Caso C)* | Deployment de Landing con Caddy no forzaba `runAsNonRoot` a nivel de pod. | Añadido `runAsNonRoot: true`, `runAsUser: 65532`, `runAsGroup: 65532` a nivel de pod spec. | ✅ Resuelto |
| **HL-06** | `bootstrap/applications/platform/backstage.yaml` | Timeouts del proxy hacia agentes LLM y restricción del MCP general. | Verificado: `timeouts: 120s` activo en Envoy y `/api/mcp-actions` bloqueado de la red pública. | ✅ Auditado OK |
| **HL-07** | `components/apps/lujosa/lujosa.yaml` *(Caso D)* | `lujosa-db` corría imagen oficial de MariaDB con entrypoint root y capacidades completas. | Migrado a `bitnami/mariadb:11.4` (UID 1001), `runAsNonRoot: true`, `drop: ["ALL"]`, `fsGroup: 1001` y probe oficial. | ✅ Resuelto |

---

## 3. Instrucciones de Verificación Automatizada para otros Agentes / LLMs

Cualquier agente que ejecute una revisión posterior de este repositorio debe ejecutar esta secuencia de comandos:

```bash
# 1. Validar Kustomizations del repo de la charla (cero warnings)
for p in bare bare-np ssh kata; do
  kubectl kustomize "session-1-ai-agent-isolation/03-gitops/isolation-postures/$p" > /dev/null
done

# 2. Correr suite de tests de los agentes A2A (82 tests)
cd session-2-ai-red-vs-blue-devsecops/04-ai-agents && uv run pytest

# 3. Validar repositorio homelab-gitops (Kubeconform estricto k8s 1.34)
cd /Users/jeanlopez/Documents/Labjp/appserver/compartido/homelab-gitops
python3 scripts/validate-gitops.py
```
Si los 3 comandos finalizan con código de salida `0`, el entorno cumple el 100% de los estándares definidos en esta especificación.
