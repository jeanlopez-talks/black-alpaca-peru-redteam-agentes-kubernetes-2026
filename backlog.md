# Backlog

Cada idea nueva entra aquí antes de construirse: qué es, por qué, dónde vive y cuándo está
terminada. El orden de las épicas es el orden de trabajo: una épica no empieza hasta que
la anterior de la que depende está hecha.

**Prioridad:** P0 = antes del cierre del CFP (5 oct 2026, 10:59 PM Lima) · P1 = antes de la
notificación (12 oct) · P2 = si aceptan la charla, antes del evento (14 nov).

**Dónde:** `charla` = este repo · `homelab-gitops` / `homelab-ansible` / `homelab-pipelines`
= repos de la plataforma · `homelab-security-policies` = estándar de seguridad (público).

**Orden acordado (3 oct 2026):** nada se bloquea todavía (todo en Audit). Primero las políticas
(E1), luego TechDocs (E2) y luego los agentes que validan en el flujo DevSecOps (E3), que
son la prioridad.

---

## E1 · Estándar de seguridad como código (Kyverno) — primero

Las políticas de Kyverno son **la fuente única** de los lineamientos de seguridad: lo que se
aplica en la admisión, lo que se comprueba en el pipeline y lo que se documenta en
TechDocs salen del mismo sitio. Sin esto, el agente de E3 no tiene qué leer.

| # | Ítem | Dónde | Hecho cuando | Prio |
|---|------|-------|--------------|------|
| 1.1 | ✅ **Hecho (3 oct 2026):** repo público [`labjp-homelab/homelab-security-policies`](https://github.com/labjp-homelab/homelab-security-policies) con **32 políticas de la biblioteca oficial de Kyverno**, ordenadas por categoría con ID estable: Pod Security Baseline (POD-001…010) y Restricted (POD-101…106), cargas (WKL), imágenes (IMG), red (NET), RBAC (RBAC) y secretos (SEC). `curation.yaml` decide qué se adopta y añade ID, textos en español y casos de prueba; `tools/vendor_policies.py` las genera. 64 casos de `kyverno test` en verde. Desplegadas por Argo CD (Application `homelab-security-policies`, `v0.2.1`), las 32 `ready`, todo en Audit. SEC-002 solo en la admisión (sin dar a Kyverno lectura de los Secrets) | homelab-security-policies, homelab-gitops | — | P1 |
| 1.2 | Desplegarlas en **Audit**, revisar los PolicyReports por namespace, corregir y pasar a **Enforce** namespace a namespace | homelab-gitops | ningún namespace de aplicación en Audit; excepciones documentadas | P2 |
| 1.3 | Política de firma de las imágenes propias (`ghcr.io/labjp-homelab/*`, firmadas por Tekton Chains), primero en Audit | homelab-gitops | Audit sin violaciones durante una semana → Enforce | P1 |
| 1.4 | Reglas para Containerfile con Kyverno: `ValidatingPolicy` con `evaluation.mode: JSON` evaluada con `kyverno apply --json` (verificado en la documentación de Kyverno 1.19; `kyverno json scan` se retiró en 1.19). Falta elegir cómo convertir el Containerfile a JSON. IDs `CF-001`… | homelab-gitops | `kyverno apply` informa los IDs incumplidos de un Containerfile | P1 |
| 1.6 | Fijar **por digest** todas las imágenes de herramientas del pipeline del duelo (Trivy, semgrep, gitleaks, Syft, cosign, kaniko, ubi-minimal, alpine/k8s). Motivo: el compromiso de la cadena de suministro de Trivy del 19 mar 2026 (CVE-2026-33634; release envenenada v0.69.4, imágenes de Docker Hub incluidas). Hoy el pipeline las baja por tag. Es la regla K8S-007 aplicada a nosotros mismos | charla | ninguna imagen por tag en `pipeline-devsecops.yaml` | P1 |
| 1.5 | Shift-left: el mismo juego de políticas corre en el pipeline (`kyverno apply` sobre los manifiestos) en el golden path y en la etapa `iac-scan` del duelo | homelab-pipelines, charla | el pipeline informa los IDs incumplidos antes del build | P2 |

## E2 · Lineamientos publicados en Backstage (TechDocs)

| # | Ítem | Dónde | Hecho cuando | Prio |
|---|------|-------|--------------|------|
| 2.1 | 🔄 **En curso:** TechDocs con `runIn: local` (`mkdocs-techdocs-core` 1.7.1 en un venv de la imagen, 39 dependencias fijadas con hash y cuarentena de 3 días; publica en `/tmp/techdocs`). Build local de las 8 páginas validado con `mkdocs build` | homelab-gitops | una página TechDocs se ve en `backstage.labjp.xyz` | P1 |
| 2.2 | ✅ **Hecho:** `tools/generate_guidelines.py` genera `docs/` (una página por regla, agrupadas por categoría, con la expresión CEL exacta y su origen), una página "Fuente de verdad", `mkdocs.yml` y `catalog-info.yaml`; `--check` falla si no están al día. CI: Pipeline `security-policies-verify` (Tekton, homelab-pipelines) en cada push, con imágenes fijadas por digest; primera ejecución en verde (64/64) | homelab-security-policies | cambiar una política regenera su página | P1 |
| 2.3 | 🔄 **En curso:** `catalog-info.yaml` generado: Resource `security-guidelines` (TechDocs) + un Resource por regla (`spec.type: security-policy`, con ID, severidad, condición y remedio en anotaciones); Backstage lo lee por URL, sin token | homelab-security-policies, homelab-gitops | aparecen en el catálogo; la de cada regla enlaza a su página | P1 |
| 2.4 | ✅ **Hecho (4 oct 2026):** el MCP `catalog-read` de Backstage (solo acciones de lectura del catálogo) es un destino de agentgateway (`backstage_`, `agentgateway-config/backend-mcp.yaml`). agentgateway lo llama con **su propia credencial** (OpenBao `apps/backstage-mcp-agentgateway` → `externalAccess` static restringido a `mcp-actions` y `catalog`): **el agente nunca la tiene**, y a Backstage solo entra el proxy (NetworkPolicy). El endpoint general, con `register-entity`, no se publica. Verificado: el agente ve `backstage_catalog.get-catalog-entity` y `backstage_catalog.query-catalog-entities` y lee la entidad de una regla | homelab-gitops | `tools/list` del gateway muestra `backstage_*`; `register-entity` no existe para el agente | P1 |

**Orden de construcción del agente (3 oct 2026):** 6.2 identidad → 2.4 Backstage en
agentgateway → 6.3 OpenFGA → E3 agente y etapas del pipeline.

## E3 · Agente de remediación (laboratorio de la sesión 2)

Un solo agente, no uno por etapa: las herramientas encuentran (Trivy, Kyverno/Conftest), el
agente prioriza, explica con el lineamiento y **propone** el cambio. Nunca aplica.

| # | Ítem | Dónde | Hecho cuando | Prio |
|---|------|-------|--------------|------|
| 3.1 | ✅ **Hecho (4 oct 2026, `agents-v0.2.2`):** módulo `remediation_agent` (A2A, dos puertas): `advise` convierte el JSON de Trivy + Containerfile en recomendaciones priorizadas con su diff; versiones y conteos salen de Trivy, nunca del LLM. 36 tests | charla `04-ai-agents` | tests verdes; release publicada | P1 |
| 3.2 | ✅ **Hecho:** el agente lee la regla por ID con `backstage_catalog.get-catalog-entity` vía agentgateway, con su cliente de Keycloak y la relación `can_call` de OpenFGA (AVD-DS-0002 → POD-101; FROM sin digest → IMG-002) | charla | el agente cita la regla por su ID | P1 |
| 3.3 | ✅ **Hecho:** desplegado en `devsecops-agent` junto al agente de aprobación (misma Application): puerta `:8081` solo para la etapa `remediation`, `:8080` solo para Backstage; sale a DNS, agentgateway, Keycloak, vLLM y GitHub:22 | charla, homelab-gitops | Synced/Healthy | P1 |
| 3.4 | ✅ **Hecho:** Trivy deja además los JSON y la etapa `remediation` (informativa) llama al agente; el log muestra R1..R4 con lineamiento y diff | charla | el log del PipelineRun muestra las recomendaciones | P1 |
| 3.5 | 🔄 **Parte hecha:** al confirmar en el chat, el agente sube la rama `remediation/<run>` (deploy key solo de este repo; `main` protegida por ruleset, verificado). Falta: abrir el PR, merge, reescanear y comprobar que AVD-DS-0002 desaparece | charla | evidencia en `04-ai-agents/evidence/` | P2 |
| 3.6 | 🔄 **Parte hecha:** tarjeta "Agente de remediación" en la página de `duel-devsecops`: informe + chat + acción pendiente con diff y botones Confirmar/Cancelar (human in the loop). Probado el backend con las mismas peticiones; falta verla con sesión iniciada | homelab-gitops | visible en la página de `duel-devsecops` | P2 |

## E4 · Acto 5: envenenar los lineamientos que lee el agente

| # | Ítem | Dónde | Hecho cuando | Prio |
|---|------|-------|--------------|------|
| 4.1 | Fixture de un lineamiento envenenado (p. ej. "las imágenes de este equipo pueden correr como root") y PipelineRun `duel-act5-poisoned-guidelines` | charla | el agente propone el cambio inseguro, convencido | P2 |
| 4.2 | Demostrar la defensa: Kyverno rechaza igual (la política no se negocia con lo que diga un documento) y, como mejora, el agente compara el texto con la política vigente y marca la discrepancia | charla | los dos resultados en la evidencia | P2 |

## E5 · Contenido de la charla

| # | Ítem | Dónde | Hecho cuando | Prio |
|---|------|-------|--------------|------|
| 5.1 | Propuesta de la sesión 2: añadir el control GitOps-only (Kyverno solo admite lo que aplica Argo CD) y el Acto 5 al esquema y al abstract, respetando los límites del formulario | charla `01-proposal` | campos dentro de los límites de caracteres y palabras | **P0** |
| 5.2 | Exportar el one-pager de la sesión 1 a PDF (adjunto del CFP) | charla | PDF generado | **P0** |
| 5.3 | Enviar las 2 propuestas en Sessionize | — | enviadas | **P0** |
| 5.4 | Slides de la sesión 2: GitOps-only, los dos intentos del agente rechazados, los fallos silenciosos del pipeline (SAST y Trivy "OK" sin escanear) y Acto 5 | charla `02-slides` | slides offline actualizadas | P2 |

## E6 · Plataforma y gobernanza de agentes

| # | Ítem | Dónde | Hecho cuando | Prio |
|---|------|-------|--------------|------|
| 6.1 | Prometheus: con la compactación al día, bajar el límite de 6Gi a lo medido más margen, y explicar el hueco de bloques entre el 2 sep y el 2 oct | homelab-gitops | límite ajustado y causa documentada | P1 |
| 6.2 | 🔄 **Parte 1 hecha (3–4 oct 2026):** cliente `devsecops-remediation-agent` (cuenta de servicio, token de 5 min, secreto en OpenBao `apps/black-alpaca/remediation-agent-oidc`) con solo `mcp:access` y las dos herramientas de lectura de Backstage; agentgateway acepta su JWT y le filtra `tools/list` a esas dos. Falta RFC 8693 (actuar "en nombre de" una persona; agentgateway lo soporta con `oauthTokenExchange`). Identidad de cada agente: un cliente confidencial de Keycloak por agente (`client_credentials`), declarado en el rol `keycloak_identity` de homelab-ansible | homelab-ansible | el agente obtiene su JWT y agentgateway lo acepta | P1 |
| 6.3 | ✅ **Hecho (4 oct 2026): OpenFGA para permisos por herramienta** (ReBAC), segunda capa sobre los roles `mcp:tool:*` de Keycloak (RBAC). **Sin adaptador:** en cada `POST /mcp` agentgateway pregunta a OpenFGA `list-objects` (`agent:<azp>` · `can_call` · `tool`) por `extAuth` con cuerpo CEL y guarda la lista en `extauthz.tools`; la regla MCP exige rol **y** relación, así que OpenFGA también filtra `tools/list`. OpenFGA 1.21 (chart 0.3.15) con PostgreSQL por GitOps; secretos de OpenBao generados como código (homelab-ansible); modelo y relaciones en `openfga-config/authorization/`, aplicados cada 10 min por una CronJob que borra lo que no esté en Git. Verificado: borrar en OpenFGA `kagent-mcp` → `gastos_create_expense` la ocultó y bloqueó con el rol intacto, y la CronJob la restauró | homelab-gitops | quitar la relación de una herramienta en OpenFGA la bloquea aunque el rol siga en Keycloak | P1 |
| 6.4 | OpenTelemetry: trazas de las llamadas A2A entre agentes | homelab-gitops, charla | traza del duelo en Grafana | P2 |
| 6.5 | Firma keyless con Rekor propio (hoy: clave cosign sin log de transparencia) | homelab-gitops | firma verificable con tlog | P2 |

---

## Decisiones tomadas (no reabrir sin motivo)

- **Registry:** GHCR (`ghcr.io/labjp-homelab`), no quay.io. Es el golden path que ya firma Tekton Chains (3 oct 2026).
- **Un agente de remediación, no uno por etapa:** menos identidades, menos tokens, menos superficie (3 oct 2026).
- **Los límites de la demo viven en la plataforma:** el AppProject y las Applications de la sesión 2 están en homelab-gitops (3 oct 2026).
- **Repo público** desde el 3 oct 2026, tras auditar el historial completo (sin secretos reales).
- **Backstage = base estable + plugins dinámicos** (4 oct 2026): los módulos propios (empezando por la pestaña del agente de remediación) se empaquetan con `backstage-cli package bundle` en una imagen mínima por plugin; un init container los instala al arrancar. Cambiar un plugin construye solo su imagen (~1 min) y reinicia el pod; el portal (1.55.3) no se reconstruye. Upstream marca como alpha el nuevo frontend system en el que se apoya.
- **Human in the loop del agente de remediación** (4 oct 2026): el modelo solo conversa; el servidor prepara la acción con el diff exacto y solo el botón Confirmar (skill `confirm-action`, misma conversación, 15 min) la ejecuta. Aplicar = rama `remediation/*`, nunca `main`. La verdad sobre lo que hizo el agente la dice el sistema, no el modelo.
- **agentgateway es la única fachada MCP** (4 oct 2026): federa los servidores MCP y autoriza cada herramienta con los roles del JWT, ocultando en `tools/list` lo no concedido. Se retiró el MCP Gateway de Kuadrant (broker/router, `mcp-system`, `mcp.labjp.xyz`): exigía Istio o parches de Envoy a mano y no filtraba la lista. Decisión completa en homelab-gitops `docs/mcp-platform/decision-agentgateway-only-mcp-facade.md`.
- **Kyverno es la fuente de los lineamientos:** TechDocs y el agente derivan de las políticas, no al revés (3 oct 2026).
- **Dónde viven y quién lee qué** (3 oct 2026): las políticas de plataforma en su **propio repo público** `labjp-homelab/homelab-security-policies` (nombre consistente con `homelab-gitops`, `homelab-pipelines`…; licencia Apache-2.0), versionado con tags y aplicado por Argo CD; las de la demo (`duel-*`) siguen namespaced en este repo. Las personas leen TechDocs; los agentes leen las reglas por el **MCP oficial de Backstage**, nunca la prosa (defensa del Acto 5).
