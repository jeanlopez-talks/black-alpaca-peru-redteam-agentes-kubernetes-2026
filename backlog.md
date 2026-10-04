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
| 1.1 | ✅ **Hecho (3 oct 2026):** repo público [`labjp-homelab/homelab-security-policies`](https://github.com/labjp-homelab/homelab-security-policies) (`policies/kubernetes/`), 7 reglas K8S-001…007 en Audit, 14 tests de `kyverno test` en verde, desplegadas por Argo CD (Application `homelab-security-policies`, fijada a `v0.1.0`). Primer informe: 1.109 incumplimientos en todo el clúster (el mayor, K8S-005, con 353) | homelab-security-policies | — | P1 |
| 1.2 | Desplegarlas en **Audit**, revisar los PolicyReports por namespace, corregir y pasar a **Enforce** namespace a namespace | homelab-gitops | ningún namespace de aplicación en Audit; excepciones documentadas | P2 |
| 1.3 | Política de firma de las imágenes propias (`ghcr.io/labjp-homelab/*`, firmadas por Tekton Chains), primero en Audit | homelab-gitops | Audit sin violaciones durante una semana → Enforce | P1 |
| 1.4 | Reglas para Containerfile con Kyverno: `ValidatingPolicy` con `evaluation.mode: JSON` evaluada con `kyverno apply --json` (verificado en la documentación de Kyverno 1.19; `kyverno json scan` se retiró en 1.19). Falta elegir cómo convertir el Containerfile a JSON. IDs `CF-001`… | homelab-gitops | `kyverno apply` informa los IDs incumplidos de un Containerfile | P1 |
| 1.6 | Fijar **por digest** todas las imágenes de herramientas del pipeline del duelo (Trivy, semgrep, gitleaks, Syft, cosign, kaniko, ubi-minimal, alpine/k8s). Motivo: el compromiso de la cadena de suministro de Trivy del 19 mar 2026 (CVE-2026-33634; release envenenada v0.69.4, imágenes de Docker Hub incluidas). Hoy el pipeline las baja por tag. Es la regla K8S-007 aplicada a nosotros mismos | charla | ninguna imagen por tag en `pipeline-devsecops.yaml` | P1 |
| 1.5 | Shift-left: el mismo juego de políticas corre en el pipeline (`kyverno apply` sobre los manifiestos) en el golden path y en la etapa `iac-scan` del duelo | homelab-pipelines, charla | el pipeline informa los IDs incumplidos antes del build | P2 |

## E2 · Lineamientos publicados en Backstage (TechDocs)

| # | Ítem | Dónde | Hecho cuando | Prio |
|---|------|-------|--------------|------|
| 2.1 | 🔄 **En curso:** TechDocs con `runIn: local` (`mkdocs-techdocs-core` 1.7.1 en un venv de la imagen, 39 dependencias fijadas con hash y cuarentena de 3 días; publica en `/tmp/techdocs`). Build local de las 8 páginas validado con `mkdocs build` | homelab-gitops | una página TechDocs se ve en `backstage.labjp.xyz` | P1 |
| 2.2 | ✅ **Hecho:** `tools/generate_guidelines.py` genera `docs/` (una página por regla, con la expresión CEL exacta), `mkdocs.yml` y `catalog-info.yaml` desde las anotaciones; `--check` falla si no están al día. Falta: correr el `--check` y `kyverno test` en un CI del repo | homelab-security-policies | cambiar una política regenera su página | P1 |
| 2.3 | 🔄 **En curso:** `catalog-info.yaml` generado: Resource `security-guidelines` (TechDocs) + un Resource por regla (`spec.type: security-policy`, con ID, severidad, condición y remedio en anotaciones); Backstage lo lee por URL, sin token | homelab-security-policies, homelab-gitops | aparecen en el catálogo; la de cada regla enlaza a su página | P1 |
| 2.4 | **MCP de Backstage** (`@backstage/plugin-mcp-actions-backend`, ya instalado con `pluginSources: [auth, catalog]`). Verificado en su esquema: el endpoint por defecto `/api/mcp-actions/v1` **siempre expone todas las acciones**, incluidas `register-entity`/`unregister-entity`; filtrar con servidores con nombre no lo protege. La protección va en el **token estático del agente**: `accessRestrictions` a `mcp-actions` y `catalog` con `permissionAttribute: {action: [read]}`. Token en OpenBao | homelab-gitops | un cliente MCP lista las reglas y recibe "denegado" al intentar registrar o borrar | P1 |

## E3 · Agente de remediación (laboratorio de la sesión 2)

Un solo agente, no uno por etapa: las herramientas encuentran (Trivy, Kyverno/Conftest), el
agente prioriza, explica con el lineamiento y **propone** el cambio. Nunca aplica.

| # | Ítem | Dónde | Hecho cuando | Prio |
|---|------|-------|--------------|------|
| 3.1 | Módulo `remediation_agent` (servidor A2A, skill `advise`): entrada JSON de Trivy + resultados de políticas; salida de recomendaciones priorizadas y diff propuesto. Las versiones que corrigen salen de los datos de Trivy, nunca del LLM. Con tests | charla `04-ai-agents` | tests verdes; release `agents-v0.2.0` | P1 |
| 3.2 | Lectura de lineamientos por el **MCP de Backstage** (2.4): el agente pide la entidad de la regla por su ID (la regla aplicable, no la prosa). Token en OpenBao (`apps/black-alpaca/remediation-agent`) y política en el rol `openbao_access` | charla, homelab-gitops, homelab-ansible | el agente cita la regla por su ID | P1 |
| 3.3 | Despliegue en `devsecops-agent` (namespace con tokens): Deployment, Service, ExternalSecret y NetworkPolicies (entra solo la etapa `remediation`; sale a DNS, Backstage y vLLM). Ingress de Backstage y de vLLM abierto solo para su pod. Application propia en `talks/black-alpaca-2026` | charla, homelab-gitops | Synced/Healthy | P1 |
| 3.4 | Pipeline: Trivy con salida JSON, etapa `iac-scan` en paralelo al SAST y etapa `remediation` (cliente A2A), ambas informativas | charla | el log del PipelineRun muestra las recomendaciones | P1 |
| 3.5 | Cerrar el ciclo: aplicar la propuesta en un PR, reconstruir, reescanear y comprobar que el hallazgo desaparece | charla | evidencia en `04-ai-agents/evidence/` | P2 |
| 3.6 | Mostrar el informe del agente de remediación en la tarjeta del Asistente DevSecOps de Backstage | homelab-gitops | visible en la página de `duel-devsecops` | P2 |

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
| 6.2 | Identidad del agente: Keycloak + intercambio de tokens RFC 8693 para que el agente actúe "en nombre de" la persona | homelab-ansible, charla | demo del token delegado | P2 |
| 6.3 | agentgateway + OpenFGA: permisos por tarea y por skill de cada agente | homelab-gitops | una skill denegada por OpenFGA en la demo | P2 |
| 6.4 | OpenTelemetry: trazas de las llamadas A2A entre agentes | homelab-gitops, charla | traza del duelo en Grafana | P2 |
| 6.5 | Firma keyless con Rekor propio (hoy: clave cosign sin log de transparencia) | homelab-gitops | firma verificable con tlog | P2 |

---

## Decisiones tomadas (no reabrir sin motivo)

- **Registry:** GHCR (`ghcr.io/labjp-homelab`), no quay.io. Es el golden path que ya firma Tekton Chains (3 oct 2026).
- **Un agente de remediación, no uno por etapa:** menos identidades, menos tokens, menos superficie (3 oct 2026).
- **Los límites de la demo viven en la plataforma:** el AppProject y las Applications de la sesión 2 están en homelab-gitops (3 oct 2026).
- **Repo público** desde el 3 oct 2026, tras auditar el historial completo (sin secretos reales).
- **Kyverno es la fuente de los lineamientos:** TechDocs y el agente derivan de las políticas, no al revés (3 oct 2026).
- **Dónde viven y quién lee qué** (3 oct 2026): las políticas de plataforma en su **propio repo público** `labjp-homelab/homelab-security-policies` (nombre consistente con `homelab-gitops`, `homelab-pipelines`…; licencia Apache-2.0), versionado con tags y aplicado por Argo CD; las de la demo (`duel-*`) siguen namespaced en este repo. Las personas leen TechDocs; los agentes leen las reglas por el **MCP oficial de Backstage**, nunca la prosa (defensa del Acto 5).
