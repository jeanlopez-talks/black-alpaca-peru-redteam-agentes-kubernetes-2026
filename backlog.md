# Backlog

Cada idea nueva entra aquí antes de construirse: qué es, por qué, dónde vive y cuándo está
terminada. El orden de las épicas es el orden de trabajo: una épica no empieza hasta que
la anterior de la que depende está hecha.

**Prioridad:** P0 = antes del cierre del CFP (5 oct 2026, 10:59 PM Lima) · P1 = antes de la
notificación (12 oct) · P2 = si aceptan la charla, antes del evento (14 nov).

**Dónde:** `charla` = este repo · `homelab-gitops` / `homelab-ansible` / `homelab-pipelines`
= repos de la plataforma.

---

## E1 · Estándar de seguridad como código (Kyverno) — primero

Las políticas de Kyverno son **la fuente única** de los lineamientos de seguridad: lo que se
aplica en la admisión, lo que se comprueba en el pipeline y lo que se documenta en
TechDocs salen del mismo sitio. Sin esto, el agente de E3 no tiene qué leer.

| # | Ítem | Dónde | Hecho cuando | Prio |
|---|------|-------|--------------|------|
| 1.1 | Definir las políticas de plataforma (API CEL `policies.kyverno.io/v1`): `runAsNonRoot`, `allowPrivilegeEscalation: false`, `drop: ALL`, `seccompProfile: RuntimeDefault`, `readOnlyRootFilesystem`, límite de memoria, imagen por digest (sin `:latest`). Cada regla con **ID estable** (`K8S-001`…) y anotaciones `title`, `category`, `severity` y `description`, que son la fuente de la documentación | homelab-gitops | políticas en Git, sincronizadas por Argo CD, cada una con su ID | P1 |
| 1.2 | Desplegarlas en **Audit**, revisar los PolicyReports por namespace, corregir y pasar a **Enforce** namespace a namespace | homelab-gitops | ningún namespace de aplicación en Audit; excepciones documentadas | P2 |
| 1.3 | Política de firma de las imágenes propias (`ghcr.io/labjp-homelab/*`, firmadas por Tekton Chains), primero en Audit | homelab-gitops | Audit sin violaciones durante una semana → Enforce | P1 |
| 1.4 | **Investigar** si Kyverno puede validar también los Containerfile (políticas sobre JSON arbitrario y `kyverno apply` con JSON). Verificar en la documentación oficial antes de decidir; si no, Conftest con los mismos IDs (`CF-001`…) | charla → homelab-gitops | decisión escrita aquí con la fuente citada | P1 |
| 1.5 | Shift-left: el mismo juego de políticas corre en el pipeline (`kyverno apply` sobre los manifiestos) en el golden path y en la etapa `iac-scan` del duelo | homelab-pipelines, charla | el pipeline informa los IDs incumplidos antes del build | P2 |

## E2 · Lineamientos publicados en Backstage (TechDocs)

| # | Ítem | Dónde | Hecho cuando | Prio |
|---|------|-------|--------------|------|
| 2.1 | Habilitar la generación de TechDocs. Hoy `runIn: docker` no funciona en el clúster. Opciones: `runIn: local` con `mkdocs-techdocs-core` en la imagen de Backstage (versiones fijadas con hash) o builder `external` en el CI. Elegir y justificar | homelab-gitops | una página TechDocs de prueba se ve en `backstage.labjp.xyz` | P2 |
| 2.2 | Generar la documentación **desde las anotaciones de las políticas** de E1 (una página por regla: ID, qué exige, por qué, ejemplo correcto e incorrecto). Nada escrito a mano que pueda divergir | homelab-pipelines | cambiar una política regenera su página | P2 |
| 2.3 | Entidad de catálogo `security-guidelines` (kind `Resource`) con `backstage.io/techdocs-ref` | homelab-gitops | aparece en el catálogo con su pestaña Docs | P2 |

## E3 · Agente de remediación (laboratorio de la sesión 2)

Un solo agente, no uno por etapa: las herramientas encuentran (Trivy, Kyverno/Conftest), el
agente prioriza, explica con el lineamiento y **propone** el cambio. Nunca aplica.

| # | Ítem | Dónde | Hecho cuando | Prio |
|---|------|-------|--------------|------|
| 3.1 | Módulo `remediation_agent` (servidor A2A, skill `advise`): entrada JSON de Trivy + resultados de políticas; salida de recomendaciones priorizadas y diff propuesto. Las versiones que corrigen salen de los datos de Trivy, nunca del LLM. Con tests | charla `04-ai-agents` | tests verdes; release `agents-v0.2.0` | P2 |
| 3.2 | Lectura de lineamientos desde Backstage: API de TechDocs con un token estático de Backstage (`backend.auth.externalAccess`) restringido al plugin `techdocs`. Token en OpenBao (`apps/black-alpaca/remediation-agent`) y política en el rol `openbao_access` | charla, homelab-gitops, homelab-ansible | el agente cita el texto del lineamiento por su ID | P2 |
| 3.3 | Despliegue en `devsecops-agent` (namespace con tokens): Deployment, Service, ExternalSecret y NetworkPolicies (entra solo la etapa `remediation`; sale a DNS, Backstage y vLLM). Ingress de Backstage y de vLLM abierto solo para su pod. Application propia en `talks/black-alpaca-2026` | charla, homelab-gitops | Synced/Healthy | P2 |
| 3.4 | Pipeline: Trivy con salida JSON, etapa `iac-scan` en paralelo al SAST y etapa `remediation` (cliente A2A), ambas informativas | charla | el log del PipelineRun muestra las recomendaciones | P2 |
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
