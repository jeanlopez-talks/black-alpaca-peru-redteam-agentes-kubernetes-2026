# Análisis con el modelo en el clúster (k3s, 5 oct 2026) — resultado propio

Agente de remediación `devsecops-agents:0.4.1`, modelo local Qwen3-8B (AWQ) en vLLM 0.30
(RTX 3060, razonamiento activado, salida guiada por esquema), PipelineRun
`act1-obvious-malicious-pr`. Salidas resumidas de lo que muestra Backstage; nada de este
documento viene del estudio de referencia.

## 1. Cómo se llegó aquí (lo que falló antes, medido)

| Intento | Qué pasó | Qué se cambió |
|---|---|---|
| Modelo sin hechos, sin razonamiento | Dijo que nginx no usa openssl, propuso «actualizar» paquetes sin parche y afirmó que corría como 1001 sin saberlo | Hechos calculados de la imagen (usuario efectivo, proceso principal, grafo `DependsOn` de Trivy) |
| Con hechos, `response_format` libre | Agotó 6.000–14.000 tokens emitiendo espacios dentro del JSON (315 s) | `structured_outputs` con `disable_any_whitespace` y `maxLength` en los textos |
| Con razonamiento | Veredictos correctos, pero «quitar openssl-libs» (nginx lo carga) y un digest inventado de cientos de dígitos | Esquema generado desde los hechos (acciones y riesgos posibles por paquete) y el Containerfile lo escribe el código |
| Primer parche «quitar módulos opcionales» | Habría impedido arrancar a nginx: el `nginx.conf` de UBI carga **todos** los módulos instalados (comprobado en la imagen) | Las librerías de un módulo solo se quitan si se quita el módulo |
| Revisión adversarial (Fable) | 2 críticos: inyección de un `RUN` vía `ImageConfig.User`; con `ENTRYPOINT`+`CMD` el proceso principal quedaba vacío y se podía quitar `openssl-libs` | Usuario saneado, semántica Docker de ENTRYPOINT/CMD, lista cerrada de líneas añadidas; 8 hallazgos reproducidos y resueltos |

## 2. Ejecución final

- **Hechos:** corre como `1001` (lo define la imagen base) → AVD-DS-0002 es defensa en
  profundidad, no HIGH. Proceso principal `nginx` (`nginx-core`), que carga `openssl-libs`
  y `pcre2`; 5 módulos instalados que nginx carga al arrancar.
- **El modelo usó el MCP de Backstage** (vía agentgateway, Keycloak + OpenFGA):
  `query-catalog-entities` (39 lineamientos) y eligió leer POD-101/POD-102 e IMG-002 con
  `get-catalog-entity`; asoció cada hallazgo al lineamiento que leyó.
- **Decisión del modelo:** quitar el módulo `nginx-mod-http-image-filter` y 18 paquetes que
  nginx no usa; mantener `openssl-libs`/`pcre2` (cambiar de base o aceptar).
- **El verificador le corrigió 2 cosas**, visibles en Backstage (p. ej. «el cambio no
  resuelve el digest», «nginx carga pcre2: no se puede quitar»).
- Tiempo del modelo: 90–140 s, en segundo plano; la etapa del pipeline no espera.

## 3. ¿Funciona la imagen corregida? ¿Cuánto reduce?

Construida localmente con el `Containerfile` que propuso el agente (misma base
`ubi9/nginx-120:9.8`) y reescaneada con Trivy 0.58.1, `HIGH,CRITICAL`:

| | HIGH/CRITICAL | Con corrección |
|---|---|---|
| Imagen original | 37 | 3 |
| Quitando los 5 módulos + paquetes sin uso | **13** | 0 |

`nginx -t` correcto y HTTP 200 sirviendo `index.html` en las dos variantes probadas (todos
los módulos, y solo `image-filter`). Las 13 restantes están en paquetes que nginx carga
(`openssl-libs`, `pcre2`) o que el modelo no eligió quitar.

## 4. Persona en el bucle (Backstage)

«aplica R2» → acción pendiente con el diff exacto y destino (rama, nunca `main`) →
«Confirmar y aplicar» → rama `remediation/act1-obvious-malicious-pr-r2`, commit `b6591c4`
del agente, **solo** las 6 líneas del diff en el `Containerfile` permitido.

Lección para la charla: el modelo analiza y decide, pero lo que llega a la persona lo
acotan los hechos y un verificador que muestra cada error que le corrigió al modelo.

## 5. Tokens: medir antes de optimizar (`agents-v0.7.0`)

Un análisis falló con JSON cortado. Se supuso que se agotaban los tokens; medirlo (cada
llamada registra ahora `finish_reason` y tokens) lo desmintió: el análisis usaba ~2,2k de
salida de 9k. La causa queda registrada si se repite; el reintento es solo red de
seguridad. Lo que sí sobraba era la entrada:

| Versión | Entrada del análisis | Salida | Tiempo por corrida |
|---|---|---|---|
| Lista completa de CVE por paquete | ~4,8k tokens | ~2,2k | 73–113 s |
| Paquetes agrupados por uso (4 grupos, no 22 paquetes) | **~2,7k** | ~1,4–2,0k | **51–52 s** |

Tres actos a la vez: las 3 corridas analizadas, `finish_reason=stop`, ningún reintento.
La lista completa de CVE sigue en el informe y en Backstage; solo deja de ir al modelo.
