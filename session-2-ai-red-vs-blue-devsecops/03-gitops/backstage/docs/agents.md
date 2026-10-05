# Agentes y human in the loop

Los dos agentes siguen el mismo patrón: **el modelo analiza y decide, el esquema acota lo
que puede decir y el código verifica**. Antes de analizar, el modelo consulta el catálogo
de Backstage por MCP (agentgateway, con la identidad propia de cada agente en Keycloak y
OpenFGA) y elige qué lineamientos leer. En Backstage se ve todo: los hechos, lo que
consultó, lo que concluyó, lo que el verificador le corrigió y lo que recibió.

## Agente de remediación (pestaña «Agente de remediación»)

1. **Lanza el pipeline.** La etapa `remediation` le envía Trivy (con el grafo de paquetes)
   y el Containerfile. Al instante sale un informe por reglas; en uno o dos minutos lo
   sustituye el análisis del modelo.
2. **El modelo analiza** sobre hechos calculados de la imagen: con qué usuario corre, qué
   proceso arranca, qué librerías carga y qué módulos tiene. Decide si cada hallazgo es
   real o un falso positivo, el riesgo de cada paquete aquí y qué quitar. El Containerfile
   lo escribe el código a partir de su decisión.
3. **Pregunta y pide el cambio.** «aplica R2» prepara una **acción pendiente** con el
   diff exacto, el destino y la caducidad (15 minutos).
4. **Decide tú.** Solo **Confirmar y aplicar** la ejecuta: el agente sube la rama
   `remediation/<pipeline-run>-r<n>` y te da el enlace del PR. El merge es tuyo y el
   despliegue sigue por GitOps.

## Agente de aprobación (tarjeta «Asistente DevSecOps»)

El revisor azul del pipeline es un LLM y se le puede engañar (Actos 2-3). Este agente da
una **segunda opinión** sobre cada PipelineRun:

1. **Hechos:** los resultados reales de cada etapa (SAST, Trivy, firma, decisión del
   azul, verificación, admisión de Kyverno), el diff del PR y las señales que se
   contradicen («el azul aprobó, pero Kyverno rechazó»).
2. **El modelo revisa el PR por su cuenta:** si es malicioso, si intenta convencer al
   revisor (inyección), qué haría si se desplegara, si al azul lo engañaron y qué decidir.
3. **Acotado y verificado:** no puede recomendar aprobar un run con etapas fallidas; la
   evidencia de una inyección solo puede ser una línea que el PR añade (cita literal).
4. **Decide tú:** las propuestas solo se ejecutan con el token de un humano, y aprobar
   un despliegue sigue siendo una anotación en Git que revisa una persona.

## Varias corridas a la vez

- **Remediación:** el agente guarda las últimas 10 corridas y el modelo las analiza en
  cola, una tras otra, sin descartar ninguna. En la pestaña eliges la corrida (la más
  reciente primero); el chat y «aplica R…» trabajan sobre la que ves, y cada acción
  pendiente recuerda de qué corrida es.
- **Aprobación:** una revisión del modelo por corrida, guardada mientras la corrida no
  cambie; cuando llega una nueva solo se revisa esa. La tarjeta muestra cada corrida en su
  desplegable, con su decisión, su revisión, sus consultas MCP y lo que recibió el modelo.

## Controles

| Riesgo | Control |
|--------|---------|
| El modelo inventa CVE, paquetes o evidencias | El esquema solo le deja citar lo que existe (paquetes del escaneo, líneas del PR, lineamientos que leyó); el verificador descarta el resto |
| El modelo propone algo imposible o peligroso | Acciones y riesgos por paquete salen de los hechos; el parche lo escribe el código con una lista cerrada de líneas |
| Un PR o un Containerfile hostil intenta inyectar instrucciones | Son datos no confiables: el modelo los revisa, pero lo que llega a la persona pasa el verificador |
| Un texto del chat intenta confirmar | Confirmar solo existe como botón; los intentos por texto reciben una respuesta fija |
| El modelo afirma haber aplicado algo | Si no hubo confirmación real, su respuesta se sustituye por la verdad |
| El pipeline, que ejecuta código del PR, intenta confirmar | Llega solo a la puerta `advise` (otro puerto, por NetworkPolicy) |
| El agente escribe en `main` | Su deploy key solo sirve para este repo y `main` está protegida |
| Un lineamiento del catálogo está envenenado | Se contrasta con la política que Kyverno aplica; si no coinciden, manda la política |
| El agente usa herramientas que no le tocan | agentgateway: rol de Keycloak + relación `can_call` en OpenFGA por herramienta |

## Lineamientos

Los lineamientos salen de las políticas Kyverno de
[homelab-security-policies](https://github.com/labjp-homelab/homelab-security-policies):
Argo CD las aplica en el clúster y el mismo repo genera su documentación y el catálogo.
Los agentes los leen por MCP y el de remediación los contrasta con la política vigente.
