# ¿Qué controles siguen importando cuando el modelo deja de rechazar? Red-teaming de agentes de IA en Kubernetes

**Estado: propuesta — pendiente de envío al CFP.**

Propuesta de sesión para Black Alpaca 2026 (Lima, Perú, 14 nov 2026). Convocatoria (CFP) abierta hasta el 5 oct 2026, 23:59 hora Este (EDT) — 10:59 PM hora Lima. Organiza CiberSecUNI. Website: blackalpaca.org.

## Datos del CFP

- Conferencia de ciberseguridad ofensiva/defensiva: pentesting, red team, hacking ético, seguridad de contenedores/hypervisor/cloud, IA.
- Evento gratuito; **sin reembolso de viaje/alojamiento**.
- **Exigencias explícitas del comité**: se rechazan propuestas sin esquema detallado, descripción completa y bio completa. **Se da preferencia a quienes adjuntan documento técnico y paquete de diapositivas** — no basta con un abstract.
- Notificación final a speakers: 12 oct 2026.
- Temas sugeridos donde encaja esta propuesta: Application Security / Security Engineering / DevSecOps; Investigación/técnicas de Red Team; Seguridad de contenedores, hypervisor y cloud; IA.

## Por qué este ángulo, para esta audiencia

Black Alpaca es una audiencia técnica de **ataque real**, no de arquitectura de plataforma — el contenido de gateways/CRDs que armamos para X-Ops y Cloud Native AI Summit no encajaría bien aquí. Esta propuesta reutiliza y reencuadra en clave ofensiva el estudio empírico más fuerte que encontramos investigando AGNTCon+MCPCon Europe 2026: **"Which Controls Still Matter When the Model Stops Refusing?"** (Roy Belio, Red Hat) — un estudio de aislamiento de agentes en Kubernetes con metodología de red team real: inyección de prompt, 8 vectores de escape probados contra el sandbox, y resultados medidos, no supuestos.

**Tesis central, tomada directamente de la charla de referencia**: el rechazo del modelo (refusal) **no es un límite de contención**. Un prompt injection exitoso lo salta — la pregunta que importa en seguridad ofensiva es qué controles de infraestructura siguen deteniendo al atacante *después* de que el modelo ya fue comprometido.

## Contenido técnico (verificado contra el PDF completo de la charla de referencia, 21 diapositivas)

**El ataque real que motiva el estudio**: caso documentado del 4 de mayo de 2026 — un tweet público mueve 3,000 millones de tokens on-chain. Cadena de ataque: (1) el atacante compra membresía de un NFT club que desbloquea el toolset de transferencia sin aprobación humana; (2) el payload va codificado en Morse — el filtro de palabras clave del bot solo escanea strings en inglés y no detecta puntos y guiones; (3) el bot (Grok) traduce el mensaje públicamente y etiqueta a la cuenta objetivo en la respuesta; (4) el escáner de comandos de otro bot (Bankr) lee el texto verificado de una cuenta como una orden autenticada y firma la transferencia ERC-20. Ningún paso individual fue un exploit de "0-day" — fue una cadena de controles que existían pero no se comunicaban entre sí (modelo de permisos vía membresía, filtro de texto en inglés solamente, sin validación de fuente/intención/anomalía antes de ejecutar).

**Por qué un clasificador de prompt injection no basta**: la charla prueba un clasificador real (`protectai/deberta-v3-base-prompt-injection-v2`) contra el mismo ataque codificado en Morse pero con distinto verbo de instrucción ("decode this morse", "translate this", "@grok translate and tag @bankrbot") — el score de detección pasa de 1.0 (bloqueo claro) a 0.004-0.005 (indistinguible de tráfico normal) según el verbo usado. **El clasificador no puede llegar a donde el prompt no puede llegar** — la frontera tiene que estar en otro lugar: infraestructura, no en el propio modelo.

**Metodología de red team aplicada (4 posturas de aislamiento × 6 fronteras medidas)**:
- Posturas probadas: `bare` (herramientas en el pod del gateway, sin NetworkPolicy), `bare-np` (con NetworkPolicy), `ssh` (herramientas en sandbox separado vía SSH/runc), `kata` (OpenShift, microVM con kernel de invitado propio).
- Fronteras medidas: credenciales del gateway, API de Kubernetes, secreto en otro compartimento, elevación de privilegios, mediación de escritura de herramientas, persistencia en el workspace.
- **8 vectores de escalada de privilegios probados y todos bloqueados** en la sesión SSH (uid 1000): `sudo` (no instalado), `su root` (contraseña desconocida), `os.setuid(0)` (sin `CAP_SETUID`), `nsenter -t 1` (permiso denegado), `mount -t proc` (requiere superusuario), `chroot` (sin `CAP_SYS_CHROOT`), binario setuid (sin capacidad de cambiar propietario a root), `/proc/1/root` (permiso denegado por entradas de namespace de propiedad de root).
- **El hallazgo honesto que hace fuerte esta charla para una audiencia de red team**: la mediación de escritura de herramientas **FALLÓ** en las posturas `ssh` y `kata` — el harness reportó el rechazo de una herramienta, pero `bash` escribió el archivo de todas formas en el mismo contenedor. Y **la persistencia en el workspace del agente falló en las 4 posturas probadas** — "ningún control de este stack lo mitiga" (mapea a OWASP ASI06, Memory and Context Poisoning). Un archivo de memoria envenenado sobrevive a una sesión, permanece dormido sin tráfico ni alerta, y se activa cuando una sesión futura carga el mismo workspace.

**Blueprint de operador para Kubernetes, con roles claros**: namespace `openclaw-gateway` (credenciales de API, service account — el "radio de explosión" real) separado de `openclaw-sandbox` (uid 1000, sin credenciales, `automountServiceAccountToken: false`, ejecución de herramientas), con SSH como único punto de ingreso entre ambos, egress deny-by-default salvo DNS, y verificación explícita de que el objetivo sandbox esté realmente activo antes de correr cualquier herramienta.

## Propuesta de descripción (borrador, esquema exigido por el CFP)

Un ataque real del 4 de mayo de 2026 movió 3,000 millones de tokens con un tweet: nada fue un 0-day, fue una cadena de controles que no se hablaban entre sí — un modelo de permisos vía membresía de NFT, un filtro de texto que solo miraba inglés, y un bot que trató un tuit verificado como una orden autenticada. En esta charla hago red-teaming real de agentes de IA desplegados en Kubernetes: pruebo 8 vectores de escalada de privilegios contra 4 posturas de aislamiento (desde un pod sin NetworkPolicy hasta OpenShift con Kata Containers), mido qué frontera contiene al atacante y cuál no, y muestro por qué un clasificador de prompt injection puede pasar de bloquear un ataque a ignorarlo por completo con solo cambiar el verbo de la instrucción. Cierro con el hallazgo más incómodo: la persistencia en el workspace del agente no la detiene ningún control de este stack — y qué hacer al respecto en un blueprint real de Kubernetes.

## Estructura sugerida (ajustar a la duración del slot; el CFP exige esquema detallado)

1. El ataque real: cadena de 3,000 millones de tokens movidos con un tuit — ningún paso fue un 0-day.
2. Por qué el rechazo del modelo no es una frontera de contención — demostración con el clasificador de prompt injection y el ataque codificado en Morse.
3. Metodología de red team: 4 posturas de aislamiento, 6 fronteras a medir, cómo se instrumentó el laboratorio (probes, tokens canario planted, verificación fuera del agente).
4. Demo en vivo: 8 vectores de escalada de privilegios intentados contra la sesión SSH sandboxed — todos bloqueados, con el mecanismo del kernel detrás de cada bloqueo (capabilities, namespaces).
5. El hallazgo incómodo: mediación de escritura de herramientas rota en 2 de 4 posturas; persistencia en el workspace rota en las 4. Qué significa esto para un pentest real de una plataforma de agentes.
6. Blueprint de operador: separación de namespaces gateway/sandbox, egress deny-by-default, verificación de objetivo antes de ejecutar.
7. Checklist de cierre para quien va a auditar o defender una plataforma de agentes en Kubernetes.
8. Preguntas.

## Material

- `index.html` y `assets/`: presentación (pendiente).
- `GUION.md`: notas y reparto de tiempo (pendiente).
- `demo/`: manifiestos de las 4 posturas de aislamiento, scripts de los 8 vectores de ataque, comandos de demo (pendiente).
- Documento técnico adjunto (exigido/preferido por el CFP): pendiente de redactar, basado en este README.

## Plan de replicación de la demo (decisión: ir por las 4 posturas completas, incluyendo Kata/OpenShift)

Evaluación honesta de qué tan reproducible es cada parte antes de comprometerse a demo en vivo:

- **Fácil, reproducible por mi cuenta en poco tiempo**: el clasificador de prompt injection fallando con el mismo texto codificado en Morse y distinto verbo (`protectai/deberta-v3-base-prompt-injection-v2` es público en HuggingFace) — reproducible en cualquier laptop. Los 8 vectores de escalada de privilegios (`sudo`, `su`, `setuid`, `nsenter`, `mount`, `chroot`, binario setuid, `/proc/1/root`) contra un pod con las mismas restricciones (uid 1000, sin capabilities) — reproducible en `kind`/`minikube` o cualquier clúster propio.
- **Requiere más esfuerzo, decidido a hacerlo**: las 4 posturas completas. `bare` y `bare-np` son directas en cualquier clúster; `ssh`/sandbox necesita armar el patrón de dos pods (gateway + sandbox); **`kata` específicamente requiere OpenShift con soporte de Kata Containers** — aprovechar el acceso a infraestructura Red Hat/OpenShift disponible por mi rol para levantar esta postura real, no simulada.
- **No reproducible ni se debe intentar**: el ataque real de los 3,000 millones de tokens (incidente contra bots de producción de terceros — se usa como caso de estudio narrado con fuente citada, nunca como algo a replicar). La falla de persistencia en el workspace del agente requiere el mismo runtime específico (`openclaw`) del estudio original — evaluar si se puede armar un análogo simplificado propio o si se presenta citando el hallazgo del estudio de referencia sin reclamarlo como demo propia.

**Crítico antes de presentar cualquier resultado como demo en vivo**: ejecutar el laboratorio completo en infraestructura propia y registrar los resultados reales — no asumir que los números del estudio de referencia se replican igual en mi entorno. Si algún resultado difiere, se presenta el resultado propio, no el ajeno.

## Estado

Carpeta creada como punto de partida, reencuadrando en clave ofensiva el contenido ya verificado del estudio de Roy Belio (Red Hat) para el bloque "¿Fue protegido?" de las propuestas hermanas de X-Ops Madrid y Cloud Native AI Summit Paris — mismo material técnico, ángulo distinto (red team vs. gobernanza de plataforma).

Falta: **ejecutar el plan de replicación completo** (ver sección arriba) — priorizar primero clasificador + escalada de privilegios (rápido), luego las 4 posturas con Kata/OpenShift (más tiempo); escribir el documento técnico que el CFP prefiere adjunto; escribir guión y diapositivas; confirmar duración real del slot al enviar.

## Fuentes consultadas

- "Which Controls Still Matter When the Model Stops Refusing? An Empirical Isolation Study of Autonomous Agent Containment on Kubernetes" — Roy Belio (Red Hat), AGNTCon+MCPCon Europe 2026 — PDF completo revisado (21 diapositivas). Fuente primaria de toda la metodología, el caso del ataque de mayo 2026, los 8 vectores de escalada y los resultados de las 4 posturas.
- Black Alpaca 2026 — CFP oficial en Sessionize (sessionize.com/black-alpaca-2026) y sitio del evento (blackalpaca.org).
