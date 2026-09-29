# Propuesta de charla — Black Alpaca 2026 (Lima)

**Evento:** Black Alpaca 2026 · CiberSecUNI · 14 nov 2026 · Lima, Perú
**CFP cierra:** 5 oct 2026, 23:59 EDT — *en tu zona (Lima): 5 oct 2026, 10:59 PM*
**Notificación final:** 12 oct 2026
**Plataforma:** Sessionize · **Website:** blackalpaca.org

**Reglas del CFP que determinan si te aceptan (léelas antes de enviar)**:
1. Se **rechazan** propuestas sin esquema detallado, descripción completa y bio completa — no basta un abstract corto tipo otros CFPs.
2. Se da **preferencia explícita** a quien adjunta documento técnico y paquete de diapositivas. Si el formulario de Sessionize permite adjuntar archivos o poner links, usar esa sección — no dejarla vacía.
3. Es una audiencia de **ataque real** (pentest, red team, CTF) — el criterio de aceptación no es "arquitectura interesante", es "esto se puede reproducir y romper algo".

---

## ✅ CAMPOS DEL FORMULARIO — copiar y pegar

### Session Title
```
¿Qué controles siguen importando cuando el modelo deja de rechazar? Red-teaming de agentes de IA en Kubernetes
```

### Tagline / Subtítulo
```
Un tweet movió 3,000 millones de tokens sin autorización de nadie. Pruebo 8 vectores de escalada de privilegios contra 4 posturas de aislamiento en Kubernetes — y muestro cuáles fallan de verdad.
```

### Description — versión larga y detallada (este CFP exige profundidad, no un resumen corto)
```
El 4 de mayo de 2026, un tweet público movió 3,000 millones de tokens on-chain sin que ningún humano aprobara la transferencia. La cadena de ataque no usó ningún 0-day: un atacante compró membresía de un NFT club que desbloqueaba el toolset de transferencia del bot sin aprobación humana; codificó el payload en Morse porque el filtro de palabras clave del bot solo escaneaba strings en inglés; el bot tradujo el mensaje públicamente y etiquetó a la cuenta objetivo en su propia respuesta; y el escáner de comandos de un segundo bot leyó ese tuit verificado como una orden autenticada y firmó la transferencia ERC-20. Cuatro controles que existían, ninguno hablando con el otro.

Esta charla es red-teaming real de agentes de IA desplegados en Kubernetes, con la tesis de que el rechazo del modelo (refusal) no es un límite de contención: un prompt injection exitoso lo salta, y lo demuestro en vivo — el mismo ataque codificado en Morse pasa de un score de detección de 1.0 (bloqueo claro) a 0.004 (indistinguible de tráfico normal) en un clasificador real de prompt injection, solo cambiando el verbo de la instrucción ("decode" vs. "translate"). El clasificador no puede llegar a donde el prompt no puede llegar — la frontera tiene que estar en la infraestructura, no en el modelo.

Pruebo 8 vectores de escalada de privilegios (sudo, su, setuid, nsenter, mount, chroot, binarios setuid, /proc/1/root) contra 4 posturas de aislamiento en Kubernetes: un pod sin NetworkPolicy, un pod con NetworkPolicy, un sandbox vía SSH/runc, y OpenShift con Kata Containers (microVM). Mido 6 fronteras reales: credenciales del gateway, API de Kubernetes, secretos en otro compartimento, elevación de privilegios, mediación de escritura de herramientas, y persistencia en el workspace del agente.

El resultado no es "todo está resuelto". La mediación de escritura de herramientas falla en 2 de las 4 posturas — el harness reporta que bloqueó una herramienta, pero el binario subyacente escribe el archivo igual, en el mismo contenedor. Y la persistencia en el workspace del agente falla en las 4 posturas probadas: ningún control de este stack la detiene. Un archivo de memoria envenenado sobrevive a la sesión, queda dormido sin generar tráfico ni alerta, y se activa cuando una sesión futura vuelve a cargar el mismo workspace — el vector que mapea a OWASP ASI06, Memory and Context Poisoning.

Cierro con un blueprint de operador para Kubernetes que sí contiene lo que se puede contener: namespaces separados para credenciales y ejecución de herramientas, SSH como único punto de ingreso entre ambos, egress deny-by-default, y verificación explícita del objetivo antes de correr cualquier herramienta — y con una lista honesta de lo que ese blueprint todavía no resuelve, para que quien se lleve esto a un pentest real sepa exactamente dónde seguir buscando.
```

### Idioma / Language
```
Español
```

### Nivel
```
Intermedio-avanzado
```
*Se asume conocimiento de Kubernetes (pods, NetworkPolicy, capabilities de Linux), conceptos básicos de contenedores/aislamiento (namespaces, uid, runc), y una noción de qué es un LLM/agente de IA — no se explica ninguno de los tres desde cero. El foco está en la metodología de ataque y en los resultados medidos, no en una introducción a IA ni a Kubernetes.*

### Tags
```
Red Team, Kubernetes, Seguridad de contenedores, Prompt Injection, Agentes de IA, Cloud Security, Pentesting, DevSecOps, Cybersecurity
```

### Co-speaker
```
(dejar vacío)
```

---

## 👤 PERFIL DE SPEAKER

### Bio (versión completa — este CFP la exige detallada, no un one-liner)
```
Jean Paul López es Senior Consultant en Red Hat, peruano, con años ayudando a empresas de LATAM a llevar cargas de trabajo a producción sobre Kubernetes y OpenShift — incluyendo el endurecimiento de clústeres para clientes con requisitos regulatorios estrictos en banca y sector público. Últimamente aplica esa misma disciplina de seguridad de plataforma al mundo de los agentes de IA: construye servidores MCP, experimenta con runtimes de agentes en clústeres reales, y antes de subir cualquier afirmación a una diapositiva la contrasta contra el código fuente, la documentación oficial o — cuando existe — contra un laboratorio propio. Esta charla nace de esa misma disciplina aplicada a un problema nuevo: qué controles de Kubernetes siguen deteniendo a un atacante cuando el modelo de IA ya fue comprometido.
```

- **Company:** `Red Hat`
- **Position:** `Senior Consultant`
- **Blog / Instagram / Other Communities:** dejar vacío si no se usan.

---

## 📎 DOCUMENTO TÉCNICO / PAQUETE DE DIAPOSITIVAS (el CFP da preferencia a quien adjunta esto)

**No enviar sin esto si el formulario lo permite.** Antes de enviar la propuesta:

1. Redactar un documento técnico corto (2-4 páginas) con: el caso del ataque de mayo 2026 con referencias citables, la tabla de las 4 posturas × 6 fronteras con resultados, el detalle de los 8 vectores de escalada probados y por qué cada uno falló (capability/namespace específico), y el blueprint de operador con manifiestos de ejemplo (NetworkPolicy, SecurityContext, namespaces separados).
2. Si ya existe un esqueleto de diapositivas (aunque sea in-progress), adjuntarlo — el comité de Black Alpaca valora explícitamente ver contenido real, no solo la promesa de que existirá.
3. Si no se logra tener el documento técnico listo antes del 5 de octubre, al menos enviar el esqueleto de la sección "Estructura sugerida" de este archivo como el "esquema detallado" que piden — es mejor que un abstract solo.

---

## 🗣️ MATERIAL DE APOYO (no va en el formulario — para preparar la charla)

### Qué se lleva la audiencia (Takeaways)
- Por qué el rechazo del modelo (refusal) nunca fue una frontera de seguridad, con una demostración medible (score de un clasificador real cayendo de 1.0 a 0.004 con un simple cambio de verbo).
- Una metodología reproducible de red team para agentes de IA en Kubernetes: 4 posturas de aislamiento, 6 fronteras a medir, cómo instrumentar el laboratorio con tokens canario.
- 8 técnicas concretas de escalada de privilegios en contenedores (sudo, setuid, nsenter, mount, chroot, /proc/1/root) y el mecanismo exacto del kernel que las bloquea (o no).
- Un hallazgo que nadie más está diciendo en voz alta: la persistencia de memoria de un agente es, hoy, un vector sin mitigación real en el ecosistema Kubernetes — y qué monitorear mientras eso se resuelve.
- Un blueprint de operador reutilizable (namespaces separados, egress deny-by-default, verificación de objetivo) para auditar o defender una plataforma de agentes real.

### Categoría / track aplicable del CFP
Application Security / Security Engineering / DevSecOps · Investigación/técnicas de Red Team · Seguridad de contenedores, hypervisor y cloud · IA.

### Esqueleto de la charla (ajustar a la duración real del slot; usar como "esquema detallado" exigido por el CFP)
1. **(0-5 min)** El ataque real: cadena de 3,000 millones de tokens movidos con un tuit el 4 de mayo de 2026 — ningún paso individual fue un 0-day, la falla fue de comunicación entre controles.
2. **(5-12 min)** Por qué el rechazo del modelo no es una frontera de contención: demo en vivo del clasificador de prompt injection pasando de bloquear a ignorar el mismo ataque con un cambio de verbo.
3. **(12-18 min)** Metodología de red team: 4 posturas de aislamiento (bare, bare-np, ssh, kata), 6 fronteras a medir, cómo se instrumenta el laboratorio (tokens canario, verificación fuera del agente).
4. **(18-28 min)** Demo en vivo: 8 vectores de escalada de privilegios contra la sesión sandboxed — resultado y mecanismo de kernel detrás de cada bloqueo (capabilities efectivas, namespaces de propiedad root).
5. **(28-36 min)** El hallazgo incómodo: mediación de escritura de herramientas rota en 2 de 4 posturas; persistencia en el workspace rota en las 4. Qué implica esto para un pentest real de una plataforma de agentes.
6. **(36-42 min)** Blueprint de operador: separación de namespaces gateway/sandbox, egress deny-by-default, verificación de objetivo antes de ejecutar — con manifiestos reales.
7. **(42-45 min)** Checklist de cierre para auditar o defender una plataforma de agentes en Kubernetes.
8. Preguntas.

---

## ⚠️ ANTES DE ENVIAR — checklist

- [ ] **Crítico**: replicar el laboratorio de aislamiento (las 4 posturas, los 8 vectores) en un clúster propio antes de presentar resultados como demo en vivo — los datos actuales vienen del estudio de referencia de Roy Belio (Red Hat), no de una ejecución propia. Si no se logra replicar a tiempo, decirlo explícitamente en la charla y en la propuesta ("metodología replicada de un estudio público, validación propia en curso").
- [ ] Redactar y adjuntar el documento técnico corto — es lo que más pesa en la aceptación según las reglas explícitas del CFP.
- [ ] Preparar al menos un esqueleto de diapositivas para adjuntar, aunque no esté terminado.
- [ ] Confirmar duración real del slot al momento de enviar (el esqueleto de arriba asume ~45 min; ajustar si el formato de Black Alpaca es más corto).
- [ ] Revisar el país en el perfil.
- [ ] No mencionar la fuente original (Roy Belio/Red Hat) como si fuera trabajo propio no atribuido — dar crédito explícito a la metodología de referencia en la charla, aun cuando el contenido se reencuadra y se presenta con voz propia.

---

## Fuentes

- "Which Controls Still Matter When the Model Stops Refusing? An Empirical Isolation Study of Autonomous Agent Containment on Kubernetes" — Roy Belio (Red Hat), AGNTCon+MCPCon Europe 2026 — PDF completo revisado (21 diapositivas). Fuente primaria de toda la metodología, el caso del ataque de mayo 2026, los 8 vectores de escalada y los resultados de las 4 posturas.
- Black Alpaca 2026 — CFP oficial en Sessionize (sessionize.com/black-alpaca-2026) y sitio del evento (blackalpaca.org).
