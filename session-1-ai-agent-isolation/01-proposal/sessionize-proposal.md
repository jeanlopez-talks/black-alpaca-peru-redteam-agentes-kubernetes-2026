# Propuesta de charla — Black Alpaca 2026 (Lima)

**Evento:** Black Alpaca 2026 · CiberSecUNI · 14 nov 2026 · Lima, Perú
**CFP cierra:** 5 oct 2026, 23:59 EDT — *en tu zona (Lima): 5 oct 2026, 10:59 PM*
**Notificación final:** 12 oct 2026
**Plataforma:** Sessionize · **Website:** blackalpaca.org
**Máximo 2 submissions por speaker** (podrías enviar esta + una segunda).

> ⚠️ **Estos campos están mapeados contra el FORMULARIO REAL de Sessionize** (revisado logueado el 2 oct 2026).
> El formulario NO tiene un campo "Tags" ni "Description" único como asumía la versión anterior.
> Tiene: Title, Description (privada), Abstract (pública ≤300 palabras), Talk Teaser (≤240 car.),
> Supporting Files (1 archivo, 50 MB), y selects cerrados para Session format / Track / Level / Language.

---

## ✅ CAMPOS DEL FORMULARIO — copiar y pegar

### Session Title  — *límite real: 100 caracteres*
```
Cuando el modelo deja de rechazar: red-teaming de agentes de IA en Kubernetes
```
*(77 car. ✓ — la versión larga anterior tenía 105 y NO entraba)*

Variante alternativa (si prefieres el gancho de la pregunta):
```
¿Qué controles importan cuando el modelo deja de rechazar? Red team de agentes en K8s
```
*(86 car. ✓)*

### Description — *campo privado, "Helps reviewers understand your talk better. Not published publicly."*
*(Aquí va la versión larga y detallada que el comité exige; no se publica, así que puede ser extensa y técnica.)*
```
El 4 de mayo de 2026, un tweet público movió 3,000 millones de tokens on-chain sin que ningún humano aprobara la transferencia. La cadena de ataque no usó ningún 0-day: un atacante compró membresía de un NFT club que desbloqueaba el toolset de transferencia del bot sin aprobación humana; codificó el payload en Morse porque el filtro de palabras clave del bot solo escaneaba strings en inglés; el bot tradujo el mensaje públicamente y etiquetó a la cuenta objetivo en su propia respuesta; y el escáner de comandos de un segundo bot leyó ese tuit verificado como una orden autenticada y firmó la transferencia ERC-20. Cuatro controles que existían, ninguno hablando con el otro.

Esta charla es red-teaming real de agentes de IA desplegados en Kubernetes, con la tesis de que el rechazo del modelo (refusal) no es un límite de contención: un prompt injection exitoso lo salta, y lo demuestro en vivo — el mismo ataque codificado en Morse pasa de un score de detección de 0.999999 (bloqueo total) a 0.003 e incluso 0.0005 (indistinguible de tráfico normal) en un clasificador real de prompt injection, solo cambiando el verbo de la instrucción ("decode" vs. "translate") — números que medí yo mismo, no copiados. El clasificador no puede llegar a donde el prompt no puede llegar — la frontera tiene que estar en la infraestructura, no en el modelo.

Pruebo 8 vectores de escalada de privilegios (sudo, su, setuid, nsenter, mount, chroot, binarios setuid, /proc/1/root) contra 4 posturas de aislamiento en Kubernetes: un pod sin NetworkPolicy, un pod con NetworkPolicy, un sandbox vía SSH/runc, y OpenShift con Kata Containers (microVM). Mido 6 fronteras reales: credenciales del gateway, API de Kubernetes, secretos en otro compartimento, elevación de privilegios, mediación de escritura de herramientas, y persistencia en el workspace del agente.

El resultado no es "todo está resuelto". La mediación de escritura de herramientas falla en 2 de las 4 posturas — el harness reporta que bloqueó una herramienta, pero el binario subyacente escribe el archivo igual, en el mismo contenedor. Y la persistencia en el workspace del agente falla en las 4 posturas probadas: ningún control de este stack la detiene. Un archivo de memoria envenenado sobrevive a la sesión, queda dormido sin generar tráfico ni alerta, y se activa cuando una sesión futura vuelve a cargar el mismo workspace — el vector que mapea a OWASP ASI06, Memory and Context Poisoning.

Todo el laboratorio es reproducible y vive en un repositorio público con GitOps (Argo CD): un ApplicationSet despliega las 4 posturas sobre OpenShift, los scripts miden las 6 fronteras con tokens canario verificados FUERA del agente, y los resultados que presento son los que ejecuto en mi propio clúster OpenShift 4.22 — no números copiados (la demo del clasificador ya está medida: 0.999999 → 0.0005). Cierro con un blueprint de operador para Kubernetes que sí contiene lo que se puede contener (namespaces separados para credenciales y ejecución, SSH como único ingreso, egress deny-by-default, verificación de objetivo antes de ejecutar) y con una lista honesta de lo que ese blueprint todavía NO resuelve, para que quien se lo lleve a un pentest real sepa exactamente dónde seguir buscando.

Crédito: la metodología de referencia es el estudio empírico de Roy Belio (Red Hat), "Which Controls Still Matter When the Model Stops Refusing?", que reencuadro en clave ofensiva con laboratorio y resultados propios.
```

### Abstract — *PÚBLICO, aparece en el schedule. Máximo 300 palabras*
```
Un tweet movió 3,000 millones de tokens sin que ningún humano firmara nada. No hubo 0-day: solo cuatro controles que existían y no se hablaban entre sí. Ese es el punto de partida para una idea incómoda — el rechazo del modelo (refusal) nunca fue una frontera de seguridad. Un prompt injection exitoso lo salta, y cuando lo hace, lo único que queda entre el atacante y tus secretos es tu infraestructura.

En esta charla hago red-teaming real de agentes de IA sobre Kubernetes. Primero demuestro, en vivo, cómo un clasificador de prompt injection pasa de bloquear un ataque a ignorarlo por completo con solo cambiar el verbo de la instrucción. Después pruebo 8 vectores de escalada de privilegios (sudo, setuid, nsenter, mount, chroot, /proc/1/root y más) contra 4 posturas de aislamiento: desde un pod sin NetworkPolicy hasta OpenShift con Kata Containers, midiendo 6 fronteras reales con tokens canario.

El resultado no es tranquilizador: la mediación de escritura de herramientas falla en 2 de 4 posturas, y la persistencia de memoria del agente no la detiene ninguna — un archivo envenenado sobrevive a la sesión y se activa después, sin generar una sola alerta.

Todo el laboratorio es reproducible: vive en un repositorio público con GitOps (Argo CD) y los números que muestro son los de mi propio clúster. Te llevas una metodología para auditar cualquier plataforma de agentes, las técnicas concretas de escalada con el mecanismo de kernel detrás de cada bloqueo, y un blueprint de operador — junto con la lista honesta de lo que ese blueprint todavía no resuelve.

Nivel intermedio-avanzado. Se asume Kubernetes, contenedores y una noción de qué es un agente de IA; el foco está en el ataque y en los resultados medidos.
```
*(~290 palabras ✓)*

### Talk Teaser — *máximo 240 caracteres, pitch para redes sociales*
```
Un tweet movió 3,000M de tokens sin que nadie firmara. El refusal del modelo no es contención. Pruebo 8 vectores de escalada contra 4 posturas de aislamiento en Kubernetes —y muestro cuáles fallan de verdad. Lab 100% reproducible.
```
*(~233 car. ✓ — verificar al pegar)*

### Session format  *(select cerrado)*
```
Session (50 min)
```
*(Opciones reales: Lightning talk (30 min) / Session (50 min) / Workshop (2 horas) / Village. El esqueleto de abajo está cronometrado a 50 min.)*

### Track  *(select cerrado)*
```
Community
```
*(Opciones reales: Community / Village / Sponsor/Business.)*

### Level  *(select cerrado)*
```
Intermediate / Advanced
```

### Language  *(select cerrado)*
```
Español
```

### Supporting Files — *1 archivo, máx 50 MB (PDF/Word/PPT/imágenes/texto)*
> El CFP da **preferencia explícita** a quien adjunta material. Como todo el contenido vive en un repo público,
> el adjunto es un **PDF corto de 1 página** (portada + resumen + QR/link al repo) exportado desde `one-pager.md` (misma carpeta).
> El repo tiene el documento técnico completo (README + docs/) y el laboratorio GitOps reproducible.
> Repo: `https://github.com/jeanpaul-lopez/black-alpaca-redteam-agentes-k8s` *(ajustar al publicar)*

### Co-speakers
```
(dejar vacío)
```

---

## 👤 PERFIL DE SPEAKER

> El perfil actual en Sessionize tiene la bio genérica de Cloud Native. Para ESTA charla conviene una bio
> que conecte tu experiencia de endurecimiento de plataforma con el ángulo de seguridad de agentes.

### Tagline  *(máx 200 car.)*
```
Senior Consultant @ Red Hat · Kubernetes/OpenShift hardening · seguridad de agentes de IA
```

### Bio
```
Jean Paul López es Senior Consultant en Red Hat, peruano, con años ayudando a empresas de LATAM a llevar cargas de trabajo a producción sobre Kubernetes y OpenShift — incluyendo el endurecimiento de clústeres para clientes con requisitos regulatorios estrictos en banca y sector público. Últimamente aplica esa misma disciplina de seguridad de plataforma al mundo de los agentes de IA: construye servidores MCP, experimenta con runtimes de agentes en clústeres reales, y antes de subir cualquier afirmación a una diapositiva la contrasta contra el código fuente, la documentación oficial o un laboratorio propio. Esta charla nace de esa disciplina aplicada a un problema nuevo: qué controles de Kubernetes siguen deteniendo a un atacante cuando el modelo de IA ya fue comprometido.
```

- **Country of Residence:** Perú *(campo obligatorio en el formulario)*
- **Shirt Size:** *(campo obligatorio — elegir la tuya)*
- **Links:** opcionales (hasta 5). LinkedIn/GitHub si quieres reforzar el perfil.

---

## 🗣️ Esqueleto de la charla — cronometrado a 50 min (formato real del slot)

1. **(0-5 min)** El ataque real: cadena de 3,000M de tokens movidos con un tuit el 4 may 2026 — ningún paso fue un 0-day; la falla fue de comunicación entre controles.
2. **(5-13 min)** Por qué el refusal del modelo no es una frontera: demo en vivo del clasificador de prompt injection pasando de bloquear (~1.0) a ignorar (~0.004) el mismo ataque Morse con un cambio de verbo.
3. **(13-20 min)** Metodología de red team: 4 posturas (bare, bare-np, ssh, kata), 6 fronteras, instrumentación con tokens canario verificados fuera del agente, y cómo Argo CD despliega todo el lab.
4. **(20-32 min)** Demo en vivo: los 8 vectores de escalada contra la sesión sandboxed — resultado y mecanismo de kernel detrás de cada bloqueo (capabilities efectivas, namespaces de propiedad root).
5. **(32-40 min)** El hallazgo incómodo: mediación de escritura rota en 2 de 4 posturas; persistencia de workspace rota en las 4. Qué implica para un pentest real.
6. **(40-47 min)** Blueprint de operador: separación de namespaces gateway/sandbox, egress deny-by-default, verificación de objetivo antes de ejecutar — con manifiestos reales del repo.
7. **(47-50 min)** Checklist de cierre para auditar o defender una plataforma de agentes + cómo reproducir el lab.
8. Preguntas.

---

## ⚠️ ANTES DE ENVIAR — checklist

- [ ] **Título ≤100 car.** — elegir entre las dos variantes de arriba.
- [ ] **Abstract ≤300 palabras** — pegar y verificar el contador de Sessionize.
- [ ] **Talk Teaser ≤240 car.** — pegar y verificar.
- [ ] **Supporting File**: exportar el one-pager a PDF y subirlo (1 archivo, 50 MB).
- [ ] **Repo público** publicado y enlazado (ajustar la URL en todos lados antes de enviar).
- [ ] **Validación real ejecutada**: clasificador + 8 vectores + 4 posturas vía Argo CD en el clúster OCP, resultados registrados en `../04-attack-lab/boundary-probes/results/`. Si algún número difiere del estudio de referencia, presentar el propio.
- [ ] Rellenar **Country of Residence (Perú)** y **Shirt Size** (obligatorios).
- [ ] Marcar el **Consent** de compartir datos con el organizador.
- [ ] Dar **crédito explícito** a Roy Belio (Red Hat) por la metodología de referencia — en la charla y en el repo.

---

## Fuentes

- "Which Controls Still Matter When the Model Stops Refusing? An Empirical Isolation Study of Autonomous Agent Containment on Kubernetes" — Roy Belio (Red Hat), AGNTCon+MCPCon Europe 2026. Fuente primaria de la metodología, el caso de mayo 2026, los 8 vectores y las 4 posturas.
- Black Alpaca 2026 — CFP oficial en Sessionize (sessionize.com/black-alpaca-2026) y sitio del evento (blackalpaca.org).
