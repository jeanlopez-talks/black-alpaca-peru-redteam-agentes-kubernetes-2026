# Cuando el modelo deja de rechazar
## Red-teaming de agentes de IA en Kubernetes — Black Alpaca 2026

**Jean Paul López** · Senior Consultant, Red Hat · Lima, Perú
Repositorio del laboratorio (reproducible, GitOps): `https://github.com/jeanlopez-talks/black-alpaca-peru-redteam-agentes-kubernetes-2026`

---

### Tesis

El **rechazo del modelo (refusal) no es un límite de contención**. Un prompt injection exitoso lo salta.
La pregunta que importa en seguridad ofensiva es qué controles de **infraestructura** siguen deteniendo
al atacante *después* de que el modelo ya fue comprometido.

### El ataque que lo motiva (caso de estudio citado, no replicado)

4 de mayo de 2026: un tweet movió **3,000 millones de tokens** on-chain sin aprobación humana. Cadena:

1. El atacante compra membresía de un NFT club que **desbloquea el toolset de transferencia** sin aprobación.
2. El payload va en **Morse** — el filtro de palabras clave solo escanea inglés y no ve puntos y guiones.
3. El bot **traduce el mensaje públicamente** y etiqueta a la cuenta objetivo en su respuesta.
4. El escáner de comandos de un segundo bot lee ese **tuit verificado como orden autenticada** y firma la transferencia ERC-20.

Ningún 0-day: cuatro controles que existían y no se comunicaban.

### Por qué un clasificador de prompt injection no basta

El mismo payload Morse con distinto **verbo** de instrucción hace que
`protectai/deberta-v3-base-prompt-injection-v2` pase de **0.999999 (bloqueo total)** con `decode this morse`
a **0.003008** con `translate this` y **0.000480** con `@grok translate and tag @bankrbot` — una caída de
**0.99952**. *El clasificador no puede llegar a donde el prompt no puede llegar.*
→ resultados propios en `../../shared/classifier/results.json` (CPU, 2 oct 2026).

### Metodología: 4 posturas de aislamiento × 6 fronteras medidas

| Postura   | Qué aísla |
|-----------|-----------|
| `bare`    | nada — línea base, sin NetworkPolicy |
| `bare-np` | NetworkPolicy egress deny-by-default |
| `ssh`     | sandbox separado, SSH como único ingreso |
| `kata`    | OpenShift + Kata Containers (microVM, kernel de invitado propio) |

**Fronteras:** credenciales del gateway · API de Kubernetes · secreto en otro compartimento ·
escalada de privilegios · mediación de escritura de herramientas · persistencia en el workspace.

### 8 vectores de escalada de privilegios (uid 1000, capabilities dropped)

`sudo` (no instalado) · `su root` (contraseña desconocida) · `os.setuid(0)` (sin `CAP_SETUID`) ·
`nsenter -t 1` (permiso denegado) · `mount -t proc` (requiere superusuario) · `chroot` (sin `CAP_SYS_CHROOT`) ·
binario setuid (sin `chown` a root) · `/proc/1/root` (namespace de PID 1 es de root).

### Los hallazgos incómodos (hipótesis a confirmar en el lab propio)

> Estos son los hallazgos del estudio de referencia (Roy Belio, Red Hat) que el lab reproduce. La matriz
> con los resultados propios se ejecuta con `../04-attack-lab/boundary-probes/collect-results.sh` y se publica en `../04-attack-lab/boundary-probes/results/`.

- **Mediación de escritura de herramientas: se espera que FALLE en `ssh` y `kata`.** El harness reporta
  "rechazado", pero `bash` escribe el archivo igual en el mismo contenedor.
- **Persistencia en el workspace: se espera que FALLE en las 4 posturas.** Ningún control de este stack la
  mitiga (OWASP **ASI06 — Memory and Context Poisoning**). Un archivo de memoria envenenado sobrevive a la
  sesión, queda dormido sin tráfico ni alerta, y se activa cuando una sesión futura carga el mismo workspace.

### Blueprint de operador (lo que SÍ se puede contener)

Namespace `openclaw-gateway` (credenciales, ServiceAccount — el radio de explosión) **separado** de
`openclaw-sandbox` (uid 1000, sin credenciales, `automountServiceAccountToken: false`), SSH como único
ingreso entre ambos, **egress deny-by-default** salvo DNS, y verificación explícita de que el sandbox
objetivo esté activo antes de ejecutar cualquier herramienta. → manifiestos en `../03-gitops/isolation-postures/`.

### Reproducibilidad

Todo el lab se despliega con **Argo CD** (`ApplicationSet` → una `Application` por postura). Los resultados
presentados son los obtenidos en un clúster **OpenShift 4.22** propio, no copiados del estudio de referencia.

---

*Metodología de referencia: Roy Belio (Red Hat), "Which Controls Still Matter When the Model Stops Refusing?",
AGNTCon+MCPCon Europe 2026 — reencuadrada en clave ofensiva, con laboratorio y resultados propios.*
