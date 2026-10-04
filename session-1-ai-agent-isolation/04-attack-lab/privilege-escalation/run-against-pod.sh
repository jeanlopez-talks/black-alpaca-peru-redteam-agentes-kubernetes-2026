#!/usr/bin/env bash
#
# run-against-pod.sh <postura>
# ----------------------------
# Helper que ejecuta escalation-probe.sh DENTRO del pod sandbox de una postura.
# Detecta oc o kubectl, resuelve el namespace sandbox de la postura segun
# ../lab-conventions.md, inyecta el probe via stdin a `exec` y recoge el resultado.
#
# Posturas validas: bare | bare-np | ssh | kata
#
# Uso:
#   ./run-against-pod.sh ssh
#   ./run-against-pod.sh kata > /tmp/kata-escalation.txt
#
# Salida: el reporte legible + el bloque JSON del probe en stdout.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROBE="$SCRIPT_DIR/escalation-probe.sh"

# ---------------------------------------------------------------------------
# 1. Validar argumento
# ---------------------------------------------------------------------------
if [[ $# -ne 1 ]]; then
  echo "uso: $0 <postura>   (bare | bare-np | ssh | kata)" >&2
  exit 2
fi
POSTURE="$1"

# ---------------------------------------------------------------------------
# 2. Resolver el namespace sandbox segun la postura (../lab-conventions.md)
# ---------------------------------------------------------------------------
case "$POSTURE" in
  bare)     SANDBOX_NS="openclaw-bare" ;;
  bare-np)  SANDBOX_NS="openclaw-bare-np" ;;
  ssh)      SANDBOX_NS="openclaw-ssh-sandbox" ;;
  kata)     SANDBOX_NS="openclaw-kata-sandbox" ;;
  *)
    echo "ERROR: postura desconocida '$POSTURE' (bare|bare-np|ssh|kata)" >&2
    exit 2
    ;;
esac

# ---------------------------------------------------------------------------
# 3. Detectar cliente: oc preferido, kubectl de respaldo
# ---------------------------------------------------------------------------
if command -v oc >/dev/null 2>&1; then
  KCTL="oc"
elif command -v kubectl >/dev/null 2>&1; then
  KCTL="kubectl"
else
  echo "ERROR: no se encontro ni 'oc' ni 'kubectl' en el PATH." >&2
  exit 1
fi

if [[ ! -f "$PROBE" ]]; then
  echo "ERROR: no encuentro el probe en $PROBE" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# 4. Localizar el deployment/pod sandbox
#    Convencion: el deployment sandbox lleva la etiqueta app=sandbox.
#    Si no hay match por label, caemos al primer pod del namespace.
# ---------------------------------------------------------------------------
echo "[*] postura=$POSTURE  namespace=$SANDBOX_NS  cliente=$KCTL" >&2

POD="$("$KCTL" -n "$SANDBOX_NS" get pods -l app=sandbox \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"

if [[ -z "$POD" ]]; then
  echo "[!] sin pods con label app=sandbox; usando el primer pod del namespace" >&2
  POD="$("$KCTL" -n "$SANDBOX_NS" get pods \
          -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
fi

if [[ -z "$POD" ]]; then
  echo "ERROR: no hay pods en el namespace $SANDBOX_NS. Despliega la postura primero." >&2
  exit 1
fi

echo "[*] pod sandbox objetivo: $POD" >&2

# ---------------------------------------------------------------------------
# 5. Verificar que el pod esta Running (no correr contra un pod no listo)
# ---------------------------------------------------------------------------
PHASE="$("$KCTL" -n "$SANDBOX_NS" get pod "$POD" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
if [[ "$PHASE" != "Running" ]]; then
  echo "ERROR: el pod $POD esta en fase '$PHASE', no 'Running'. Aborto." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# 6. Inyectar y ejecutar el probe via stdin (sin necesidad de 'kubectl cp')
#    'exec -i ... -- bash -s' lee el script desde stdin: evita copiar archivos
#    y funciona aunque el contenedor no tenga el probe montado.
# ---------------------------------------------------------------------------
echo "[*] ejecutando escalation-probe.sh dentro de $POD ..." >&2
echo >&2

"$KCTL" -n "$SANDBOX_NS" exec -i "$POD" -- bash -s < "$PROBE"

echo >&2
echo "[*] probe de escalada completado para la postura '$POSTURE'." >&2
