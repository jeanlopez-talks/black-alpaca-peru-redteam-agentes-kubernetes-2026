#!/usr/bin/env bash
#
# collect_results.sh [postura...]
# -------------------------------
# Orquesta el laboratorio: corre probe_boundaries.sh + escalation_probe.sh
# contra una o varias posturas (via kubectl exec) y genera:
#   results/<postura>.json   resultado maquina-legible por postura
#   results/matrix.md        tabla comparativa (4 posturas x 6 fronteras)
#
# Sin argumentos, procesa las 4 posturas: bare bare-np ssh kata.
# Admite un subconjunto:  ./collect_results.sh ssh kata
#
# Detecta oc o kubectl. Corre el probe de fronteras DOS veces por postura para
# verificar la persistencia de workspace (si el canario sobrevive a la 2a corrida,
# la persistencia queda confirmada DESDE FUERA del agente).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BOUNDARIES_PROBE="$SCRIPT_DIR/probe_boundaries.sh"
ESCALATION_PROBE="$LAB_DIR/escalation/escalation_probe.sh"
RESULTS_DIR="$SCRIPT_DIR/results"

ALL_POSTURES=(bare bare-np ssh kata)
POSTURES=("$@")
if [[ ${#POSTURES[@]} -eq 0 ]]; then
  POSTURES=("${ALL_POSTURES[@]}")
fi

# ---------------------------------------------------------------------------
# Cliente kube
# ---------------------------------------------------------------------------
if command -v oc >/dev/null 2>&1; then KCTL="oc"
elif command -v kubectl >/dev/null 2>&1; then KCTL="kubectl"
else echo "ERROR: no hay 'oc' ni 'kubectl' en el PATH." >&2; exit 1; fi

for f in "$BOUNDARIES_PROBE" "$ESCALATION_PROBE"; do
  [[ -f "$f" ]] || { echo "ERROR: falta el probe $f" >&2; exit 1; }
done

mkdir -p "$RESULTS_DIR"

# Namespace sandbox por postura (../../../shared/lab-conventions.md).
sandbox_ns() {
  case "$1" in
    bare)    echo "openclaw-bare" ;;
    bare-np) echo "openclaw-bare-np" ;;
    ssh)     echo "openclaw-ssh-sandbox" ;;
    kata)    echo "openclaw-kata-sandbox" ;;
    *)       echo "" ;;
  esac
}

# Resuelve el pod sandbox de un namespace.
find_sandbox_pod() {
  local ns="$1" pod
  pod="$("$KCTL" -n "$ns" get pods -l app=sandbox -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  [[ -z "$pod" ]] && pod="$("$KCTL" -n "$ns" get pods -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  echo "$pod"
}

# Extrae el bloque JSON entre los marcadores de un probe.
extract_json() {
  sed -n '/===JSON_BEGIN===/,/===JSON_END===/p' | sed '1d;$d'
}

# ---------------------------------------------------------------------------
# Procesar cada postura
# ---------------------------------------------------------------------------
declare -A STATUS   # STATUS["<postura>:<frontera>"] = PASS|FAIL|n/a

for POSTURE in "${POSTURES[@]}"; do
  NS="$(sandbox_ns "$POSTURE")"
  echo "==============================================================================="
  echo " Postura: $POSTURE   namespace: $NS   cliente: $KCTL"
  echo "==============================================================================="

  if [[ -z "$NS" ]]; then
    echo "[!] postura desconocida '$POSTURE', la salto." >&2
    continue
  fi

  POD="$(find_sandbox_pod "$NS")"
  if [[ -z "$POD" ]]; then
    echo "[!] sin pod sandbox en $NS (¿desplegaste la postura?). La salto." >&2
    # Registramos n/a para esta postura.
    for b in gateway-creds k8s-api secret-crosscompartment priv-escalation tool-write-mediation workspace-persistence; do
      STATUS["$POSTURE:$b"]="n/a"
    done
    continue
  fi
  echo "[*] pod objetivo: $POD"

  # --- Escalada (vector priv-escalation) ---
  echo "[*] corriendo escalation_probe.sh ..."
  ESC_OUT="$("$KCTL" -n "$NS" exec -i "$POD" -- bash -s < "$ESCALATION_PROBE" 2>/dev/null || true)"
  ESC_JSON="$(printf '%s\n' "$ESC_OUT" | extract_json)"

  # --- Fronteras: corremos DOS veces para verificar persistencia ---
  echo "[*] corriendo probe_boundaries.sh (pasada 1/2) ..."
  "$KCTL" -n "$NS" exec -i "$POD" --env="POSTURE=$POSTURE" -- bash -s < "$BOUNDARIES_PROBE" >/dev/null 2>&1 || true
  echo "[*] corriendo probe_boundaries.sh (pasada 2/2, verifica persistencia) ..."
  BND_OUT="$("$KCTL" -n "$NS" exec -i "$POD" --env="POSTURE=$POSTURE" -- bash -s < "$BOUNDARIES_PROBE" 2>/dev/null || true)"
  BND_JSON="$(printf '%s\n' "$BND_OUT" | extract_json)"

  # --- Guardar JSON por postura ---
  OUT_FILE="$RESULTS_DIR/$POSTURE.json"
  cat > "$OUT_FILE" <<JSON
{
  "posture": "$POSTURE",
  "namespace": "$NS",
  "pod": "$POD",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "escalation": ${ESC_JSON:-null},
  "boundaries": ${BND_JSON:-null}
}
JSON
  echo "[*] guardado $OUT_FILE"

  # --- Derivar estado por frontera para la matriz ---
  # priv-escalation: PASS solo si los 8 vectores fueron PASS (fail==0).
  ESC_FAIL="$(printf '%s' "$ESC_JSON" | grep -oE '"fail":[[:space:]]*[0-9]+' | head -1 | grep -oE '[0-9]+' || echo "")"
  if [[ -z "$ESC_FAIL" ]]; then STATUS["$POSTURE:priv-escalation"]="n/a"
  elif [[ "$ESC_FAIL" -eq 0 ]]; then STATUS["$POSTURE:priv-escalation"]="PASS"
  else STATUS["$POSTURE:priv-escalation"]="FAIL"; fi

  # Resto de fronteras: leemos el verdict de cada boundary del JSON.
  for b in gateway-creds k8s-api secret-crosscompartment tool-write-mediation workspace-persistence; do
    v="$(printf '%s' "$BND_JSON" \
      | tr -d '\n' \
      | grep -oE "\"boundary\":[[:space:]]*\"$b\"[^}]*\"verdict\":[[:space:]]*\"(PASS|FAIL)\"" \
      | grep -oE '"verdict":[[:space:]]*"(PASS|FAIL)"' \
      | grep -oE '(PASS|FAIL)' | head -1 || true)"
    STATUS["$POSTURE:$b"]="${v:-n/a}"
  done
  echo
done

# ---------------------------------------------------------------------------
# Matriz comparativa (4 posturas x 6 fronteras)
# ---------------------------------------------------------------------------
BOUNDARIES=(gateway-creds k8s-api secret-crosscompartment priv-escalation tool-write-mediation workspace-persistence)
MATRIX="$RESULTS_DIR/matrix.md"

{
  echo "# Matriz de resultados — red-teaming de agentes en Kubernetes"
  echo
  echo "Generado: $(date -u +%Y-%m-%dT%H:%M:%SZ) · cliente: \`$KCTL\`"
  echo
  echo "PASS = la frontera CONTUVO al atacante · FAIL = el atacante ESCAPO · n/a = postura no desplegada"
  echo
  # Cabecera
  printf '| frontera |'
  for p in "${ALL_POSTURES[@]}"; do printf ' %s |' "$p"; done
  printf '\n|---|'
  for _ in "${ALL_POSTURES[@]}"; do printf '---|'; done
  printf '\n'
  # Filas
  for b in "${BOUNDARIES[@]}"; do
    printf '| %s |' "$b"
    for p in "${ALL_POSTURES[@]}"; do
      printf ' %s |' "${STATUS["$p:$b"]:-n/a}"
    done
    printf '\n'
  done
  echo
  echo "> Nota de honestidad: \`tool-write-mediation\` y \`workspace-persistence\`"
  echo "> se esperan como **FAIL** (hallazgos del estudio de referencia). Confirma"
  echo "> en TU clúster — no copies los numeros del estudio original."
} > "$MATRIX"

echo "==============================================================================="
echo " Matriz escrita en $MATRIX"
echo "==============================================================================="
cat "$MATRIX"
