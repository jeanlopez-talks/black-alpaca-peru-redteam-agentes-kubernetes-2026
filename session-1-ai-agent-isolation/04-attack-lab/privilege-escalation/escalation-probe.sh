#!/usr/bin/env bash
#
# escalation-probe.sh
# -------------------
# Se ejecuta DENTRO del pod sandbox (uid 1000, capabilities dropped) e intenta
# los 8 vectores de escalada de privilegios de ../lab-conventions.md, en orden.
#
# Para cada vector captura el resultado REAL (comando + exit code + stderr) y
# reporta:
#   PASS = el vector fue BLOQUEADO (el sandbox contuvo el intento)   -> lo esperado
#   FAIL = el vector ESCAPO (logro elevar privilegios)               -> hallazgo grave
#
# Tambien imprime el mecanismo de kernel que se espera que lo bloquee.
# Al final emite un bloque JSON con el detalle maquina-legible.
#
# NOTA: este script NO requiere kubectl/oc; se ejecuta ya dentro del contenedor.
#       El helper run-against-pod.sh es quien lo inyecta via exec.

set -euo pipefail

# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

# Acumuladores para el bloque JSON final.
JSON_ENTRIES=()
PASS_COUNT=0
FAIL_COUNT=0

# Escapa comillas/backslashes/newlines para incrustar texto en JSON.
json_escape() {
  local s=${1//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\t'/\\t}
  s=${s//$'\r'/}
  printf '%s' "$s"
}

# record <num> <nombre> <mecanismo> <comando> <exit_code> <stderr> <veredicto>
record() {
  local num="$1" name="$2" mech="$3" cmd="$4" rc="$5" err="$6" verdict="$7"

  if [[ "$verdict" == "PASS" ]]; then
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi

  # Salida legible.
  printf '[%s] vector %d: %-16s\n' "$verdict" "$num" "$name"
  printf '        comando : %s\n' "$cmd"
  printf '        exit    : %s\n' "$rc"
  printf '        mecanismo esperado: %s\n' "$mech"
  if [[ -n "$err" ]]; then
    printf '        stderr  : %s\n' "$err"
  fi
  echo

  JSON_ENTRIES+=("$(cat <<JSON
    {
      "vector": $num,
      "name": "$(json_escape "$name")",
      "command": "$(json_escape "$cmd")",
      "exit_code": $rc,
      "expected_mechanism": "$(json_escape "$mech")",
      "stderr": "$(json_escape "$err")",
      "verdict": "$verdict"
    }
JSON
)")
}

# Ejecuta un comando capturando stderr y exit code SIN abortar el script.
# Uso: run_capture "<comando a probar>"   -> setea RC y ERR
run_capture() {
  local to_run="$1"
  ERR=""
  RC=0
  # Deshabilitamos -e temporalmente: esperamos que el comando falle.
  set +e
  ERR="$(bash -c "$to_run" 2>&1 1>/dev/null)"
  RC=$?
  set -e
}

echo "==============================================================================="
echo " escalation-probe — 8 vectores de escalada (uid=$(id -u) gid=$(id -g))"
echo " host=$(hostname 2>/dev/null || echo '?')  fecha=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "==============================================================================="
echo

# ---------------------------------------------------------------------------
# Vector 1: sudo  (esperado: binario no instalado)
# ---------------------------------------------------------------------------
CMD='sudo -n id'
run_capture "$CMD"
# PASS si NO somos root tras el intento. Aqui el intento debe fallar (rc!=0).
if [[ "$RC" -ne 0 ]]; then verdict=PASS; else verdict=FAIL; fi
record 1 "sudo" "binario no instalado" "$CMD" "$RC" "$ERR" "$verdict"

# ---------------------------------------------------------------------------
# Vector 2: su root  (esperado: contrasena desconocida)
# ---------------------------------------------------------------------------
# Enviamos una contrasena cualquiera por stdin; debe rechazarse.
CMD='echo "x" | su -c id root'
run_capture "$CMD"
if [[ "$RC" -ne 0 ]]; then verdict=PASS; else verdict=FAIL; fi
record 2 "su root" "contrasena desconocida" "$CMD" "$RC" "$ERR" "$verdict"

# ---------------------------------------------------------------------------
# Vector 3: os.setuid(0)  (esperado: sin CAP_SETUID)
# ---------------------------------------------------------------------------
# Intentamos elevar via python (o perl si no hay python). Debe lanzar EPERM.
if command -v python3 >/dev/null 2>&1; then
  CMD='python3 -c "import os; os.setuid(0); print(os.getuid())"'
elif command -v python >/dev/null 2>&1; then
  CMD='python -c "import os; os.setuid(0); print(os.getuid())"'
else
  CMD='perl -e "POSIX::setuid(0) or die $!; print((getpwuid($<))[2])" 2>&1'
fi
run_capture "$CMD"
# PASS si fallo (no pudo setuid). Si rc==0 y devolvio 0, escapo.
if [[ "$RC" -ne 0 ]]; then verdict=PASS; else verdict=FAIL; fi
record 3 "os.setuid(0)" "sin CAP_SETUID" "$CMD" "$RC" "$ERR" "$verdict"

# ---------------------------------------------------------------------------
# Vector 4: nsenter -t 1  (esperado: permiso denegado, no CAP_SYS_ADMIN)
# ---------------------------------------------------------------------------
CMD='nsenter -t 1 -m -u -i -n -p -- id'
run_capture "$CMD"
if [[ "$RC" -ne 0 ]]; then verdict=PASS; else verdict=FAIL; fi
record 4 "nsenter -t 1" "permiso denegado (no CAP_SYS_ADMIN)" "$CMD" "$RC" "$ERR" "$verdict"

# ---------------------------------------------------------------------------
# Vector 5: mount -t proc  (esperado: requiere superusuario / CAP_SYS_ADMIN)
# ---------------------------------------------------------------------------
CMD='mkdir -p /tmp/pm && mount -t proc proc /tmp/pm'
run_capture "$CMD"
if [[ "$RC" -ne 0 ]]; then verdict=PASS; else verdict=FAIL; fi
record 5 "mount -t proc" "requiere superusuario / CAP_SYS_ADMIN" "$CMD" "$RC" "$ERR" "$verdict"

# ---------------------------------------------------------------------------
# Vector 6: chroot  (esperado: sin CAP_SYS_CHROOT)
# ---------------------------------------------------------------------------
CMD='chroot / /bin/true'
run_capture "$CMD"
if [[ "$RC" -ne 0 ]]; then verdict=PASS; else verdict=FAIL; fi
record 6 "chroot" "sin CAP_SYS_CHROOT" "$CMD" "$RC" "$ERR" "$verdict"

# ---------------------------------------------------------------------------
# Vector 7: binario setuid  (esperado: sin capacidad de chown a root)
# ---------------------------------------------------------------------------
# Creamos un binario y tratamos de darle setuid-root. chown a root debe fallar.
CMD='cp /bin/sh /tmp/rootsh && chown 0:0 /tmp/rootsh && chmod 4755 /tmp/rootsh && /tmp/rootsh -c "id -u"'
run_capture "$CMD"
if [[ "$RC" -ne 0 ]]; then verdict=PASS; else verdict=FAIL; fi
record 7 "binario setuid" "sin capacidad de chown a root" "$CMD" "$RC" "$ERR" "$verdict"

# ---------------------------------------------------------------------------
# Vector 8: /proc/1/root  (esperado: permiso denegado; namespace de PID 1 de root)
# ---------------------------------------------------------------------------
CMD='ls -la /proc/1/root/'
run_capture "$CMD"
if [[ "$RC" -ne 0 ]]; then verdict=PASS; else verdict=FAIL; fi
record 8 "/proc/1/root" "permiso denegado (namespace de PID 1 es de root)" "$CMD" "$RC" "$ERR" "$verdict"

# ---------------------------------------------------------------------------
# Resumen + bloque JSON
# ---------------------------------------------------------------------------
echo "-------------------------------------------------------------------------------"
echo " Resumen escalada: PASS(bloqueado)=$PASS_COUNT  FAIL(escapo)=$FAIL_COUNT  total=8"
echo "-------------------------------------------------------------------------------"
echo

# Unimos las entradas JSON con comas.
JOINED=""
for i in "${!JSON_ENTRIES[@]}"; do
  if [[ "$i" -gt 0 ]]; then JOINED+=","$'\n'; fi
  JOINED+="${JSON_ENTRIES[$i]}"
done

echo "===JSON_BEGIN==="
cat <<JSON
{
  "probe": "escalation",
  "uid": $(id -u),
  "gid": $(id -g),
  "hostname": "$(json_escape "$(hostname 2>/dev/null || echo '')")",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "summary": { "pass": $PASS_COUNT, "fail": $FAIL_COUNT, "total": 8 },
  "vectors": [
$JOINED
  ]
}
JSON
echo "===JSON_END==="

# El script siempre sale 0: el veredicto esta en el JSON, no en el exit code.
exit 0
