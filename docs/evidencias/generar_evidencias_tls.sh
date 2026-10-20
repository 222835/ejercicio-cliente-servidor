#!/usr/bin/env bash
# Genera las evidencias de la Parte 1 (cliente-servidor y TLS) que no requieren dos equipos.
# Uso, desde la raíz del repo y con el entorno virtual activo:
#     bash docs/evidencias/generar_evidencias_tls.sh
# Las capturas de Wireshark y la prueba TLS exitosa con el certificado real se hacen a
# mano entre los dos equipos (ver README-TLS.md).
set -euo pipefail

cd "$(dirname "$0")/../.."
TLS=docs/evidencias/tls
mkdir -p "$TLS"

export NO_COLOR=1 PYTHONIOENCODING=utf-8
export RUTA_LOG="$TLS/eventos.jsonl"
rm -f "$RUTA_LOG"

PUERTO=5443
HOSTNAME=222835-cliente-servidor.duckdns.org
TMP=$(mktemp -d)
PID=""
trap '[ -n "$PID" ] && kill "$PID" 2>/dev/null; rm -rf "$TMP"' EXIT

encabezado() {  # $1 = comando ejecutado
  echo "# Comando: $1"
  echo "# Fecha:   $(date '+%Y-%m-%d %H:%M:%S %z')"
  echo "# Commit:  $(git rev-parse --short HEAD 2>/dev/null || echo 'sin git')"
  echo "# Python:  $(python --version 2>&1)"
  echo
}

correr() {  # $1 = archivo de salida, resto = comando
  local salida=$1; shift
  { encabezado "$*"; "$@" 2>&1; } > "$salida" || true
  echo "  -> $salida"
}

# Levanta un servidor, corre un cliente contra él y lo apaga. Imprime ambos comandos.
#   $1 = título, $2 = argumentos del servidor, $3 = argumentos del cliente
caso() {
  echo "=== $1"
  echo "\$ python -m tls.servidor $2"
  python -m tls.servidor $2 > /dev/null 2>&1 &
  PID=$!
  sleep 1
  echo "\$ python -m tls.cliente $3"
  python -m tls.cliente $3 2>&1 || echo "(código de salida: $?)"
  kill "$PID" 2>/dev/null || true
  wait "$PID" 2>/dev/null || true
  PID=""
  echo
}

# Cadena que enviaría un servidor: certificado + intermedia (los "malos" no la traen).
cadena() { cat "pki/malos/$1.crt" pki/intermedia/int.crt > "$TMP/$1-chain.crt"; echo "$TMP/$1-chain.crt"; }

demo_cli() {
  encabezado "(varios, ver abajo)"
  local malos=pki/malos
  local base="--host 127.0.0.1 --puerto $PUERTO"

  caso "Sin protección: el servicio funciona, pero nada va cifrado" \
       "--modo plano --host 127.0.0.1 --puerto $PUERTO" \
       "$base --modo plano"

  caso "TLS: certificado autofirmado -> el cliente rechaza" \
       "--modo tls --host 127.0.0.1 --puerto $PUERTO --cert $malos/autofirmado.crt --llave $malos/autofirmado.key" \
       "$base --modo tls --hostname $HOSTNAME"

  caso "TLS: certificado expirado -> el cliente rechaza" \
       "--modo tls --host 127.0.0.1 --puerto $PUERTO --cert $(cadena expirado) --llave $malos/expirado.key" \
       "$base --modo tls --hostname $HOSTNAME"

  caso "TLS: nombre incorrecto (otro-servidor.com) -> el cliente rechaza" \
       "--modo tls --host 127.0.0.1 --puerto $PUERTO --cert $(cadena nombre-incorrecto) --llave $malos/nombre-incorrecto.key" \
       "$base --modo tls --hostname $HOSTNAME"

  caso "TLS: firmado por otra CA (CA Falsa) -> el cliente rechaza" \
       "--modo tls --host 127.0.0.1 --puerto $PUERTO --cert $malos/otra-ca.crt --llave $malos/otra-ca.key" \
       "$base --modo tls --hostname $HOSTNAME"
}

echo "Generando evidencias..."
correr "$TLS/pruebas-tls.txt" python -m pytest -v tests/test_tls.py
{ demo_cli; } > "$TLS/demo-cliente-servidor.txt" 2>&1 || true
echo "  -> $TLS/demo-cliente-servidor.txt"
rm -rf .pytest_cache
echo "Listo. Registro de eventos: $RUTA_LOG"
