#!/usr/bin/env bash
# Genera las evidencias de la Parte 3 (IPSec) y la Parte 4 (VPN y AAA).
# Uso, desde la raíz del repo y con el entorno virtual activo:
#     bash docs/evidencias/generar_evidencias_vpn_ipsec.sh
set -euo pipefail

cd "$(dirname "$0")/../.."
VPN=docs/evidencias/vpn
IPSEC=docs/evidencias/ipsec
mkdir -p "$VPN" "$IPSEC"

export COLUMNS=130 NO_COLOR=1 TERM=dumb
export RUTA_LOG="$VPN/eventos.jsonl"
rm -f "$RUTA_LOG"

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

echo "Generando evidencias..."

# Parte 4: pruebas automáticas
correr "$VPN/pruebas-autenticacion-autorizacion.txt" python -m pytest -v tests/test_auth.py
correr "$VPN/pruebas-vpn-acceso-remoto.txt"          python -m pytest -v tests/test_acceso_remoto.py
correr "$VPN/pruebas-vpn-sitio-a-sitio.txt"          python -m pytest -v tests/test_sitio_a_sitio.py

# Parte 4: demos (las demos también escriben en eventos.jsonl)
correr "$VPN/demo-vpn-acceso-remoto.txt" python demo_vpn.py --remota
correr "$VPN/demo-vpn-sitio-a-sitio.txt" python demo_vpn.py --sitio
correr "$VPN/demo-vpn-completa.txt" python demo_vpn.py

# Parte 3: IPSec
correr "$IPSEC/pruebas-ipsec.txt" python -m pytest -v tests/test_ipsec.py
correr "$IPSEC/demo-transporte-vs-tunel.txt" python demo_ipsec.py

# Resumen de todas las pruebas juntas
correr "docs/evidencias/pruebas-todas.txt" python -m pytest -v

rm -rf .pytest_cache
echo "Listo. Registro de eventos: $RUTA_LOG"
