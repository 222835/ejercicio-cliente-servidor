#!/usr/bin/env bash
# 
# Genera la PKI del proyecto:
#   - CA raíz (autofirmada)
#   - CA intermedia (firmada por la raíz)
#   - Certificado del servidor (firmado por la intermedia)
#   - Certificados inválidos para las pruebas de rechazo
#
#   Necesita openssl y faketime
#

set -euo pipefail

DOMINIO="222835-cliente-servidor.duckdns.org"
ORG="Proyecto CS"
PAIS="MX"

cd "$(dirname "$0")"

paso() { echo; echo "==> $1"; }

# --- Protección contra sobrescribir una CA existente ------------------------
if [[ -f root/ca.key && "${1:-}" != "--forzar" ]]; then
  echo "Ya existe una CA en root/ca.key."
  echo "Regenerarla invalida todos los certificados que ya se entregaron."
  echo "Si de verdad quieres empezar de cero: ./generar_pki.sh --forzar"
  exit 1
fi

if [[ "${1:-}" == "--forzar" ]]; then
  echo "Borrando la PKI actual..."
  rm -rf root intermedia servidor malos
fi

mkdir -p root intermedia servidor malos/ca-falsa

# --- 1. CA raíz ---------------------------------------------------------------
paso "1/6  CA raíz"
openssl genrsa -out root/ca.key 4096 2>/dev/null
openssl req -x509 -new -key root/ca.key -sha256 -days 3650 \
  -subj "/C=$PAIS/O=$ORG/CN=Proyecto Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out root/ca.crt

# --- 2. CA intermedia -----------------------------------------------------------
paso "2/6  CA intermedia"
cat > intermedia/ext.cnf << 'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
EOF

openssl genrsa -out intermedia/int.key 4096 2>/dev/null
openssl req -new -key intermedia/int.key \
  -subj "/C=$PAIS/O=$ORG/CN=Proyecto Intermediate CA" \
  -out intermedia/int.csr
openssl x509 -req -in intermedia/int.csr -CA root/ca.crt -CAkey root/ca.key \
  -CAcreateserial -days 1825 -sha256 -extfile intermedia/ext.cnf \
  -out intermedia/int.crt 2>/dev/null

# --- 3. Certificado del servidor ----------------------------------------------
paso "3/6  Certificado del servidor ($DOMINIO)"
cat > servidor/ext.cnf << EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:$DOMINIO
EOF

openssl genrsa -out servidor/server.key 2048 2>/dev/null
openssl req -new -key servidor/server.key \
  -subj "/C=$PAIS/O=$ORG/CN=$DOMINIO" \
  -out servidor/server.csr
openssl x509 -req -in servidor/server.csr -CA intermedia/int.crt \
  -CAkey intermedia/int.key -CAcreateserial -days 365 -sha256 \
  -extfile servidor/ext.cnf -out servidor/server.crt 2>/dev/null

# El servidor envía su certificado + la intermedia; el cliente solo tiene ca.crt
cat servidor/server.crt intermedia/int.crt > servidor/server-chain.crt

# --- 4. Certificados inválidos: autofirmado y nombre incorrecto ---------------
paso "4/6  Certificado autofirmado"
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -subj "/C=$PAIS/O=$ORG/CN=$DOMINIO" \
  -keyout malos/autofirmado.key -out malos/autofirmado.crt 2>/dev/null

paso "5/6  Certificado con nombre incorrecto y certificado de otra CA"
cat > malos/ext-otro.cnf << 'EOF'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:otro-servidor.com
EOF

openssl genrsa -out malos/nombre-incorrecto.key 2048 2>/dev/null
openssl req -new -key malos/nombre-incorrecto.key \
  -subj "/C=$PAIS/O=$ORG/CN=otro-servidor.com" \
  -out malos/nombre-incorrecto.csr
openssl x509 -req -in malos/nombre-incorrecto.csr -CA intermedia/int.crt \
  -CAkey intermedia/int.key -CAcreateserial -days 365 -sha256 \
  -extfile malos/ext-otro.cnf -out malos/nombre-incorrecto.crt 2>/dev/null
cat malos/nombre-incorrecto.crt intermedia/int.crt > malos/nombre-incorrecto-chain.crt

# CA falsa: firma un certificado con el dominio correcto, pero no es de confianza
openssl genrsa -out malos/ca-falsa/ca-falsa.key 4096 2>/dev/null
openssl req -x509 -new -key malos/ca-falsa/ca-falsa.key -sha256 -days 3650 \
  -subj "/C=$PAIS/O=Atacante/CN=CA Falsa" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out malos/ca-falsa/ca-falsa.crt

openssl genrsa -out malos/otra-ca.key 2048 2>/dev/null
openssl req -new -key malos/otra-ca.key \
  -subj "/C=$PAIS/O=Atacante/CN=$DOMINIO" \
  -out malos/otra-ca.csr
openssl x509 -req -in malos/otra-ca.csr -CA malos/ca-falsa/ca-falsa.crt \
  -CAkey malos/ca-falsa/ca-falsa.key -CAcreateserial -days 365 -sha256 \
  -extfile servidor/ext.cnf -out malos/otra-ca.crt 2>/dev/null

# --- 5. Certificado expirado ----------------------------------------------------
paso "6/6  Certificado expirado"
if command -v faketime > /dev/null; then
  openssl genrsa -out malos/expirado.key 2048 2>/dev/null
  openssl req -new -key malos/expirado.key \
    -subj "/C=$PAIS/O=$ORG/CN=$DOMINIO" \
    -out malos/expirado.csr
  faketime '2024-01-01' openssl x509 -req -in malos/expirado.csr \
    -CA intermedia/int.crt -CAkey intermedia/int.key -CAcreateserial \
    -days 30 -sha256 -extfile servidor/ext.cnf -out malos/expirado.crt 2>/dev/null
elif [[ -f generar_expirado.py ]]; then
  python3 generar_expirado.py
else
  echo "AVISO: no se generó el certificado expirado."
  echo "Instala faketime (sudo apt install faketime) o agrega generar_expirado.py."
fi

chmod 600 root/ca.key intermedia/int.key servidor/server.key 2>/dev/null || true

# --- Verificación de la cadena de confianza ------------------------------------
paso "Verificación contra root/ca.crt"

comprobar() {
  local titulo="$1"; shift
  local salida
  printf '  %-24s ' "$titulo"
  if salida=$(openssl verify -CAfile root/ca.crt -untrusted intermedia/int.crt "$@" 2>&1); then
    echo "ACEPTADO"
  else
    echo "RECHAZADO: $(grep -m1 'error' <<< "$salida" | sed 's/.*lookup: //')"
  fi
}

comprobar "servidor (esperado OK)" -verify_hostname "$DOMINIO" servidor/server.crt
comprobar "autofirmado"           malos/autofirmado.crt
[[ -f malos/expirado.crt ]] && comprobar "expirado" malos/expirado.crt
comprobar "nombre incorrecto"     -verify_hostname "$DOMINIO" malos/nombre-incorrecto.crt
comprobar "otra CA"               malos/otra-ca.crt

echo
echo "Listo. Recuerda:"
echo "  - Respalda root/ca.key e intermedia/int.key fuera del repo."
echo "  - Copia servidor/server-chain.crt y servidor/server.key a /opt/proyecto/certs/ en el servidor."
echo "  - Ningún archivo .key de root/, intermedia/, servidor/ ni ca-falsa/ se sube al repo."
