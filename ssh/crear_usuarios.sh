#!/usr/bin/env bash
# 
# Da de alta cuentas para el acceso SSH al servidor del proyecto.
#
# Uso:
#   sudo ./crear_usuarios.sh <usuario> <llave.pub>            Integrante normal
#   sudo ./crear_usuarios.sh <usuario> <llave.pub> admin      Integrante con sudo
#   sudo ./crear_usuarios.sh <usuario> --sin-acceso           Cuenta sin acceso SSH
#

set -euo pipefail

GRUPO_SSH="sshusers"

uso() { sed -n '5,17p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

[[ $EUID -eq 0 ]] || { echo "Ejecútalo con sudo."; exit 1; }
[[ $# -ge 2 ]] || uso

USUARIO="$1"
LLAVE="$2"
ROL="${3:-normal}"

# --- Grupo autorizado ---------------------------------------------------------
if ! getent group "$GRUPO_SSH" > /dev/null; then
  groupadd "$GRUPO_SSH"
  echo "Grupo $GRUPO_SSH creado."
fi

# --- Validar rol y llave antes de tocar nada --------------------------------
if [[ "$LLAVE" != "--sin-acceso" ]]; then
  case "$ROL" in
    normal|admin) ;;
    *) echo "Rol desconocido: $ROL (usa normal o admin)"; exit 1 ;;
  esac

  # Llave pública
  [[ -f "$LLAVE" ]] || { echo "No encuentro la llave: $LLAVE"; exit 1; }

  # Quita los saltos de línea de Windows (\r) que dejan las llaves copiadas desde allá
  LINEA=$(tr -d '\r' < "$LLAVE" | grep -m1 -E '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-)' || true)
  if [[ -z "$LINEA" ]]; then
    echo "El archivo no parece una llave pública SSH (debe empezar con ssh-ed25519, ssh-rsa o ecdsa-sha2-)."
    echo "Asegúrate de usar el archivo .pub y no la llave privada."
    exit 1
  fi
fi

# --- Cuenta -------------------------------------------------------------------
if id "$USUARIO" &> /dev/null; then
  echo "El usuario $USUARIO ya existe; se actualiza su configuración."
else
  adduser --disabled-password --gecos "" "$USUARIO" > /dev/null
  echo "Usuario $USUARIO creado (sin contraseña: solo puede entrar con llave)."
fi

# --- Cuenta sin acceso SSH ----------------------------------------------------
if [[ "$LLAVE" == "--sin-acceso" ]]; then
  gpasswd -d "$USUARIO" "$GRUPO_SSH" &> /dev/null || true
  echo "$USUARIO queda SIN acceso SSH (no pertenece a $GRUPO_SSH)."
  exit 0
fi

# --- Instalar la llave ----------------------------------------------------------
HOME_USUARIO=$(getent passwd "$USUARIO" | cut -d: -f6)
SSH_DIR="$HOME_USUARIO/.ssh"
AUTH="$SSH_DIR/authorized_keys"

mkdir -p "$SSH_DIR"
touch "$AUTH"
if grep -qxF "$LINEA" "$AUTH"; then
  echo "La llave ya estaba autorizada."
else
  echo "$LINEA" >> "$AUTH"
  echo "Llave agregada."
fi

chown -R "$USUARIO:$USUARIO" "$SSH_DIR"
chmod 700 "$SSH_DIR"
chmod 600 "$AUTH"

# --- Permisos según el rol ------------------------------------------------------
usermod -aG "$GRUPO_SSH" "$USUARIO"
if [[ "$ROL" == "admin" ]]; then
  usermod -aG sudo "$USUARIO"
fi
# Nota: el rol normal no le quita sudo a nadie que ya lo tenga, para no dejar
# sin administración a una cuenta por error.

# --- Resumen ------------------------------------------------------------------
echo
echo "Resumen de $USUARIO"
echo "  Grupos: $(id -nG "$USUARIO")"
if command -v ssh-keygen > /dev/null; then
  echo "  Llave:  $(ssh-keygen -lf <(echo "$LINEA"))"
fi
echo
echo "Comparte esta huella con $USUARIO: debe coincidir con la que le muestra"
echo "  ssh-keygen -lf ~/.ssh/id_ed25519.pub   (en su computadora)"
