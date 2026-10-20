#!/usr/bin/env python3
"""
Convierte los eventos de SSH y de sudo de /var/log/auth.log al formato de
registro común del proyecto (comun/registro.py).

Eventos que genera (componente "ssh"):
  autenticacion_exitosa     Accepted publickey ...
  autenticacion_fallida     usuario inexistente, usuario no permitido (AllowGroups),
                            llave rechazada, demasiados intentos o autenticación
                            no completada (por ejemplo, intento con contraseña)
  sesion_cerrada            el usuario cerró su sesión SSH
  operacion_administrativa  comando ejecutado con sudo
  acceso_denegado           intento de usar sudo sin privilegios
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import time
from datetime import datetime, timezone

# Permite importar comun/ aunque el script viva en ssh/
RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RAIZ)

from comun.registro import RUTA_DEFECTO, registrar  # noqa: E402

ARCHIVO_DEFECTO = "/var/log/auth.log"
ARCHIVO_ESTADO = os.path.join(os.path.dirname(RUTA_DEFECTO) or ".", ".auth_log_ultimo")

# --- Formato de las líneas de auth.log -----------------------------------------
# Ubuntu reciente:  2026-10-19T18:28:27.225790-05:00 host sshd-session[4439]: mensaje
# Formato clásico:  Oct 19 18:28:27 host sshd[4439]: mensaje
LINEA_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+)\s+\S+\s+(?P<prog>[\w.\-]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
LINEA_CLASICA = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+(?P<prog>[\w.\-]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)

# --- Mensajes de sshd -----------------------------------------------------------------
SSH_ACEPTADO = re.compile(
    r"Accepted (?P<metodo>\S+) for (?P<usuario>\S+) from (?P<ip>\S+) port (?P<puerto>\d+)"
    r"(?: ssh2)?(?:: (?P<tipo>\S+) (?P<huella>SHA256:\S+))?"
)
SSH_NO_PERMITIDO = re.compile(
    r"User (?P<usuario>\S+) from (?P<ip>\S+) not allowed because (?P<detalle>.+)"
)
SSH_INEXISTENTE = re.compile(
    r"Invalid user (?P<usuario>\S*) from (?P<ip>\S+)(?: port (?P<puerto>\d+))?"
)
SSH_LLAVE_RECHAZADA = re.compile(
    r"Failed (?P<metodo>\S+) for (?:invalid user )?(?P<usuario>\S+) from (?P<ip>\S+) port (?P<puerto>\d+)"
)
SSH_DEMASIADOS = re.compile(
    r"maximum authentication attempts exceeded for (?:invalid user )?(?P<usuario>\S+) "
    r"from (?P<ip>\S+) port (?P<puerto>\d+)"
)
SSH_NO_COMPLETADA = re.compile(
    r"Connection (?:closed|reset) by authenticating user (?P<usuario>\S+) (?P<ip>\S+) "
    r"port (?P<puerto>\d+) \[preauth\]"
)
SSH_DESCONECTADO = re.compile(
    r"Disconnected from user (?P<usuario>\S+) (?P<ip>\S+) port (?P<puerto>\d+)"
)

# --- Mensajes de sudo ------------------------------------------------------------------
SUDO_DENEGADO = re.compile(
    r"^\s*(?P<usuario>\S+) : (?P<razon>user NOT in sudoers|command not allowed|"
    r"\d+ incorrect password attempts?) ; .*?COMMAND=(?P<comando>.+)$"
)
SUDO_EJECUTADO = re.compile(
    r"^\s*(?P<usuario>\S+) : (?:TTY=\S+ ; )?PWD=.*? ; USER=(?P<como>\S+) ; COMMAND=(?P<comando>.+)$"
)

MOTIVOS_SUDO = {
    "user NOT in sudoers": "sin_privilegios_admin",
    "command not allowed": "comando_no_permitido",
}


def a_utc(ts: str) -> str:
    """Convierte la fecha de auth.log a ISO en UTC, como el registro común."""
    if "T" in ts:
        fecha = datetime.fromisoformat(ts)
    else:
        partes = " ".join(ts.split())  # "Oct  5" -> "Oct 5"
        fecha = datetime.strptime(f"{datetime.now().year} {partes}", "%Y %b %d %H:%M:%S")
        fecha = fecha.astimezone()  # se asume la zona horaria local
    return fecha.astimezone(timezone.utc).isoformat(timespec="microseconds")


class Procesador:
    def __init__(self, ultimo: str | None):
        self.ultimo = ultimo
        # Conexiones que ya registraron un fallo, para no contar dos veces el
        # mismo intento ("Failed publickey" seguido de "Connection closed ...")
        self.fallos_registrados: set[tuple[str, str]] = set()
        self.total = 0

    def emitir(self, evento: str, ts: str, **datos) -> None:
        datos = {k: v for k, v in datos.items() if v not in (None, "")}
        # Se conserva la hora real del evento (auth.log), no la hora de procesamiento
        registro = registrar(evento, componente="ssh", timestamp=ts[:19] + "+00:00",
                             origen="auth.log", **datos)
        self.total += 1
        detalle = datos.get("motivo") or datos.get("comando") or datos.get("metodo") or ""
        print(f"[{registro['nivel']:<7}] {evento:<25} {datos.get('usuario', '-'):<12} "
              f"{datos.get('ip_origen', ''):<16} {detalle}")

    def fallo(self, ts: str, m: re.Match, motivo: str, **extra) -> None:
        clave = (m.group("ip"), m.groupdict().get("puerto") or "")
        if clave[1] and clave in self.fallos_registrados:
            return
        if clave[1]:
            self.fallos_registrados.add(clave)
        self.emitir("autenticacion_fallida", ts, usuario=m.group("usuario") or "(vacío)",
                    ip_origen=m.group("ip"), puerto=m.groupdict().get("puerto"),
                    motivo=motivo, **extra)

    def linea(self, texto: str) -> None:
        m = LINEA_ISO.match(texto) or LINEA_CLASICA.match(texto)
        if not m:
            return
        prog, msg = m.group("prog"), m.group("msg")
        if not (prog.startswith("sshd") or prog == "sudo"):
            return

        ts = a_utc(m.group("ts"))
        if self.ultimo and ts <= self.ultimo:
            return

        if prog.startswith("sshd"):
            self.linea_ssh(ts, msg)
        else:
            self.linea_sudo(ts, msg)

        self.ultimo = ts
        guardar_estado(ts)

    def linea_ssh(self, ts: str, msg: str) -> None:
        if m := SSH_ACEPTADO.search(msg):
            self.emitir("autenticacion_exitosa", ts, usuario=m.group("usuario"),
                        ip_origen=m.group("ip"), puerto=m.group("puerto"),
                        metodo=m.group("metodo"), tipo_llave=m.group("tipo"),
                        huella=m.group("huella"))
        elif m := SSH_NO_PERMITIDO.search(msg):
            self.fallo(ts, m, "usuario_no_permitido", detalle=m.group("detalle"))
        elif m := SSH_INEXISTENTE.search(msg):
            self.fallo(ts, m, "usuario_inexistente")
        elif m := SSH_LLAVE_RECHAZADA.search(msg):
            self.fallo(ts, m, "credencial_rechazada", metodo=m.group("metodo"))
        elif m := SSH_DEMASIADOS.search(msg):
            self.fallo(ts, m, "demasiados_intentos")
        elif m := SSH_NO_COMPLETADA.search(msg):
            self.fallo(ts, m, "autenticacion_no_completada")
        elif m := SSH_DESCONECTADO.search(msg):
            self.emitir("sesion_cerrada", ts, usuario=m.group("usuario"),
                        ip_origen=m.group("ip"), puerto=m.group("puerto"))

    def linea_sudo(self, ts: str, msg: str) -> None:
        if m := SUDO_DENEGADO.search(msg):
            razon = m.group("razon")
            motivo = MOTIVOS_SUDO.get(razon, "autenticacion_sudo_fallida")
            self.emitir("acceso_denegado", ts, usuario=m.group("usuario"),
                        motivo=motivo, comando=m.group("comando").strip())
        elif m := SUDO_EJECUTADO.search(msg):
            self.emitir("operacion_administrativa", ts, usuario=m.group("usuario"),
                        ejecutado_como=m.group("como"), comando=m.group("comando").strip())


def leer_estado() -> str | None:
    try:
        with open(ARCHIVO_ESTADO, encoding="utf-8") as f:
            return f.read().strip() or None
    except FileNotFoundError:
        return None


def guardar_estado(ts: str) -> None:
    os.makedirs(os.path.dirname(ARCHIVO_ESTADO) or ".", exist_ok=True)
    with open(ARCHIVO_ESTADO, "w", encoding="utf-8") as f:
        f.write(ts)


def abrir(ruta: str):
    try:
        return open(ruta, encoding="utf-8", errors="replace")
    except PermissionError:
        sys.exit(f"Sin permiso para leer {ruta}.\n"
                 f"Agrega tu usuario al grupo adm: sudo usermod -aG adm $USER\n"
                 f"y vuelve a abrir la terminal.")
    except FileNotFoundError:
        sys.exit(f"No existe {ruta}. ¿Está instalado y activo rsyslog?\n"
                 f"  sudo apt install rsyslog -y && sudo systemctl enable --now rsyslog")


def main() -> None:
    p = argparse.ArgumentParser(description="Pasa los eventos de SSH y sudo al registro común.")
    p.add_argument("--archivo", default=ARCHIVO_DEFECTO, help=f"por defecto {ARCHIVO_DEFECTO}")
    p.add_argument("--seguir", action="store_true", help="seguir esperando eventos nuevos")
    p.add_argument("--desde-inicio", action="store_true", help="ignorar lo ya procesado")
    args = p.parse_args()

    proc = Procesador(None if args.desde_inicio else leer_estado())
    f = abrir(args.archivo)
    for texto in f:
        proc.linea(texto.rstrip("\n"))

    if not args.seguir:
        print(f"\n{proc.total} eventos nuevos registrados en {RUTA_DEFECTO}")
        return

    print(f"\nEscuchando eventos nuevos en {args.archivo} (Ctrl+C para salir)...")
    try:
        while True:
            texto = f.readline()
            if texto:
                proc.linea(texto.rstrip("\n"))
                continue
            # Si el archivo se rotó o se truncó, se vuelve a abrir
            if os.path.getsize(args.archivo) < f.tell():
                f.close()
                f = abrir(args.archivo)
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{proc.total} eventos registrados en {RUTA_DEFECTO}")


if __name__ == "__main__":
    main()
