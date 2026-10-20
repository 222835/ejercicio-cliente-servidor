from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

from comun.registro import registrar

ITERACIONES_PBKDF2 = 600_000
LONGITUD_SAL = 16
MAX_INTENTOS = 3

PERMISOS_POR_ROL: dict[str, frozenset[str]] = {
    "admin":    frozenset({"archivos", "wiki", "base_datos", "panel_admin"}),
    "empleado": frozenset({"archivos", "wiki"}),
    "invitado": frozenset({"wiki"}),
}


class ErrorAutenticacion(Exception):
    pass


class ErrorAutorizacion(Exception):
    pass


@dataclass
class Usuario:
    nombre: str
    rol: str
    sal: bytes
    hash_contrasena: bytes
    iteraciones: int
    intentos_fallidos: int = 0
    bloqueado: bool = False

    def __repr__(self) -> str:
        return f"Usuario(nombre={self.nombre!r}, rol={self.rol!r}, bloqueado={self.bloqueado})"


def hashear_contrasena(contrasena: str, sal: bytes | None = None,
                       iteraciones: int = ITERACIONES_PBKDF2) -> tuple[bytes, bytes]:
    sal = sal if sal is not None else os.urandom(LONGITUD_SAL)
    derivada = hashlib.pbkdf2_hmac("sha256", contrasena.encode("utf-8"), sal, iteraciones)
    return sal, derivada


class AlmacenUsuarios:
    def __init__(self, iteraciones: int = ITERACIONES_PBKDF2):
        self.iteraciones = iteraciones
        self._usuarios: dict[str, Usuario] = {}

    def agregar(self, nombre: str, contrasena: str, rol: str) -> Usuario:
        if rol not in PERMISOS_POR_ROL:
            raise ValueError(f"Rol desconocido: {rol}")
        if nombre in self._usuarios:
            raise ValueError(f"El usuario {nombre} ya existe")
        sal, h = hashear_contrasena(contrasena, iteraciones=self.iteraciones)
        usuario = Usuario(nombre, rol, sal, h, self.iteraciones)
        self._usuarios[nombre] = usuario
        return usuario

    def obtener(self, nombre: str) -> Usuario | None:
        return self._usuarios.get(nombre)

    def desbloquear(self, nombre: str) -> None:
        u = self._usuarios[nombre]
        u.bloqueado, u.intentos_fallidos = False, 0

    def nombres(self) -> list[str]:
        return sorted(self._usuarios)


def autenticar(almacen: AlmacenUsuarios, nombre: str, contrasena: str,
               **contexto) -> Usuario:
    usuario = almacen.obtener(nombre)

    if usuario is None:
        hashear_contrasena(contrasena, b"\x00" * LONGITUD_SAL, almacen.iteraciones)
        registrar("autenticacion_fallida", "auth", usuario=nombre,
                  motivo="usuario_inexistente", **contexto)
        raise ErrorAutenticacion("Usuario o contraseña incorrectos")

    if usuario.bloqueado:
        registrar("autenticacion_fallida", "auth", usuario=nombre,
                  motivo="cuenta_bloqueada", **contexto)
        raise ErrorAutenticacion("Cuenta bloqueada")

    _, calculado = hashear_contrasena(contrasena, usuario.sal, usuario.iteraciones)
    if hmac.compare_digest(calculado, usuario.hash_contrasena):
        usuario.intentos_fallidos = 0
        registrar("autenticacion_exitosa", "auth", usuario=nombre, rol=usuario.rol, **contexto)
        return usuario

    usuario.intentos_fallidos += 1
    registrar("autenticacion_fallida", "auth", usuario=nombre,
              motivo="contrasena_incorrecta",
              intentos=usuario.intentos_fallidos, **contexto)
    if usuario.intentos_fallidos >= MAX_INTENTOS:
        usuario.bloqueado = True
        registrar("cuenta_bloqueada", "auth", usuario=nombre, **contexto)
    raise ErrorAutenticacion("Usuario o contraseña incorrectos")


def autorizar(usuario: Usuario, recurso: str, **contexto) -> bool:
    permitido = recurso in PERMISOS_POR_ROL.get(usuario.rol, frozenset())
    registrar("acceso_permitido" if permitido else "acceso_denegado", "authz",
              usuario=usuario.nombre, rol=usuario.rol, recurso=recurso, **contexto)
    return permitido


def exigir_autorizacion(usuario: Usuario, recurso: str, **contexto) -> None:
    if not autorizar(usuario, recurso, **contexto):
        raise ErrorAutorizacion(f"El rol '{usuario.rol}' no tiene acceso a '{recurso}'")
