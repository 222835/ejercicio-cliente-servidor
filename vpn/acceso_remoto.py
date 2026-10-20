from __future__ import annotations

import ipaddress
import secrets
import time
from dataclasses import dataclass, field
from typing import Callable

from comun.registro import registrar
from vpn.auth import (AlmacenUsuarios, ErrorAutenticacion, ErrorAutorizacion,
                      Usuario, autenticar, autorizar, exigir_autorizacion,
                      PERMISOS_POR_ROL)

RECURSOS_INTERNOS: dict[str, dict[str, str]] = {
    "archivos":    {"ip": "10.0.0.10", "descripcion": "Servidor de archivos compartidos"},
    "wiki":        {"ip": "10.0.0.20", "descripcion": "Wiki interna"},
    "base_datos":  {"ip": "10.0.0.30", "descripcion": "Base de datos de clientes"},
    "panel_admin": {"ip": "10.0.0.40", "descripcion": "Panel de administración"},
}


class ErrorSesion(Exception):
    pass


class ErrorVPN(Exception):
    pass


@dataclass
class SesionVPN:
    id: str
    usuario: Usuario
    ip_virtual: str
    ip_origen: str
    inicio: float
    expira: float
    accesos: list[str] = field(default_factory=list)


class ServidorVPNAccesoRemoto:
    def __init__(self, almacen: AlmacenUsuarios, red_pool: str = "10.8.0.0/24",
                 duracion_sesion: int = 3600, reloj: Callable[[], float] = time.time):
        self.almacen = almacen
        self.red_pool = ipaddress.ip_network(red_pool)
        hosts = list(self.red_pool.hosts())
        self.ip_servidor = str(hosts[0])
        self._ips_libres = [str(ip) for ip in hosts[1:]]
        self.duracion = duracion_sesion
        self.reloj = reloj
        self.sesiones: dict[str, SesionVPN] = {}

    def conectar(self, nombre: str, contrasena: str, ip_origen: str = "203.0.113.50") -> SesionVPN:
        registrar("intento_conexion_vpn", "vpn_remota", usuario=nombre, ip_origen=ip_origen)
        try:
            usuario = autenticar(self.almacen, nombre, contrasena, ip_origen=ip_origen)
        except ErrorAutenticacion:
            registrar("conexion_vpn_rechazada", "vpn_remota", usuario=nombre, ip_origen=ip_origen)
            raise

        if not self._ips_libres:
            raise ErrorVPN("No hay IPs virtuales disponibles")
        ip_virtual = self._ips_libres.pop(0)
        ahora = self.reloj()
        sesion = SesionVPN(secrets.token_hex(16), usuario, ip_virtual, ip_origen,
                           ahora, ahora + self.duracion)
        self.sesiones[sesion.id] = sesion
        registrar("conexion_vpn_establecida", "vpn_remota", usuario=nombre, rol=usuario.rol,
                  ip_origen=ip_origen, ip_virtual=ip_virtual)
        return sesion

    def desconectar(self, id_sesion: str) -> None:
        sesion = self.sesiones.pop(id_sesion, None)
        if sesion:
            self._ips_libres.append(sesion.ip_virtual)
            self._ips_libres.sort(key=ipaddress.ip_address)
            registrar("desconexion_vpn", "vpn_remota", usuario=sesion.usuario.nombre,
                      ip_virtual=sesion.ip_virtual)

    def _validar_sesion(self, id_sesion: str) -> SesionVPN:
        sesion = self.sesiones.get(id_sesion)
        if sesion is None:
            registrar("sesion_invalida", "vpn_remota", motivo="no_existe")
            raise ErrorSesion("Sesión inexistente o cerrada")
        if self.reloj() > sesion.expira:
            self.desconectar(id_sesion)
            registrar("sesion_invalida", "vpn_remota", usuario=sesion.usuario.nombre,
                      motivo="vencida")
            raise ErrorSesion("La sesión venció; vuelve a autenticarte")
        return sesion

    def acceder(self, id_sesion: str, recurso: str) -> str:
        sesion = self._validar_sesion(id_sesion)
        if recurso not in RECURSOS_INTERNOS:
            registrar("acceso_denegado", "vpn_remota", usuario=sesion.usuario.nombre,
                      recurso=recurso, motivo="recurso_inexistente")
            raise ErrorAutorizacion(f"Recurso desconocido: {recurso}")

        destino = RECURSOS_INTERNOS[recurso]["ip"]
        exigir_autorizacion(sesion.usuario, recurso, ip_virtual=sesion.ip_virtual,
                            ip_destino=destino)
        sesion.accesos.append(recurso)
        return (f"[{sesion.ip_virtual} -> {destino}] "
                f"{RECURSOS_INTERNOS[recurso]['descripcion']}: contenido entregado")

    def recursos_disponibles(self, id_sesion: str) -> list[str]:
        sesion = self._validar_sesion(id_sesion)
        return sorted(PERMISOS_POR_ROL[sesion.usuario.rol])

    def operacion_admin(self, id_sesion: str, operacion: str, **params):
        sesion = self._validar_sesion(id_sesion)
        u = sesion.usuario
        if not autorizar(u, "panel_admin", operacion=operacion):
            registrar("operacion_admin_rechazada", "admin", usuario=u.nombre, operacion=operacion)
            raise ErrorAutorizacion(f"'{u.nombre}' no puede ejecutar '{operacion}'")

        if operacion == "crear_usuario":
            self.almacen.agregar(params["nombre"], params["contrasena"], params["rol"])
            resultado = f"Usuario {params['nombre']} creado con rol {params['rol']}"
        elif operacion == "listar_sesiones":
            resultado = [(s.usuario.nombre, s.ip_virtual) for s in self.sesiones.values()]
        elif operacion == "desbloquear_usuario":
            self.almacen.desbloquear(params["nombre"])
            resultado = f"Usuario {params['nombre']} desbloqueado"
        elif operacion == "expulsar_usuario":
            ids = [s.id for s in self.sesiones.values() if s.usuario.nombre == params["nombre"]]
            for i in ids:
                self.desconectar(i)
            resultado = f"{len(ids)} sesión(es) cerrada(s)"
        else:
            raise ValueError(f"Operación desconocida: {operacion}")

        detalle = {k: v for k, v in params.items() if k != "contrasena"}
        registrar("operacion_administrativa", "admin", usuario=u.nombre,
                  operacion=operacion, **detalle)
        return resultado
