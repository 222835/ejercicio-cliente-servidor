import copy

import pytest

from comun import registro
from vpn.auth import ErrorAutenticacion
from vpn.sitio_a_sitio import ErrorRuta, Gateway, vista_desde_internet
from ipsec import IPSecSA
from vpn.tunel_ipsec import ErrorIPSec

PSK = b"clave-precompartida-de-prueba-32b"


@pytest.fixture
def gateways():
    matriz = Gateway("GW-Matriz", "10.1.0.0/24", "198.51.100.1", PSK)
    sucursal = Gateway("GW-Sucursal", "10.2.0.0/24", "203.0.113.1", PSK)
    matriz.establecer_tunel(sucursal)
    return matriz, sucursal


def test_trafico_entre_sitios(gateways):
    matriz, sucursal = gateways
    p = matriz.enviar("10.1.0.5", "10.2.0.7", "reporte de ventas")
    interno = sucursal.recibir(p)
    assert interno == {"src": "10.1.0.5", "dst": "10.2.0.7", "proto": "TCP",
                       "datos": "reporte de ventas"}


def test_trafico_en_ambos_sentidos(gateways):
    matriz, sucursal = gateways
    p = sucursal.enviar("10.2.0.7", "10.1.0.5", "respuesta")
    assert matriz.recibir(p)["datos"] == "respuesta"


def test_internet_solo_ve_ips_de_gateways(gateways):
    matriz, _ = gateways
    p = matriz.enviar("10.1.0.5", "10.2.0.7", "secreto")
    visto = vista_desde_internet(p)
    assert (visto["src"], visto["dst"]) == ("198.51.100.1", "203.0.113.1")
    texto = str(p)
    assert "10.1.0.5" not in texto and "10.2.0.7" not in texto and "secreto" not in texto


def test_psk_distinta_no_establece_tunel():
    a = Gateway("GW-A", "10.1.0.0/24", "198.51.100.1", PSK)
    intruso = Gateway("GW-Falso", "10.2.0.0/24", "192.0.2.66", b"otra-clave")
    with pytest.raises(ErrorAutenticacion):
        a.establecer_tunel(intruso)
    assert registro.eventos("tunel_rechazado")
    with pytest.raises(ErrorRuta):
        a.enviar("10.1.0.5", "10.2.0.7", "x")


def test_replay_rechazado(gateways):
    matriz, sucursal = gateways
    p = matriz.enviar("10.1.0.5", "10.2.0.7", "transferir $100")
    sucursal.recibir(p)
    with pytest.raises(ErrorIPSec, match="Replay"):
        sucursal.recibir(copy.deepcopy(p))
    assert registro.eventos("replay_detectado")


def test_paquete_alterado_rechazado(gateways):
    matriz, sucursal = gateways
    p = matriz.enviar("10.1.0.5", "10.2.0.7", "hola")
    carga = bytearray.fromhex(p["encrypted_packet"])
    carga[0] ^= 0xFF
    p["encrypted_packet"] = carga.hex()
    with pytest.raises(ErrorIPSec, match="alterado"):
        sucursal.recibir(p)


def test_paquete_alterado_no_consume_secuencia(gateways):
    matriz, sucursal = gateways
    p = matriz.enviar("10.1.0.5", "10.2.0.7", "hola")
    falso = copy.deepcopy(p)
    falso["encrypted_packet"] = "00" + falso["encrypted_packet"][2:]
    with pytest.raises(ErrorIPSec):
        sucursal.recibir(falso)
    assert sucursal.recibir(p)["datos"] == "hola"


def test_paquetes_fuera_de_orden_dentro_de_ventana(gateways):
    matriz, sucursal = gateways
    p1 = matriz.enviar("10.1.0.5", "10.2.0.7", "1")
    p2 = matriz.enviar("10.1.0.5", "10.2.0.7", "2")
    sucursal.recibir(p2)
    assert sucursal.recibir(p1)["datos"] == "1"


def test_destino_sin_tunel(gateways):
    matriz, _ = gateways
    with pytest.raises(ErrorRuta):
        matriz.enviar("10.1.0.5", "10.9.0.1", "x")
    with pytest.raises(ErrorRuta):
        matriz.enviar("10.7.0.5", "10.2.0.7", "origen falso")
    assert registro.eventos("ruta_rechazada")


def test_spi_desconocido(gateways):
    matriz, sucursal = gateways
    p = matriz.enviar("10.1.0.5", "10.2.0.7", "x")
    p["ipsec_header"]["spi"] = 0xDEADBEEF
    with pytest.raises(ErrorIPSec, match="SPI"):
        sucursal.recibir(p)


def test_usa_el_modo_tunel_de_la_parte3(gateways):
    matriz, _ = gateways
    tunel, _ = next(iter(matriz._salida.values()))
    assert isinstance(tunel.sa, IPSecSA)
    p = matriz.enviar("10.1.0.5", "10.2.0.7", "x")
    assert set(p) == {"new_ip_header", "ipsec_header", "encrypted_packet"}


def test_paquete_viejo_fuera_de_ventana(gateways):
    matriz, sucursal = gateways
    primero = matriz.enviar("10.1.0.5", "10.2.0.7", "viejo")
    for i in range(70):
        ultimo = matriz.enviar("10.1.0.5", "10.2.0.7", str(i))
    sucursal.recibir(ultimo)
    with pytest.raises(ErrorIPSec, match="Replay"):
        sucursal.recibir(primero)


def test_numero_de_secuencia_alterado(gateways):
    matriz, sucursal = gateways
    p = matriz.enviar("10.1.0.5", "10.2.0.7", "x")
    p["ipsec_header"]["seq"] = 999
    with pytest.raises(ErrorIPSec, match="alterado"):
        sucursal.recibir(p)


def test_paquete_falso_no_bloquea_al_legitimo(gateways):
    matriz, sucursal = gateways
    legitimo = matriz.enviar("10.1.0.5", "10.2.0.7", "pago autorizado")
    falso = copy.deepcopy(legitimo)
    falso["encrypted_packet"] = "00" * (len(falso["encrypted_packet"]) // 2)
    with pytest.raises(ErrorIPSec):
        sucursal.recibir(falso)
    assert sucursal.recibir(legitimo)["datos"] == "pago autorizado"
