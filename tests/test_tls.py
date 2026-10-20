import datetime
import os
import pathlib
import ssl
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from comun import registro
from tls.cliente import ErrorCertificado, enviar
from tls.servidor import Servidor

RAIZ = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PKI = os.path.join(RAIZ, "pki")
CA_PROYECTO = os.path.join(PKI, "root", "ca.crt")
INTERMEDIA = os.path.join(PKI, "intermedia", "int.crt")
HOSTNAME = "222835-cliente-servidor.duckdns.org"
LOOPBACK = "127.0.0.1"


# --- PKI de prueba -----------------------------------------------------------------
# La llave privada del servidor real (pki/servidor/server.key) no se sube al repo, así
# que el caso exitoso se prueba con una PKI desechable de la misma forma (raíz →
# intermedia → servidor). Los casos de rechazo sí usan los certificados de la Parte 2.

def _nombre(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _emitir(cn, llave, emisor_nombre, emisor_llave, ca, san=None):
    ahora = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder()
         .subject_name(_nombre(cn)).issuer_name(emisor_nombre)
         .public_key(llave.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(ahora - datetime.timedelta(minutes=5))
         .not_valid_after(ahora + datetime.timedelta(days=1))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(llave.public_key()),
                        critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
             emisor_llave.public_key()), critical=False))
    if ca:
        b = b.add_extension(x509.KeyUsage(
            False, False, False, False, False, True, True, False, False), critical=True)
    else:
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                            critical=False)
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]),
                            critical=False)
    return b.sign(emisor_llave, hashes.SHA256())


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture(scope="module")
def pki_prueba(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki_prueba")
    raiz_k, int_k, srv_k = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    raiz = _emitir("Raiz de prueba", raiz_k, _nombre("Raiz de prueba"), raiz_k, ca=True)
    inter = _emitir("Intermedia de prueba", int_k, raiz.subject, raiz_k, ca=True)
    hoja = _emitir("servidor.prueba", srv_k, inter.subject, int_k, ca=False,
                   san="servidor.prueba")

    rutas = SimpleNamespace(hostname="servidor.prueba")
    rutas.ca = d / "ca.crt"
    rutas.cadena = d / "server-chain.crt"
    rutas.solo_hoja = d / "server.crt"
    rutas.llave = d / "server.key"
    rutas.ca.write_bytes(_pem(raiz))
    rutas.cadena.write_bytes(_pem(hoja) + _pem(inter))
    rutas.solo_hoja.write_bytes(_pem(hoja))
    rutas.llave.write_bytes(srv_k.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return rutas


@contextmanager
def servidor(modo, cert=None, llave=None):
    s = Servidor(host=LOOPBACK, puerto=0, modo=modo, cert=str(cert) if cert else None,
                 llave=str(llave) if llave else None)
    s.iniciar()
    try:
        yield s
    finally:
        s.detener()


# --- Modo sin protección ---------------------------------------------------------------

def test_modo_sin_proteccion_devuelve_el_eco():
    with servidor("plano") as s:
        r = enviar(LOOPBACK, s.puerto, "hola servidor", modo="plano")
    assert r.respuesta == "ECO: hola servidor"
    assert r.protocolo is None


# --- Modo TLS: conexión exitosa -----------------------------------------------------------

def test_tls_exitoso_valida_cadena_y_hostname_aunque_se_conecte_por_ip(pki_prueba):
    with servidor("tls", pki_prueba.cadena, pki_prueba.llave) as s:
        r = enviar(LOOPBACK, s.puerto, "mensaje cifrado", modo="tls",
                   hostname=pki_prueba.hostname, ca=str(pki_prueba.ca))
    assert r.respuesta == "ECO: mensaje cifrado"
    assert r.protocolo in ("TLSv1.2", "TLSv1.3")
    assert r.cifrado


@pytest.mark.skipif(not os.path.exists(os.path.join(PKI, "servidor", "server.key")),
                    reason="pki/servidor/server.key no está en este equipo")
def test_tls_exitoso_con_el_certificado_real_de_la_pki():
    with servidor("tls", os.path.join(PKI, "servidor", "server-chain.crt"),
                  os.path.join(PKI, "servidor", "server.key")) as s:
        r = enviar(LOOPBACK, s.puerto, "hola", modo="tls", hostname=HOSTNAME,
                   ca=CA_PROYECTO)
    assert r.respuesta == "ECO: hola"


# --- Modo TLS: el cliente rechaza lo que no es confiable ------------------------------------

def _con_intermedia(tmp_path, nombre):
    cadena = tmp_path / f"{nombre}-chain.crt"
    cadena.write_bytes(pathlib.Path(PKI, "malos", f"{nombre}.crt").read_bytes()
                       + pathlib.Path(INTERMEDIA).read_bytes())
    return cadena


# (certificado malo, ¿se envía la intermedia?, código de verificación de OpenSSL)
MALOS = [
    pytest.param("autofirmado", False, 18, id="autofirmado"),
    pytest.param("expirado", True, 10, id="expirado"),
    pytest.param("nombre-incorrecto", True, 62, id="nombre-incorrecto"),
    pytest.param("otra-ca", False, 20, id="firmado-por-otra-CA"),
]


@pytest.mark.parametrize("malo, con_intermedia, codigo", MALOS)
def test_cliente_rechaza_los_certificados_invalidos_de_la_parte_2(
        tmp_path, malo, con_intermedia, codigo):
    cadena = (_con_intermedia(tmp_path, malo) if con_intermedia
              else os.path.join(PKI, "malos", f"{malo}.crt"))
    with servidor("tls", cadena, os.path.join(PKI, "malos", f"{malo}.key")) as s:
        with pytest.raises(ErrorCertificado) as exc:
            enviar(LOOPBACK, s.puerto, "no debe llegar", modo="tls",
                   hostname=HOSTNAME, ca=CA_PROYECTO)
    assert exc.value.codigo == codigo


def test_cliente_rechaza_un_servidor_valido_si_su_ca_no_es_de_confianza(pki_prueba):
    with servidor("tls", pki_prueba.cadena, pki_prueba.llave) as s:
        with pytest.raises(ErrorCertificado) as exc:
            enviar(LOOPBACK, s.puerto, "x", modo="tls",
                   hostname=pki_prueba.hostname, ca=CA_PROYECTO)
    assert exc.value.codigo == 20


def test_cliente_rechaza_un_servidor_que_no_envia_la_intermedia(pki_prueba):
    with servidor("tls", pki_prueba.solo_hoja, pki_prueba.llave) as s:
        with pytest.raises(ErrorCertificado) as exc:
            enviar(LOOPBACK, s.puerto, "x", modo="tls",
                   hostname=pki_prueba.hostname, ca=str(pki_prueba.ca))
    assert exc.value.codigo == 20


def test_cliente_rechaza_si_el_hostname_esperado_no_coincide(pki_prueba):
    with servidor("tls", pki_prueba.cadena, pki_prueba.llave) as s:
        with pytest.raises(ErrorCertificado) as exc:
            enviar(LOOPBACK, s.puerto, "x", modo="tls",
                   hostname="otro-servidor.com", ca=str(pki_prueba.ca))
    assert exc.value.codigo == 62


def test_el_rechazo_de_un_certificado_queda_en_el_registro():
    cadena = os.path.join(PKI, "malos", "autofirmado.crt")
    with servidor("tls", cadena, os.path.join(PKI, "malos", "autofirmado.key")) as s:
        with pytest.raises(ErrorCertificado):
            enviar(LOOPBACK, s.puerto, "x", modo="tls", hostname=HOSTNAME,
                   ca=CA_PROYECTO)
    rechazos = registro.eventos("certificado_rechazado", "tls")
    assert len(rechazos) == 1
    assert rechazos[0]["nivel"] == "WARNING"
    assert rechazos[0]["motivo"]


# --- Mezclar modos --------------------------------------------------------------------------

def test_cliente_tls_contra_servidor_sin_proteccion_falla():
    with servidor("plano") as s:
        with pytest.raises(ssl.SSLError):
            enviar(LOOPBACK, s.puerto, "x", modo="tls", hostname=HOSTNAME,
                   ca=CA_PROYECTO)


def test_cliente_sin_proteccion_contra_servidor_tls_no_recibe_eco(pki_prueba):
    with servidor("tls", pki_prueba.cadena, pki_prueba.llave) as s:
        try:
            r = enviar(LOOPBACK, s.puerto, "texto en claro", modo="plano")
        except OSError:
            return
    assert "texto en claro" not in r.respuesta
