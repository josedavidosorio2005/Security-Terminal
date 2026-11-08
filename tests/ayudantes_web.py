"""Ayudantes de prueba para la auditoria web: servidor HTTP(S) local y certificados.

Nunca se usan objetivos remotos: todo el trafico de las pruebas va contra
``127.0.0.1`` con un servidor y un certificado generados por la propia suite.
"""

from __future__ import annotations

import datetime
import http.server
import ipaddress
import ssl
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generar_certificado_autofirmado(
    ip: str = "127.0.0.1", *, vencido: bool = False, dias_validez: int = 365
) -> tuple[bytes, bytes]:
    """Genera un certificado autofirmado (PEM) para ``ip``, valido o ya vencido."""
    clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nombre = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ip)])
    ahora = datetime.datetime.now(datetime.UTC)
    if vencido:
        no_antes = ahora - datetime.timedelta(days=30)
        no_despues = ahora - datetime.timedelta(days=1)
    else:
        no_antes = ahora - datetime.timedelta(days=1)
        no_despues = ahora + datetime.timedelta(days=dias_validez)

    constructor = (
        x509.CertificateBuilder()
        .subject_name(nombre)
        .issuer_name(nombre)
        .public_key(clave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(no_antes)
        .not_valid_after(no_despues)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip))]),
            critical=False,
        )
    )
    certificado = constructor.sign(clave, hashes.SHA256())
    cert_pem = certificado.public_bytes(serialization.Encoding.PEM)
    key_pem = clave.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


@dataclass
class RespuestaConfigurada:
    codigo_estado: int = 200
    cabeceras: list[tuple[str, str]] = field(default_factory=list)
    cuerpo: bytes = b"ok"
    # Segundos a esperar antes de responder (solo para pruebas de limites de tiempo).
    demora: float = 0.0


class _Manejador(http.server.BaseHTTPRequestHandler):
    respuestas: dict[str, RespuestaConfigurada] = {}
    protocol_version = "HTTP/1.1"

    def _responder(self) -> None:
        config = self.respuestas.get(self.path) or RespuestaConfigurada()
        if config.demora:
            time.sleep(config.demora)
        self.send_response(config.codigo_estado)
        for nombre, valor in config.cabeceras:
            self.send_header(nombre, valor)
        self.send_header("Content-Length", str(len(config.cuerpo)))
        self.end_headers()
        self.wfile.write(config.cuerpo)

    def do_GET(self) -> None:  # noqa: N802 - nombre fijado por BaseHTTPRequestHandler
        self._responder()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - silencio en las pruebas
        pass


@contextmanager
def servidor_prueba(
    respuestas: dict[str, RespuestaConfigurada],
    *,
    https: bool = False,
    cert_pem: bytes | None = None,
    key_pem: bytes | None = None,
) -> Generator[tuple[str, int]]:
    """Levanta un servidor HTTP(S) local en un hilo y devuelve ``(host, puerto)``.

    El servidor vive solo mientras dura el bloque ``with``: se usa para que cada
    prueba controle exactamente que cabeceras/cuerpo/estado devolver sin depender
    de ningun servicio externo.
    """
    clase_manejador = type("ManejadorDePrueba", (_Manejador,), {"respuestas": respuestas})
    servidor = http.server.HTTPServer(("127.0.0.1", 0), clase_manejador)

    archivos_temporales: list[str] = []
    if https:
        import tempfile

        contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f_cert:
            f_cert.write(cert_pem or b"")
            ruta_cert = f_cert.name
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f_key:
            f_key.write(key_pem or b"")
            ruta_key = f_key.name
        archivos_temporales.extend([ruta_cert, ruta_key])
        contexto.load_cert_chain(certfile=ruta_cert, keyfile=ruta_key)
        servidor.socket = contexto.wrap_socket(servidor.socket, server_side=True)

    hilo = threading.Thread(target=servidor.serve_forever, daemon=True)
    hilo.start()
    try:
        yield "127.0.0.1", servidor.server_address[1]
    finally:
        servidor.shutdown()
        servidor.server_close()
        hilo.join(timeout=5)
        import os

        for ruta in archivos_temporales:
            try:
                os.unlink(ruta)
            except OSError:
                pass
