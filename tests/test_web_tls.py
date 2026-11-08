from __future__ import annotations

import ssl

import pytest

from eurabyte_security.core.errores import ErrorAuditoriaWeb
from eurabyte_security.modules.web import tls as tls_modulo
from eurabyte_security.modules.web.tls import evaluar_tls, obtener_info_tls

from .ayudantes_web import RespuestaConfigurada, generar_certificado_autofirmado, servidor_prueba


def _confiar_en(monkeypatch: pytest.MonkeyPatch, ruta_cert) -> None:
    """Hace que ``ssl.create_default_context()`` confie en ``ruta_cert`` como CA.

    Simula lo que haria un cliente real con una CA interna distribuida: el
    cliente SI valida la cadena de confianza, solo que ahora incluye el
    certificado de prueba de la propia suite. Nunca se desactiva la validacion.
    """
    original = ssl.create_default_context

    def _contexto_con_ca(*args, **kwargs):
        kwargs.setdefault("cafile", str(ruta_cert))
        return original(*args, **kwargs)

    monkeypatch.setattr(tls_modulo.ssl, "create_default_context", _contexto_con_ca)


def test_certificado_confiable_cuando_el_cliente_confia_en_la_ca(tmp_path, monkeypatch):
    cert_pem, key_pem = generar_certificado_autofirmado("127.0.0.1")
    ruta_cert = tmp_path / "ca.pem"
    ruta_cert.write_bytes(cert_pem)
    _confiar_en(monkeypatch, ruta_cert)

    with servidor_prueba(
        {"/": RespuestaConfigurada(200, [], b"ok")}, https=True, cert_pem=cert_pem, key_pem=key_pem
    ) as (host, puerto):
        import ipaddress

        info = obtener_info_tls(ipaddress.IPv4Address(host), puerto, tiempo_limite=5.0)

    assert info.certificado is not None
    assert info.certificado.confiable is True
    assert info.certificado.coincide_con_host is True
    assert info.certificado.error_confianza is None
    assert info.version_protocolo is not None

    hallazgos = evaluar_tls(info, esquema="https")
    confianza = next(h for h in hallazgos if h.id_ == "tls-confianza")
    assert confianza.severidad == "info"
    assert confianza.estado == "Confiable"


def test_certificado_autofirmado_no_confiable_reporta_el_hecho_y_los_metadatos(monkeypatch):
    cert_pem, key_pem = generar_certificado_autofirmado("127.0.0.1")
    # Sin monkeypatch: el cliente usa el contexto por defecto del sistema, que no
    # confia en este certificado autofirmado de prueba.
    with servidor_prueba(
        {"/": RespuestaConfigurada(200, [], b"ok")}, https=True, cert_pem=cert_pem, key_pem=key_pem
    ) as (host, puerto):
        import ipaddress

        info = obtener_info_tls(ipaddress.IPv4Address(host), puerto, tiempo_limite=5.0)

    assert info.certificado is not None
    assert info.certificado.confiable is False
    assert info.certificado.error_confianza is not None
    # Los metadatos reales (sujeto/fechas) se leyeron igual, solo que sin verificar.
    assert info.certificado.sujeto is not None
    assert info.certificado.no_despues is not None

    hallazgos = evaluar_tls(info, esquema="https")
    confianza = next(h for h in hallazgos if h.id_ == "tls-confianza")
    assert confianza.severidad == "alta"
    assert confianza.estado == "No confiable"
    identidad = next(h for h in hallazgos if h.id_ == "tls-identidad")
    assert "sin verificar" in identidad.estado.lower()


def test_certificado_vencido_se_reporta_como_vencido_con_severidad_alta():
    cert_pem, key_pem = generar_certificado_autofirmado("127.0.0.1", vencido=True)
    with servidor_prueba(
        {"/": RespuestaConfigurada(200, [], b"ok")}, https=True, cert_pem=cert_pem, key_pem=key_pem
    ) as (host, puerto):
        import ipaddress

        info = obtener_info_tls(ipaddress.IPv4Address(host), puerto, tiempo_limite=5.0)

    assert info.certificado is not None
    assert info.certificado.confiable is False

    hallazgos = evaluar_tls(info, esquema="https")
    vencimiento = next(h for h in hallazgos if h.id_ == "tls-vencimiento")
    assert vencimiento.severidad == "alta"
    assert vencimiento.estado == "Vencido"


def test_tls_no_aplica_sobre_http():
    hallazgos = evaluar_tls(None, esquema="http")
    assert hallazgos[0].estado == "No aplica"


def test_obtener_info_tls_falla_con_error_propio_si_no_hay_servidor():
    import ipaddress

    with pytest.raises(ErrorAuditoriaWeb):
        obtener_info_tls(ipaddress.IPv4Address("127.0.0.1"), 1, tiempo_limite=1.0)
