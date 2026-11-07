"""Pruebas de extremo a extremo de ejecutar_auditoria_web: estado real de las
redirecciones, limite de saltos, limite de tiempo total, y certificados no confiables.

Usa siempre un servidor HTTP(S) local (ver ``ayudantes_web.py``), nunca un objetivo
remoto.
"""

from __future__ import annotations

import ipaddress

import pytest

from eurabyte_security.core.errores import ErrorAuditoriaWeb, ErrorFueraDeAlcance
from eurabyte_security.core.validation import validar_url_web
from eurabyte_security.modules.web import auditor as modulo_auditor
from eurabyte_security.modules.web.auditor import ejecutar_auditoria_web

from .ayudantes_web import RespuestaConfigurada, generar_certificado_autofirmado, servidor_prueba

_RED_127 = [ipaddress.IPv4Network("127.0.0.1/32")]


def _redireccion_hallazgo(resultado):
    return next(h for h in resultado.hallazgos if h.categoria == "redireccion")


def test_redireccion_autorizada_seguida_se_registra_como_seguida():
    respuestas_host = {
        "/": RespuestaConfigurada(302, [("Location", "/destino")], b""),
        "/destino": RespuestaConfigurada(200, [], b"ok"),
    }
    with servidor_prueba(respuestas_host) as (host, puerto):
        componentes = validar_url_web(f"http://{host}:{puerto}/")
        resultado = ejecutar_auditoria_web(
            componentes, redes_autorizadas=_RED_127, seguir_redirecciones=True
        )

    hallazgo = _redireccion_hallazgo(resultado)
    assert "seguida" in hallazgo.estado.lower()
    assert "no seguida" not in hallazgo.estado.lower()
    assert hallazgo.severidad == "info"
    assert resultado.saltos_seguidos
    assert resultado.codigo_estado == 200  # el estado final es el del destino, no el 302


def test_redireccion_autorizada_no_seguida_por_defecto():
    respuestas_host = {
        "/": RespuestaConfigurada(302, [("Location", "/destino")], b""),
        "/destino": RespuestaConfigurada(200, [], b"ok"),
    }
    with servidor_prueba(respuestas_host) as (host, puerto):
        componentes = validar_url_web(f"http://{host}:{puerto}/")
        resultado = ejecutar_auditoria_web(
            componentes, redes_autorizadas=_RED_127, seguir_redirecciones=False
        )

    hallazgo = _redireccion_hallazgo(resultado)
    assert "no seguida" in hallazgo.estado.lower()
    assert not resultado.saltos_seguidos
    assert resultado.codigo_estado == 302  # nunca se llego a pedir el destino


def test_redireccion_fuera_de_alcance_nunca_se_sigue_aunque_se_pida():
    respuestas_host = {
        "/": RespuestaConfigurada(302, [("Location", "http://192.168.77.77/otro")], b""),
    }
    with servidor_prueba(respuestas_host) as (host, puerto):
        componentes = validar_url_web(f"http://{host}:{puerto}/")
        resultado = ejecutar_auditoria_web(
            componentes, redes_autorizadas=_RED_127, seguir_redirecciones=True
        )

    hallazgo = _redireccion_hallazgo(resultado)
    assert hallazgo.severidad == "alta"
    assert "fuera de alcance" in hallazgo.estado.lower()
    assert not resultado.saltos_seguidos


def test_limite_maximo_de_saltos_se_respeta():
    # Cadena de redirecciones mas larga que MAXIMO_SALTOS, todas dentro de alcance.
    total_pasos = modulo_auditor.MAXIMO_SALTOS + 3
    respuestas_host = {
        f"/paso{i}": RespuestaConfigurada(302, [("Location", f"/paso{i + 1}")], b"")
        for i in range(total_pasos)
    }
    respuestas_host[f"/paso{total_pasos}"] = RespuestaConfigurada(200, [], b"fin")

    with servidor_prueba(respuestas_host) as (host, puerto):
        componentes = validar_url_web(f"http://{host}:{puerto}/paso0")
        resultado = ejecutar_auditoria_web(
            componentes, redes_autorizadas=_RED_127, seguir_redirecciones=True
        )

    assert len(resultado.saltos_seguidos) == modulo_auditor.MAXIMO_SALTOS
    # No se llego al final de la cadena: el ultimo salto seguido no es el paso final.
    assert resultado.codigo_estado == 302


def test_limite_de_tiempo_total_distinto_del_limite_por_peticion(monkeypatch):
    """El limite total de la auditoria se agota aunque cada peticion individual sea rapida.

    Cada peticion individual respeta facilmente ``--tiempo-limite`` (generoso, 5s), pero
    la SUMA de las dos primeras (con una demora deliberada de 0.1s cada una) supera el
    limite TOTAL falseado (0.05s) antes de llegar al final de la cadena: demuestra que
    son dos limites independientes.
    """
    monkeypatch.setattr(modulo_auditor, "TIEMPO_LIMITE_TOTAL_MAXIMO", 0.05)

    respuestas_host = {
        "/paso0": RespuestaConfigurada(302, [("Location", "/paso1")], b"", demora=0.1),
        "/paso1": RespuestaConfigurada(302, [("Location", "/paso2")], b"", demora=0.1),
        "/paso2": RespuestaConfigurada(200, [], b"fin"),
    }

    with servidor_prueba(respuestas_host) as (host, puerto):
        componentes = validar_url_web(f"http://{host}:{puerto}/paso0")
        resultado = ejecutar_auditoria_web(
            componentes,
            redes_autorizadas=_RED_127,
            seguir_redirecciones=True,
            tiempo_limite=5.0,  # limite POR peticion, generoso: no es lo que corta aqui
        )

    assert len(resultado.saltos_seguidos) < 2  # nunca llego a /paso2
    assert any(h.id_ == "redireccion-tiempo-total-agotado" for h in resultado.hallazgos)


def test_certificado_no_confiable_devuelve_hallazgos_tls_sin_excepcion():
    """Reproduce el bug reportado: un TLS no confiable no debe dejar la auditoria sin hallazgos."""
    cert_pem, key_pem = generar_certificado_autofirmado("127.0.0.1")
    with servidor_prueba(
        {"/": RespuestaConfigurada(200, [], b"ok")}, https=True, cert_pem=cert_pem, key_pem=key_pem
    ) as (host, puerto):
        componentes = validar_url_web(f"https://{host}:{puerto}/")
        resultado = ejecutar_auditoria_web(componentes, redes_autorizadas=_RED_127)

    assert resultado.codigo_estado is None  # la parte HTTP no se completo
    confianza = next(h for h in resultado.hallazgos if h.id_ == "tls-confianza")
    assert confianza.severidad == "alta"
    assert confianza.estado == "No confiable"
    # Como la peticion HTTP no se completo, no se inventan hallazgos de cabeceras/cookies.
    assert not any(h.categoria in ("cabecera", "cookie") for h in resultado.hallazgos)
    assert any(h.id_ == "http-incompleto" for h in resultado.hallazgos)


def test_certificado_vencido_tambien_devuelve_hallazgos_tls():
    cert_pem, key_pem = generar_certificado_autofirmado("127.0.0.1", vencido=True)
    with servidor_prueba(
        {"/": RespuestaConfigurada(200, [], b"ok")}, https=True, cert_pem=cert_pem, key_pem=key_pem
    ) as (host, puerto):
        componentes = validar_url_web(f"https://{host}:{puerto}/")
        resultado = ejecutar_auditoria_web(componentes, redes_autorizadas=_RED_127)

    vencimiento = next(h for h in resultado.hallazgos if h.id_ == "tls-vencimiento")
    assert vencimiento.estado == "Vencido"
    assert vencimiento.severidad == "alta"


def test_fuera_de_alcance_no_hace_ninguna_peticion():
    with pytest.raises(ErrorFueraDeAlcance):
        ejecutar_auditoria_web(
            validar_url_web("http://127.0.0.1:65000/"),
            redes_autorizadas=[ipaddress.IPv4Network("10.0.0.0/24")],
        )


def test_cancelacion_antes_de_iniciar_no_hace_ninguna_peticion():
    with pytest.raises(ErrorAuditoriaWeb):
        ejecutar_auditoria_web(
            validar_url_web("http://127.0.0.1:65000/"),
            redes_autorizadas=_RED_127,
            debe_cancelar=lambda: True,
        )


def test_tipos_solo_tls_no_hace_evaluacion_de_cabeceras_ni_cookies():
    with servidor_prueba(
        {"/": RespuestaConfigurada(200, [("Set-Cookie", "a=1")], b"ok")}
    ) as (host, puerto):
        componentes = validar_url_web(f"http://{host}:{puerto}/")
        resultado = ejecutar_auditoria_web(
            componentes, redes_autorizadas=_RED_127, tipos=frozenset({"tls"})
        )

    assert all(h.categoria == "tls" for h in resultado.hallazgos)


def test_tipo_invalido_lanza_value_error():
    with servidor_prueba({"/": RespuestaConfigurada(200, [], b"ok")}) as (host, puerto):
        componentes = validar_url_web(f"http://{host}:{puerto}/")
        with pytest.raises(ValueError):
            ejecutar_auditoria_web(
                componentes, redes_autorizadas=_RED_127, tipos=frozenset({"no-existe"})
            )
