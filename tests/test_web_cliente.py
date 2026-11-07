from __future__ import annotations

import pytest

from eurabyte_security.core.errores import ErrorAuditoriaWeb
from eurabyte_security.core.validation import validar_url_web
from eurabyte_security.modules.web import cliente

from .ayudantes_web import RespuestaConfigurada, servidor_prueba


def test_peticion_basica_devuelve_estado_cabeceras_y_cuerpo():
    respuestas = {"/": RespuestaConfigurada(200, [("X-Test", "valor")], b"contenido")}
    with servidor_prueba(respuestas) as (host, puerto):
        componentes = validar_url_web(f"http://{host}:{puerto}/")
        respuesta = cliente.realizar_peticion(componentes, tiempo_limite=5.0)

    assert respuesta.codigo_estado == 200
    assert ("X-Test", "valor") in respuesta.cabeceras
    assert respuesta.cuerpo == b"contenido"
    assert not respuesta.cuerpo_truncado
    assert respuesta.ubicacion_redireccion is None
    assert respuesta.tls is None  # HTTP, no TLS


def test_redireccion_nunca_se_sigue_automaticamente():
    respuestas = {
        "/": RespuestaConfigurada(302, [("Location", "/otro")], b""),
        "/otro": RespuestaConfigurada(200, [], b"destino"),
    }
    with servidor_prueba(respuestas) as (host, puerto):
        componentes = validar_url_web(f"http://{host}:{puerto}/")
        respuesta = cliente.realizar_peticion(componentes, tiempo_limite=5.0)

    assert respuesta.codigo_estado == 302
    assert respuesta.ubicacion_redireccion == "/otro"
    # No se recibio el cuerpo del destino: nunca se hizo una segunda peticion.
    assert respuesta.cuerpo != b"destino"


def test_respuesta_demasiado_grande_se_trunca_sin_fallar():
    cuerpo_enorme = b"a" * (cliente.TAMANO_MAXIMO_CUERPO + 1024)
    respuestas = {"/": RespuestaConfigurada(200, [], cuerpo_enorme)}
    with servidor_prueba(respuestas) as (host, puerto):
        componentes = validar_url_web(f"http://{host}:{puerto}/")
        respuesta = cliente.realizar_peticion(componentes, tiempo_limite=5.0)

    assert respuesta.cuerpo_truncado
    assert len(respuesta.cuerpo) <= cliente.TAMANO_MAXIMO_CUERPO + 8192


def test_tiempo_agotado_al_conectar_con_puerto_cerrado():
    # Puerto 1 en loopback: nadie escucha, la conexion debe fallar o agotar el tiempo
    # (segun el sistema operativo), nunca colgarse indefinidamente.
    componentes = validar_url_web("http://127.0.0.1:1/")
    with pytest.raises(ErrorAuditoriaWeb):
        cliente.realizar_peticion(componentes, tiempo_limite=1.0)


def test_cancelacion_detiene_la_peticion_antes_de_completarse():
    respuestas = {"/": RespuestaConfigurada(200, [], b"contenido")}
    with servidor_prueba(respuestas) as (host, puerto):
        componentes = validar_url_web(f"http://{host}:{puerto}/")
        with pytest.raises(ErrorAuditoriaWeb, match="cancel"):
            cliente.realizar_peticion(
                componentes, tiempo_limite=5.0, debe_cancelar=lambda: True
            )
