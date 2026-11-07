from __future__ import annotations

import ipaddress

import pytest

from eurabyte_security.core.errores import ErrorAuditoriaWeb, ErrorFueraDeAlcance
from eurabyte_security.core.validation import validar_url_web
from eurabyte_security.modules.web.cliente import RespuestaWeb
from eurabyte_security.modules.web.redirecciones import (
    evaluar_redireccion,
    resolver_siguiente_salto,
)

_RED_127 = [ipaddress.IPv4Network("127.0.0.1/32")]


def _respuesta(url: str, ubicacion: str | None) -> RespuestaWeb:
    componentes = validar_url_web(url)
    return RespuestaWeb(
        componentes=componentes,
        codigo_estado=302 if ubicacion else 200,
        cabeceras=(),
        cuerpo=b"",
        cuerpo_truncado=False,
        ubicacion_redireccion=ubicacion,
        tls=None,
    )


def test_sin_redireccion_no_hay_hallazgos():
    respuesta = _respuesta("http://127.0.0.1/", None)
    assert evaluar_redireccion(respuesta, redes_autorizadas=_RED_127, se_siguio=False) == []


def test_redireccion_a_dominio_no_se_puede_evaluar_con_seguridad():
    respuesta = _respuesta("http://127.0.0.1/", "https://example.com/login")
    hallazgos = evaluar_redireccion(respuesta, redes_autorizadas=_RED_127, se_siguio=False)
    assert hallazgos[0].severidad == "media"
    assert "no se puede evaluar" in hallazgos[0].estado.lower()

    with pytest.raises(ErrorAuditoriaWeb):
        resolver_siguiente_salto(respuesta, redes_autorizadas=_RED_127)


def test_redireccion_fuera_de_alcance_se_marca_como_alta_y_no_se_sigue():
    respuesta = _respuesta("http://127.0.0.1/", "http://192.168.1.50/panel")
    hallazgos = evaluar_redireccion(respuesta, redes_autorizadas=_RED_127, se_siguio=False)
    assert hallazgos[0].severidad == "alta"
    assert "fuera de alcance" in hallazgos[0].estado.lower()

    with pytest.raises(ErrorFueraDeAlcance):
        resolver_siguiente_salto(respuesta, redes_autorizadas=_RED_127)


def test_redireccion_relativa_dentro_de_alcance_se_resuelve_contra_la_url_base():
    respuesta = _respuesta("http://127.0.0.1:8080/inicio", "/panel")
    siguiente = resolver_siguiente_salto(respuesta, redes_autorizadas=_RED_127)
    assert siguiente.host == ipaddress.IPv4Address("127.0.0.1")
    assert siguiente.puerto == 8080
    assert siguiente.ruta == "/panel"


def test_redireccion_dentro_de_alcance_no_seguida_por_defecto():
    respuesta = _respuesta("http://127.0.0.1/", "http://127.0.0.1/otro")
    hallazgos = evaluar_redireccion(respuesta, redes_autorizadas=_RED_127, se_siguio=False)
    assert hallazgos[0].severidad == "info"
    assert "no seguida" in hallazgos[0].estado.lower()


def test_redireccion_dentro_de_alcance_y_seguida_es_informativa():
    respuesta = _respuesta("http://127.0.0.1/", "http://127.0.0.1/otro")
    hallazgos = evaluar_redireccion(respuesta, redes_autorizadas=_RED_127, se_siguio=True)
    assert hallazgos[0].severidad == "info"
    assert "seguida" in hallazgos[0].estado.lower()
    assert "no seguida" not in hallazgos[0].estado.lower()
