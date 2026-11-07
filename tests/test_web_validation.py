from __future__ import annotations

import ipaddress

import pytest

from eurabyte_security.core.errores import ErrorValidacion
from eurabyte_security.core.validation import validar_url_web


def test_url_https_valida_se_interpreta_correctamente():
    componentes = validar_url_web("https://127.0.0.1:8443/panel?a=1")
    assert componentes.esquema == "https"
    assert componentes.host == ipaddress.IPv4Address("127.0.0.1")
    assert componentes.puerto == 8443
    assert componentes.ruta == "/panel?a=1"


def test_url_http_sin_puerto_usa_el_puerto_por_defecto():
    componentes = validar_url_web("http://127.0.0.1/")
    assert componentes.puerto == 80
    assert componentes.esquema == "http"


def test_url_https_sin_puerto_usa_443():
    componentes = validar_url_web("https://127.0.0.1")
    assert componentes.puerto == 443
    assert componentes.ruta == "/"


@pytest.mark.parametrize(
    "url",
    [
        "",
        "ftp://127.0.0.1/",
        "https://example.com/",  # nombre de dominio: requiere DNS, no soportado
        "https://usuario:clave@127.0.0.1/",
        "https://127.0.0.1:999999/",
        "no-es-una-url",
        "https://[::1]/",  # IPv6: no soportado en esta entrega
    ],
)
def test_entradas_malformadas_o_no_soportadas_se_rechazan(url: str):
    with pytest.raises(ErrorValidacion):
        validar_url_web(url)
