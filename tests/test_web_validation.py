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


# ---------------------------------------------------------------------------
# Ningun mensaje de error de validar_url_web() debe filtrar un secreto en claro.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "secreto"),
    [
        # Esquema invalido: el mensaje interpola la URL completa.
        ("ftp://127.0.0.1/?token=secreto-esquema-123", "secreto-esquema-123"),
        # Credenciales en la URL: justo lo que el mensaje rechaza, no debe repetirlo.
        ("https://admin:supersecreta-456@127.0.0.1/", "supersecreta-456"),
        # Puerto invalido: la URL completa (con su query) se mostraba cruda.
        ("https://127.0.0.1:no-es-un-puerto/?password=secreto-puerto-789", "secreto-puerto-789"),
        # Host vacio: idem.
        ("https:///?token=secreto-sin-host-321", "secreto-sin-host-321"),
        # URL que ni siquiera se puede dividir (IPv6 mal formado) con un secreto detras.
        ("http://[::1/roto?token=secreto-url-rota-654", "secreto-url-rota-654"),
    ],
)
def test_mensajes_de_error_no_filtran_secretos_en_claro(url: str, secreto: str):
    with pytest.raises(ErrorValidacion) as info:
        validar_url_web(url)
    assert secreto not in str(info.value)


def test_credenciales_se_eliminan_del_mensaje_no_solo_el_secreto():
    with pytest.raises(ErrorValidacion) as info:
        validar_url_web("https://admin:supersecreta@127.0.0.1/")
    mensaje = str(info.value)
    assert "admin" not in mensaje
    assert "supersecreta" not in mensaje
