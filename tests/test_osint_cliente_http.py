"""Pruebas de ``integrations/osint/cliente_http.py``.

Ninguna prueba hace una peticion de red real: ``cliente_http.urlopen`` se sustituye por
un doble en cada caso (ver CLAUDE.md, regla 5 y ``docs/OSINT.md``).
"""

from __future__ import annotations

import urllib.error
from email.message import Message

import pytest

from eurabyte_security.core.errores import ErrorFuenteOSINTError
from eurabyte_security.integrations.osint import cliente_http


class _RespuestaFalsa:
    def __init__(self, cuerpo: str, codigo: int = 200, cabeceras: Message | None = None) -> None:
        self._cuerpo = cuerpo.encode("utf-8")
        self.status = codigo
        self.headers = cabeceras or Message()

    def read(self) -> bytes:
        return self._cuerpo

    def getcode(self) -> int:
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def test_peticion_json_devuelve_datos_decodificados(monkeypatch):
    monkeypatch.setattr(cliente_http, "urlopen", lambda *_a, **_k: _RespuestaFalsa('{"a": 1}'))
    datos = cliente_http.peticion_json("https://ejemplo.invalido/api")
    assert datos == {"a": 1}


def test_peticion_json_respuesta_no_json_lanza_error(monkeypatch):
    monkeypatch.setattr(cliente_http, "urlopen", lambda *_a, **_k: _RespuestaFalsa("no es json"))
    with pytest.raises(ErrorFuenteOSINTError):
        cliente_http.peticion_json("https://ejemplo.invalido/api")


def test_peticion_http_404_lanza_error_sin_reintentar(monkeypatch):
    llamadas = []

    def _urlopen_falso(*_a, **_k):
        llamadas.append(1)
        raise urllib.error.HTTPError(
            "https://ejemplo.invalido", 404, "No encontrado", Message(), None
        )

    monkeypatch.setattr(cliente_http, "urlopen", _urlopen_falso)
    with pytest.raises(ErrorFuenteOSINTError, match="404"):
        cliente_http.peticion_http("https://ejemplo.invalido/api")
    assert len(llamadas) == 1


def test_peticion_http_429_respeta_retry_after_y_reintenta(monkeypatch):
    cabeceras_429 = Message()
    cabeceras_429["Retry-After"] = "0"
    llamadas = {"n": 0}

    def _urlopen_falso(*_a, **_k):
        llamadas["n"] += 1
        if llamadas["n"] == 1:
            raise urllib.error.HTTPError(
                "https://ejemplo.invalido", 429, "Demasiadas peticiones", cabeceras_429, None
            )
        return _RespuestaFalsa("ok", 200)

    monkeypatch.setattr(cliente_http, "urlopen", _urlopen_falso)
    respuesta = cliente_http.peticion_http("https://ejemplo.invalido/api", reintentos=2)
    assert respuesta.cuerpo == "ok"
    assert llamadas["n"] == 2


def test_peticion_http_cancelacion_detiene_reintentos(monkeypatch):
    cabeceras_429 = Message()
    cabeceras_429["Retry-After"] = "5"

    def _urlopen_falso(*_a, **_k):
        raise urllib.error.HTTPError(
            "https://ejemplo.invalido", 429, "Demasiadas peticiones", cabeceras_429, None
        )

    monkeypatch.setattr(cliente_http, "urlopen", _urlopen_falso)
    with pytest.raises(ErrorFuenteOSINTError):
        cliente_http.peticion_http(
            "https://ejemplo.invalido/api", reintentos=3, debe_cancelar=lambda: True
        )


def test_peticion_http_timeout_lanza_error_fuente(monkeypatch):
    def _urlopen_falso(*_a, **_k):
        raise TimeoutError("se agoto el tiempo")

    monkeypatch.setattr(cliente_http, "urlopen", _urlopen_falso)
    with pytest.raises(ErrorFuenteOSINTError):
        cliente_http.peticion_http("https://ejemplo.invalido/api")


def test_peticion_http_error_de_conexion_lanza_error_fuente(monkeypatch):
    def _urlopen_falso(*_a, **_k):
        raise urllib.error.URLError("nombre no resuelto")

    monkeypatch.setattr(cliente_http, "urlopen", _urlopen_falso)
    with pytest.raises(ErrorFuenteOSINTError):
        cliente_http.peticion_http("https://ejemplo.invalido/api")


def test_url_con_secreto_en_consulta_no_aparece_en_claro_en_el_error(monkeypatch):
    def _urlopen_falso(*_a, **_k):
        raise urllib.error.HTTPError("https://ejemplo.invalido", 500, "Error", Message(), None)

    monkeypatch.setattr(cliente_http, "urlopen", _urlopen_falso)
    url = "https://ejemplo.invalido/api?token=secreto123"
    with pytest.raises(ErrorFuenteOSINTError) as exc_info:
        cliente_http.peticion_http(url)
    assert "secreto123" not in str(exc_info.value)
