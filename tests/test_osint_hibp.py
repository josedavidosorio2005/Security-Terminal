"""Pruebas de ``integrations/osint/hibp.py`` (Have I Been Pwned)."""

from __future__ import annotations

import pytest

from eurabyte_security.core.errores import ErrorFuenteOSINTError, ErrorFuenteOSINTNoDisponible
from eurabyte_security.integrations.osint import cache, hibp
from eurabyte_security.integrations.osint.limitador import LimitadorTasa


def _sin_cache(monkeypatch):
    monkeypatch.setattr(cache, "obtener", lambda clave: None)
    monkeypatch.setattr(cache, "guardar", lambda clave, valor, ttl_segundos: None)
    # Nunca espera el intervalo de tasa real en las pruebas (seria lento y
    # compartiria estado entre pruebas, ya que el limitador es global por fuente).
    monkeypatch.setattr(
        LimitadorTasa, "esperar_si_necesario", lambda self, debe_cancelar=None: None
    )


def test_sin_clave_configurada_no_disponible(monkeypatch):
    monkeypatch.delenv(hibp.VARIABLE_CLAVE_HIBP, raising=False)
    with pytest.raises(ErrorFuenteOSINTNoDisponible):
        hibp.AdaptadorHIBP().investigar(
            "usuario@ejemplo.com", tipo_objetivo="correo", tiempo_limite=5.0, debe_cancelar=None
        )


def test_sin_brechas_devuelve_hallazgo_informativo(monkeypatch):
    monkeypatch.setenv(hibp.VARIABLE_CLAVE_HIBP, "clave-de-prueba")
    _sin_cache(monkeypatch)
    monkeypatch.setattr(hibp, "peticion_json", lambda *_a, **_k: [])
    hallazgos = hibp.AdaptadorHIBP().investigar(
        "usuario@ejemplo.com", tipo_objetivo="correo", tiempo_limite=5.0, debe_cancelar=None
    )
    assert len(hallazgos) == 1
    assert hallazgos[0].titulo == "Sin brechas conocidas"
    assert hallazgos[0].indicador_exposicion is None


def test_404_se_trata_como_sin_brechas(monkeypatch):
    monkeypatch.setenv(hibp.VARIABLE_CLAVE_HIBP, "clave-de-prueba")
    _sin_cache(monkeypatch)

    def _fallar(*_a, **_k):
        raise ErrorFuenteOSINTError(
            "'haveibeenpwned.com' respondio con el codigo HTTP 404.", codigo_http=404
        )

    monkeypatch.setattr(hibp, "peticion_json", _fallar)
    hallazgos = hibp.AdaptadorHIBP().investigar(
        "usuario@ejemplo.com", tipo_objetivo="correo", tiempo_limite=5.0, debe_cancelar=None
    )
    assert hallazgos[0].titulo == "Sin brechas conocidas"


def test_401_clave_invalida_no_disponible(monkeypatch):
    monkeypatch.setenv(hibp.VARIABLE_CLAVE_HIBP, "clave-invalida")
    _sin_cache(monkeypatch)

    def _fallar(*_a, **_k):
        raise ErrorFuenteOSINTError(
            "'haveibeenpwned.com' respondio con el codigo HTTP 401.", codigo_http=401
        )

    monkeypatch.setattr(hibp, "peticion_json", _fallar)
    with pytest.raises(ErrorFuenteOSINTNoDisponible):
        hibp.AdaptadorHIBP().investigar(
            "usuario@ejemplo.com", tipo_objetivo="correo", tiempo_limite=5.0, debe_cancelar=None
        )


def test_clave_nunca_aparece_en_el_mensaje_de_error(monkeypatch):
    monkeypatch.setenv(hibp.VARIABLE_CLAVE_HIBP, "clave-ultra-secreta-123")
    _sin_cache(monkeypatch)

    def _fallar(*_a, **_k):
        raise ErrorFuenteOSINTError(
            "'haveibeenpwned.com' respondio con el codigo HTTP 401.", codigo_http=401
        )

    monkeypatch.setattr(hibp, "peticion_json", _fallar)
    with pytest.raises(ErrorFuenteOSINTNoDisponible) as exc_info:
        hibp.AdaptadorHIBP().investigar(
            "usuario@ejemplo.com", tipo_objetivo="correo", tiempo_limite=5.0, debe_cancelar=None
        )
    assert "clave-ultra-secreta-123" not in str(exc_info.value)


def test_brecha_encontrada_guarda_solo_categorias_nunca_datos_reales(monkeypatch):
    monkeypatch.setenv(hibp.VARIABLE_CLAVE_HIBP, "clave-de-prueba")
    _sin_cache(monkeypatch)
    monkeypatch.setattr(
        hibp,
        "peticion_json",
        lambda *_a, **_k: [
            {
                "Name": "EjemploBreach",
                "Title": "Ejemplo Breach",
                "BreachDate": "2020-01-01",
                "DataClasses": ["Email addresses", "Passwords"],
                "Description": "<p>texto HTML no confiable</p>",
            }
        ],
    )
    hallazgos = hibp.AdaptadorHIBP().investigar(
        "usuario@ejemplo.com", tipo_objetivo="correo", tiempo_limite=5.0, debe_cancelar=None
    )
    assert len(hallazgos) == 1
    hallazgo = hallazgos[0]
    assert "Email addresses" in hallazgo.descripcion
    assert "Passwords" in hallazgo.descripcion
    assert hallazgo.indicador_exposicion is not None
    assert hallazgo.nivel_confianza == "confirmado"
    # Nunca se guarda el HTML/descripcion cruda de la brecha como si fuera un dato.
    assert "texto HTML no confiable" not in hallazgo.descripcion


def test_usa_cache_si_esta_disponible(monkeypatch):
    monkeypatch.setenv(hibp.VARIABLE_CLAVE_HIBP, "clave-de-prueba")
    llamadas = []
    monkeypatch.setattr(cache, "obtener", lambda clave: [])
    monkeypatch.setattr(cache, "guardar", lambda *a, **k: None)
    monkeypatch.setattr(hibp, "peticion_json", lambda *a, **k: llamadas.append(1))
    hibp.AdaptadorHIBP().investigar(
        "usuario@ejemplo.com", tipo_objetivo="correo", tiempo_limite=5.0, debe_cancelar=None
    )
    assert llamadas == []
