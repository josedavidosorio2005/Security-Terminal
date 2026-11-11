"""Pruebas de ``integrations/osint/virustotal.py``."""

from __future__ import annotations

import pytest

from eurabyte_security.core.errores import ErrorFuenteOSINTError, ErrorFuenteOSINTNoDisponible
from eurabyte_security.integrations.osint import cache, virustotal
from eurabyte_security.integrations.osint.limitador import LimitadorTasa


def _preparar(monkeypatch):
    monkeypatch.setattr(cache, "obtener", lambda clave: None)
    monkeypatch.setattr(cache, "guardar", lambda clave, valor, ttl_segundos: None)
    monkeypatch.setattr(
        LimitadorTasa, "esperar_si_necesario", lambda self, debe_cancelar=None: None
    )


def test_sin_clave_no_disponible(monkeypatch):
    monkeypatch.delenv(virustotal.VARIABLE_CLAVE_VT, raising=False)
    with pytest.raises(ErrorFuenteOSINTNoDisponible):
        virustotal.AdaptadorVirusTotal().investigar(
            "ejemplo.com", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=None
        )


def test_dominio_limpio_sin_indicador(monkeypatch):
    monkeypatch.setenv(virustotal.VARIABLE_CLAVE_VT, "clave")
    _preparar(monkeypatch)
    monkeypatch.setattr(
        virustotal,
        "peticion_json",
        lambda *_a, **_k: {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0},
                    "reputation": 5,
                }
            }
        },
    )
    hallazgos = virustotal.AdaptadorVirusTotal().investigar(
        "ejemplo.com", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=None
    )
    assert hallazgos[0].indicador_exposicion is None


def test_dominio_marcado_malicioso_genera_indicador(monkeypatch):
    monkeypatch.setenv(virustotal.VARIABLE_CLAVE_VT, "clave")
    _preparar(monkeypatch)
    monkeypatch.setattr(
        virustotal,
        "peticion_json",
        lambda *_a, **_k: {
            "data": {"attributes": {"last_analysis_stats": {"malicious": 3, "suspicious": 1}}}
        },
    )
    hallazgos = virustotal.AdaptadorVirusTotal().investigar(
        "malicioso.invalido", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=None
    )
    assert hallazgos[0].indicador_exposicion is not None
    assert "3" in hallazgos[0].indicador_exposicion


def test_dominio_no_encontrado_no_disponible(monkeypatch):
    monkeypatch.setenv(virustotal.VARIABLE_CLAVE_VT, "clave")
    _preparar(monkeypatch)

    def _fallar(*_a, **_k):
        raise ErrorFuenteOSINTError("'virustotal.com' respondio con el codigo HTTP 404.")

    monkeypatch.setattr(virustotal, "peticion_json", _fallar)
    with pytest.raises(ErrorFuenteOSINTNoDisponible):
        virustotal.AdaptadorVirusTotal().investigar(
            "ejemplo.com", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=None
        )


def test_clave_invalida_no_disponible(monkeypatch):
    monkeypatch.setenv(virustotal.VARIABLE_CLAVE_VT, "clave-mala")
    _preparar(monkeypatch)

    def _fallar(*_a, **_k):
        raise ErrorFuenteOSINTError("'virustotal.com' respondio con el codigo HTTP 401.")

    monkeypatch.setattr(virustotal, "peticion_json", _fallar)
    with pytest.raises(ErrorFuenteOSINTNoDisponible) as exc_info:
        virustotal.AdaptadorVirusTotal().investigar(
            "ejemplo.com", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=None
        )
    assert "clave-mala" not in str(exc_info.value)
