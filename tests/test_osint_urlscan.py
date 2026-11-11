"""Pruebas de ``integrations/osint/urlscan.py`` (busqueda publica, sin clave)."""

from __future__ import annotations

import pytest

from eurabyte_security.core.errores import ErrorFuenteOSINTError
from eurabyte_security.integrations.osint import urlscan


def test_disponible_sin_configuracion():
    assert urlscan.AdaptadorUrlscan().configurada() is True


def test_sin_resultados_no_produce_hallazgos(monkeypatch):
    monkeypatch.setattr(urlscan, "peticion_json", lambda *_a, **_k: {"results": []})
    hallazgos = urlscan.AdaptadorUrlscan().investigar(
        "ejemplo.com", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=None
    )
    assert hallazgos == []


def test_resultados_se_resumen_como_probable(monkeypatch):
    monkeypatch.setattr(
        urlscan,
        "peticion_json",
        lambda *_a, **_k: {
            "results": [
                {
                    "page": {"url": "https://ejemplo.com/"},
                    "task": {"time": "2026-01-01T00:00:00.000Z"},
                    "result": "https://urlscan.io/result/abc123/",
                }
            ]
        },
    )
    hallazgos = urlscan.AdaptadorUrlscan().investigar(
        "ejemplo.com", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=None
    )
    assert len(hallazgos) == 1
    assert hallazgos[0].nivel_confianza == "probable"
    assert len(hallazgos[0].evidencias) == 1


def test_respuesta_malformada_lanza_error(monkeypatch):
    monkeypatch.setattr(urlscan, "peticion_json", lambda *_a, **_k: ["no es un dict"])
    with pytest.raises(ErrorFuenteOSINTError):
        urlscan.AdaptadorUrlscan().investigar(
            "ejemplo.com", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=None
        )
