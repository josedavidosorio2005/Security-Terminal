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
            "total": 1,
            "results": [
                {
                    "page": {"url": "https://ejemplo.com/"},
                    "task": {"time": "2026-01-01T00:00:00.000Z"},
                    "result": "https://urlscan.io/result/abc123/",
                }
            ],
        },
    )
    hallazgos = urlscan.AdaptadorUrlscan().investigar(
        "ejemplo.com", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=None
    )
    assert len(hallazgos) == 1
    assert hallazgos[0].nivel_confianza == "probable"
    evidencia = hallazgos[0].evidencias[0]
    # La URL observada va limpia en 'valor' (nunca combinada con la fecha como texto):
    # ver seccion 2 de la especificacion de evidencia completa ("URL completas, no
    # resumidas ni truncadas").
    assert evidencia.valor == "https://ejemplo.com/"
    assert evidencia.fecha_observada == "2026-01-01T00:00:00.000Z"
    assert evidencia.referencia == "https://urlscan.io/result/abc123/"


def test_paginacion_sigue_el_cursor_hasta_la_ultima_pagina(monkeypatch):
    pagina_1 = {
        "total": 150,
        "results": [
            {
                "page": {"url": f"https://ejemplo.com/{i}"},
                "task": {"time": "2026-01-01T00:00:00.000Z"},
                "result": f"https://urlscan.io/result/{i}/",
                "sort": [1000 + i, i],
            }
            for i in range(urlscan.RESULTADOS_POR_PAGINA)
        ],
    }
    pagina_2 = {
        "total": 150,
        "results": [
            {
                "page": {"url": "https://ejemplo.com/ultimo"},
                "task": {"time": "2026-01-02T00:00:00.000Z"},
                "result": "https://urlscan.io/result/ultimo/",
                "sort": [2000, 1],
            }
        ],
    }
    llamadas = []

    def _fake(url, **_kwargs):
        llamadas.append(url)
        return pagina_1 if len(llamadas) == 1 else pagina_2

    monkeypatch.setattr(urlscan, "peticion_json", _fake)
    hallazgos = urlscan.AdaptadorUrlscan().investigar(
        "ejemplo.com", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=None
    )
    assert len(llamadas) == 2
    assert "search_after=" not in llamadas[0]
    assert "search_after=1099,99" in llamadas[1]
    assert len(hallazgos[0].evidencias) == urlscan.RESULTADOS_POR_PAGINA + 1


def test_paginacion_se_detiene_si_se_cancela(monkeypatch):
    llamadas = []

    def _fake(*_a, **_k):
        llamadas.append(1)
        return {
            "total": 1000,
            "results": [
                {
                    "page": {"url": "https://ejemplo.com/x"},
                    "task": {"time": "2026-01-01T00:00:00.000Z"},
                    "result": "https://urlscan.io/result/x/",
                    "sort": [1, 1],
                }
            ]
            * urlscan.RESULTADOS_POR_PAGINA,
        }

    monkeypatch.setattr(urlscan, "peticion_json", _fake)
    secuencia = iter([False, True, True])
    hallazgos = urlscan.AdaptadorUrlscan().investigar(
        "ejemplo.com",
        tipo_objetivo="dominio",
        tiempo_limite=5.0,
        debe_cancelar=lambda: next(secuencia, True),
    )
    assert len(llamadas) == 1
    assert hallazgos  # la primera pagina ya recuperada se conserva


def test_truncamiento_se_documenta_en_la_descripcion(monkeypatch):
    def _fake(*_a, **_k):
        return {
            "total": 500,
            "results": [
                {
                    "page": {"url": f"https://ejemplo.com/{i}"},
                    "task": {"time": "2026-01-01T00:00:00.000Z"},
                    "result": f"https://urlscan.io/result/{i}/",
                    "sort": [i, i],
                }
                for i in range(urlscan.RESULTADOS_POR_PAGINA)
            ],
        }

    monkeypatch.setattr(urlscan, "peticion_json", _fake)
    hallazgos = urlscan.AdaptadorUrlscan().investigar(
        "ejemplo.com", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=None
    )
    assert "500" in hallazgos[0].descripcion


def test_respuesta_malformada_lanza_error(monkeypatch):
    monkeypatch.setattr(urlscan, "peticion_json", lambda *_a, **_k: ["no es un dict"])
    with pytest.raises(ErrorFuenteOSINTError):
        urlscan.AdaptadorUrlscan().investigar(
            "ejemplo.com", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=None
        )
