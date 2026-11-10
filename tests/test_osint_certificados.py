"""Pruebas de ``integrations/osint/certificados.py`` (Certificate Transparency)."""

from __future__ import annotations

import pytest

from eurabyte_security.core.errores import ErrorFuenteOSINTError
from eurabyte_security.integrations.osint import certificados


def test_subdominios_se_deduplican_y_ordenan(monkeypatch):
    monkeypatch.setattr(
        certificados,
        "peticion_json",
        lambda *_a, **_k: [
            {"name_value": "www.ejemplo.com\nmail.ejemplo.com"},
            {"name_value": "*.api.ejemplo.com"},
            {"name_value": "www.ejemplo.com"},  # duplicado
        ],
    )
    hallazgos = certificados.AdaptadorCertificateTransparency().investigar(
        "ejemplo.com", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=None
    )
    assert len(hallazgos) == 1
    assert hallazgos[0].nivel_confianza == "probable"
    valores = sorted(e.valor for e in hallazgos[0].evidencias)
    assert valores == ["api.ejemplo.com", "mail.ejemplo.com", "www.ejemplo.com"]


def test_sin_subdominios_no_produce_hallazgos(monkeypatch):
    monkeypatch.setattr(certificados, "peticion_json", lambda *_a, **_k: [])
    hallazgos = certificados.AdaptadorCertificateTransparency().investigar(
        "ejemplo.com", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=None
    )
    assert hallazgos == []


def test_respuesta_malformada_lanza_error(monkeypatch):
    monkeypatch.setattr(certificados, "peticion_json", lambda *_a, **_k: {"no": "es una lista"})
    with pytest.raises(ErrorFuenteOSINTError):
        certificados.AdaptadorCertificateTransparency().investigar(
            "ejemplo.com", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=None
        )


def test_limite_de_subdominios_respetado(monkeypatch):
    entradas = [{"name_value": f"host{i}.ejemplo.com"} for i in range(80)]
    monkeypatch.setattr(certificados, "peticion_json", lambda *_a, **_k: entradas)
    hallazgos = certificados.AdaptadorCertificateTransparency().investigar(
        "ejemplo.com", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=None
    )
    assert len(hallazgos[0].evidencias) == certificados.MAXIMO_SUBDOMINIOS
