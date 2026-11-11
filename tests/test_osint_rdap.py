"""Pruebas de ``integrations/osint/rdap.py`` (dominio e infraestructura IP).

``peticion_json`` se sustituye en cada modulo que lo usa: ninguna prueba consulta
``rdap.org`` de verdad (ver CLAUDE.md, regla 5).
"""

from __future__ import annotations

import pytest

from eurabyte_security.core.errores import ErrorFuenteOSINTError, ErrorFuenteOSINTNoDisponible
from eurabyte_security.integrations.osint import rdap


def test_rdap_dominio_hallazgo_basico(monkeypatch):
    monkeypatch.setattr(
        rdap,
        "peticion_json",
        lambda *_a, **_k: {
            "status": ["active"],
            "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}],
            "entities": [],
        },
    )
    hallazgos = rdap.AdaptadorRDAPDominio().investigar(
        "ejemplo.com", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=None
    )
    assert len(hallazgos) == 1
    assert "active" in hallazgos[0].descripcion


def test_rdap_dominio_extrae_organizacion_pero_nunca_persona(monkeypatch):
    vcard_org = ["version", {}, "text", "4.0"], ["org", {}, "text", "Ejemplo S.A."]
    vcard_fn = ["fn", {}, "text", "Juan Perez"]
    monkeypatch.setattr(
        rdap,
        "peticion_json",
        lambda *_a, **_k: {
            "status": ["active"],
            "events": [],
            "entities": [
                {"roles": ["registrant"], "vcardArray": ["vcard", [vcard_fn, vcard_org[1]]]},
            ],
        },
    )
    hallazgos = rdap.AdaptadorRDAPDominio().investigar(
        "ejemplo.com", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=None
    )
    organizaciones = [h for h in hallazgos if h.titulo == "Organizacion registrante (RDAP)"]
    assert len(organizaciones) == 1
    assert "Ejemplo S.A." in organizaciones[0].descripcion
    assert "Juan Perez" not in organizaciones[0].descripcion
    assert organizaciones[0].nivel_confianza == "probable"


def test_rdap_dominio_404_no_disponible(monkeypatch):
    def _fallar(*_a, **_k):
        raise ErrorFuenteOSINTError("'rdap.org' respondio con el codigo HTTP 404.")

    monkeypatch.setattr(rdap, "peticion_json", _fallar)
    with pytest.raises(ErrorFuenteOSINTNoDisponible):
        rdap.AdaptadorRDAPDominio().investigar(
            "noexiste.invalido", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=None
        )


def test_rdap_dominio_respuesta_malformada_lanza_error(monkeypatch):
    monkeypatch.setattr(rdap, "peticion_json", lambda *_a, **_k: ["no es un dict"])
    with pytest.raises(ErrorFuenteOSINTError):
        rdap.AdaptadorRDAPDominio().investigar(
            "ejemplo.com", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=None
        )


def test_infraestructura_ip_sin_resolucion_dns_no_disponible(monkeypatch):
    import socket

    def _resolver_falla(*_a, **_k):
        raise OSError("nombre no resuelto")

    monkeypatch.setattr(socket, "getaddrinfo", _resolver_falla)
    with pytest.raises(ErrorFuenteOSINTNoDisponible):
        rdap.AdaptadorInfraestructuraIP().investigar(
            "noexiste.invalido", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=None
        )


def test_infraestructura_ip_hallazgo_basico(monkeypatch):
    import socket

    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *_a, **_k: [(2, 1, 6, "", ("93.184.216.34", 0))]
    )
    monkeypatch.setattr(
        rdap,
        "peticion_json",
        lambda *_a, **_k: {
            "name": "RED-EJEMPLO",
            "country": "US",
            "startAddress": "93.184.216.0",
            "endAddress": "93.184.216.255",
            "entities": [],
        },
    )
    hallazgos = rdap.AdaptadorInfraestructuraIP().investigar(
        "ejemplo.com", tipo_objetivo="dominio", tiempo_limite=5.0, debe_cancelar=None
    )
    assert len(hallazgos) == 1
    assert "RED-EJEMPLO" in hallazgos[0].descripcion
    assert hallazgos[0].nivel_confianza == "confirmado"
