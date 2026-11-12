"""Pruebas de ``integrations/osint/telefono_metadatos.py``.

Esta fuente nunca hace una peticion de red (solo lee los catalogos locales de
``phonenumbers``): las pruebas usan numeros de prueba documentados (no numeros reales
de terceros) y no necesitan ningun doble de red.
"""

from __future__ import annotations

import pytest

from eurabyte_security.core.errores import ErrorFuenteOSINTError
from eurabyte_security.integrations.osint.telefono_metadatos import AdaptadorMetadatosTelefono


def test_disponible_sin_configuracion():
    assert AdaptadorMetadatosTelefono().configurada() is True


def test_metadatos_completos_para_un_numero_movil_colombiano():
    hallazgos = AdaptadorMetadatosTelefono().investigar(
        "+573001234567", tipo_objetivo="telefono", tiempo_limite=5.0, debe_cancelar=None
    )
    assert len(hallazgos) >= 1
    principal = hallazgos[0]
    assert principal.nivel_confianza == "confirmado"
    valores = [e.valor for e in principal.evidencias]
    assert any(v.startswith("E.164: +573001234567") for v in valores)
    assert any("Formato nacional" in v for v in valores)
    assert any("Formato internacional" in v for v in valores)
    assert any("Codigo de pais: +57" in v for v in valores)
    assert any("Numero posible" in v for v in valores)
    assert any("Numero valido" in v for v in valores)
    assert any("Tipo de linea: movil" in v for v in valores)
    assert any("Pais o region (ISO): CO" in v for v in valores)
    assert any("Zona(s) horaria(s)" in v for v in valores)


def test_operador_sugerido_se_marca_no_verificado_y_en_hallazgo_separado():
    hallazgos = AdaptadorMetadatosTelefono().investigar(
        "+573001234567", tipo_objetivo="telefono", tiempo_limite=5.0, debe_cancelar=None
    )
    operador = [h for h in hallazgos if "operador" in h.titulo.lower()]
    if operador:  # phonenumbers no siempre tiene datos de operador para un numero dado
        assert operador[0].nivel_confianza == "no_verificado"
        assert operador[0] is not hallazgos[0]


def test_numero_sin_region_no_falla_sin_evidencias_de_region():
    # Un numero de prueba que phonenumbers sabe interpretar pero sin region asociada
    # clara no debe lanzar ni omitir el resto de metadatos basicos.
    hallazgos = AdaptadorMetadatosTelefono().investigar(
        "+800123456789", tipo_objetivo="telefono", tiempo_limite=5.0, debe_cancelar=None
    )
    assert len(hallazgos) >= 1
    valores = [e.valor for e in hallazgos[0].evidencias]
    assert any(v.startswith("E.164:") for v in valores)


def test_numero_no_e164_lanza_error_de_fuente():
    with pytest.raises(ErrorFuenteOSINTError):
        AdaptadorMetadatosTelefono().investigar(
            "no-es-un-numero", tipo_objetivo="telefono", tiempo_limite=5.0, debe_cancelar=None
        )


def test_nunca_hace_una_peticion_de_red(monkeypatch):
    """Si alguien introdujera por error una llamada HTTP en esta fuente, esta prueba
    la detectaria: sustituye 'urlopen' para que cualquier intento de red falle."""
    from eurabyte_security.integrations.osint import cliente_http

    def _red_prohibida(*_args, **_kwargs):
        raise AssertionError("telefono_metadatos no debe hacer ninguna peticion de red")

    monkeypatch.setattr(cliente_http, "urlopen", _red_prohibida)
    AdaptadorMetadatosTelefono().investigar(
        "+573001234567", tipo_objetivo="telefono", tiempo_limite=5.0, debe_cancelar=None
    )
