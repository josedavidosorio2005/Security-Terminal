"""Pruebas de ``integrations/osint/twilio_lookup.py`` (fuente opcional, de pago)."""

from __future__ import annotations

import pytest

from eurabyte_security.core.errores import ErrorFuenteOSINTError, ErrorFuenteOSINTNoDisponible
from eurabyte_security.integrations.osint import twilio_lookup


def _configurar(monkeypatch):
    monkeypatch.setenv(twilio_lookup.VARIABLE_ACCOUNT_SID, "AC-prueba")
    monkeypatch.setenv(twilio_lookup.VARIABLE_AUTH_TOKEN, "token-secreto-123")


def test_requiere_seleccion_explicita():
    # Nunca debe ejecutarse solo porque las credenciales esten configuradas (ver
    # modules/osint/motor.py): es una fuente que factura por consulta.
    assert twilio_lookup.AdaptadorTwilioLookup().requiere_seleccion_explicita is True


def test_sin_credenciales_no_disponible(monkeypatch):
    monkeypatch.delenv(twilio_lookup.VARIABLE_ACCOUNT_SID, raising=False)
    monkeypatch.delenv(twilio_lookup.VARIABLE_AUTH_TOKEN, raising=False)
    with pytest.raises(ErrorFuenteOSINTNoDisponible):
        twilio_lookup.AdaptadorTwilioLookup().investigar(
            "+573001234567", tipo_objetivo="telefono", tiempo_limite=5.0, debe_cancelar=None
        )


def test_falta_solo_el_auth_token_no_disponible(monkeypatch):
    monkeypatch.setenv(twilio_lookup.VARIABLE_ACCOUNT_SID, "AC-prueba")
    monkeypatch.delenv(twilio_lookup.VARIABLE_AUTH_TOKEN, raising=False)
    assert twilio_lookup.AdaptadorTwilioLookup().configurada() is False


def test_mensaje_no_configurada_avisa_del_costo(monkeypatch):
    monkeypatch.delenv(twilio_lookup.VARIABLE_ACCOUNT_SID, raising=False)
    mensaje = twilio_lookup.AdaptadorTwilioLookup().mensaje_no_configurada()
    assert "factura" in mensaje.lower() or "costo" in mensaje.lower()


def test_numero_valido_devuelve_hallazgo_confirmado(monkeypatch):
    _configurar(monkeypatch)
    monkeypatch.setattr(
        twilio_lookup,
        "peticion_json",
        lambda *_a, **_k: {
            "valid": True,
            "country_code": "CO",
            "line_type_intelligence": {"type": "mobile", "carrier_name": "Operador Ejemplo"},
        },
    )
    hallazgos = twilio_lookup.AdaptadorTwilioLookup().investigar(
        "+573001234567", tipo_objetivo="telefono", tiempo_limite=5.0, debe_cancelar=None
    )
    assert hallazgos[0].nivel_confianza == "confirmado"
    operador = [h for h in hallazgos if "operador" in h.titulo.lower()]
    assert operador
    assert operador[0].nivel_confianza == "no_verificado"


def test_404_no_disponible(monkeypatch):
    _configurar(monkeypatch)

    def _fallar(*_a, **_k):
        raise ErrorFuenteOSINTError(
            "'lookups.twilio.com' respondio con el codigo HTTP 404.", codigo_http=404
        )

    monkeypatch.setattr(twilio_lookup, "peticion_json", _fallar)
    with pytest.raises(ErrorFuenteOSINTNoDisponible):
        twilio_lookup.AdaptadorTwilioLookup().investigar(
            "+573001234567", tipo_objetivo="telefono", tiempo_limite=5.0, debe_cancelar=None
        )


def test_401_credenciales_invalidas_no_disponible(monkeypatch):
    _configurar(monkeypatch)

    def _fallar(*_a, **_k):
        raise ErrorFuenteOSINTError(
            "'lookups.twilio.com' respondio con el codigo HTTP 401.", codigo_http=401
        )

    monkeypatch.setattr(twilio_lookup, "peticion_json", _fallar)
    with pytest.raises(ErrorFuenteOSINTNoDisponible):
        twilio_lookup.AdaptadorTwilioLookup().investigar(
            "+573001234567", tipo_objetivo="telefono", tiempo_limite=5.0, debe_cancelar=None
        )


def test_429_limite_de_tasa_no_disponible(monkeypatch):
    _configurar(monkeypatch)

    def _fallar(*_a, **_k):
        raise ErrorFuenteOSINTError(
            "'lookups.twilio.com' respondio con el codigo HTTP 429.", codigo_http=429
        )

    monkeypatch.setattr(twilio_lookup, "peticion_json", _fallar)
    with pytest.raises(ErrorFuenteOSINTNoDisponible):
        twilio_lookup.AdaptadorTwilioLookup().investigar(
            "+573001234567", tipo_objetivo="telefono", tiempo_limite=5.0, debe_cancelar=None
        )


def test_credenciales_nunca_aparecen_en_el_mensaje_de_error(monkeypatch):
    monkeypatch.setenv(twilio_lookup.VARIABLE_ACCOUNT_SID, "AC-prueba")
    monkeypatch.setenv(twilio_lookup.VARIABLE_AUTH_TOKEN, "token-ultra-secreto-999")

    def _fallar(*_a, **_k):
        raise ErrorFuenteOSINTError(
            "'lookups.twilio.com' respondio con el codigo HTTP 401.", codigo_http=401
        )

    monkeypatch.setattr(twilio_lookup, "peticion_json", _fallar)
    with pytest.raises(ErrorFuenteOSINTNoDisponible) as exc_info:
        twilio_lookup.AdaptadorTwilioLookup().investigar(
            "+573001234567", tipo_objetivo="telefono", tiempo_limite=5.0, debe_cancelar=None
        )
    assert "token-ultra-secreto-999" not in str(exc_info.value)
