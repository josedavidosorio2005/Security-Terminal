"""Pruebas de validacion y autorizacion OSINT (``core/osint/validacion.py``)."""

from __future__ import annotations

import pytest

from eurabyte_security.core.errores import ErrorAutorizacionOSINTRequerida, ErrorValidacion
from eurabyte_security.core.osint.validacion import (
    extraer_dominio_de_objetivo,
    requiere_autorizacion_datos_personales,
    validar_correo_osint,
    validar_dominio_osint,
    validar_telefono_osint,
    validar_usuario_osint,
    verificar_autorizacion_datos_personales,
)

# ---------------------------------------------------------------------------
# Dominio
# ---------------------------------------------------------------------------


def test_dominio_valido_se_normaliza_a_minusculas():
    assert validar_dominio_osint("Ejemplo.COM") == "ejemplo.com"


def test_dominio_con_punto_final_se_admite():
    assert validar_dominio_osint("ejemplo.com.") == "ejemplo.com"


@pytest.mark.parametrize(
    "entrada",
    [
        "",
        "   ",
        "https://ejemplo.com",
        "ejemplo.com/ruta",
        "usuario@ejemplo.com",
        "no es un dominio",
    ],
)
def test_dominio_invalido_rechazado(entrada):
    with pytest.raises(ErrorValidacion):
        validar_dominio_osint(entrada)


# ---------------------------------------------------------------------------
# Correo
# ---------------------------------------------------------------------------


def test_correo_valido_separa_local_y_dominio():
    resultado = validar_correo_osint("Usuario.Prueba@Ejemplo.COM")
    assert resultado.local == "Usuario.Prueba"
    assert resultado.dominio == "ejemplo.com"
    assert resultado.correo == "Usuario.Prueba@ejemplo.com"


@pytest.mark.parametrize(
    "entrada",
    [
        "",
        "sin-arroba.com",
        "dos@arrobas@ejemplo.com",
        "@ejemplo.com",
        "usuario@",
        "usuario@dominio invalido",
    ],
)
def test_correo_invalido_rechazado(entrada):
    with pytest.raises(ErrorValidacion):
        validar_correo_osint(entrada)


def test_correo_demasiado_largo_rechazado():
    local_largo = "a" * 250
    with pytest.raises(ErrorValidacion):
        validar_correo_osint(f"{local_largo}@ejemplo.com")


# ---------------------------------------------------------------------------
# Telefono
# ---------------------------------------------------------------------------


def test_telefono_internacional_valido_se_normaliza_a_e164():
    resultado = validar_telefono_osint("+57 300 1234567")
    assert resultado.e164 == "+573001234567"
    assert resultado.region == "CO"
    assert resultado.tipo_numero in {"movil", "fijo_o_movil"}


def test_telefono_nacional_con_region_por_defecto():
    resultado = validar_telefono_osint("300 1234567", region_por_defecto="CO")
    assert resultado.e164 == "+573001234567"


def test_telefono_nacional_sin_region_rechazado():
    with pytest.raises(ErrorValidacion):
        validar_telefono_osint("3001234567")


def test_telefono_invalido_rechazado():
    with pytest.raises(ErrorValidacion):
        validar_telefono_osint("+570000000000000000")


def test_telefono_vacio_rechazado():
    with pytest.raises(ErrorValidacion):
        validar_telefono_osint("")


# ---------------------------------------------------------------------------
# Usuario
# ---------------------------------------------------------------------------


def test_usuario_valido():
    assert validar_usuario_osint(" mi-usuario_01 ") == "mi-usuario_01"


@pytest.mark.parametrize("entrada", ["", "usuario con espacios", "a" * 40, "usuario@invalido"])
def test_usuario_invalido_rechazado(entrada):
    with pytest.raises(ErrorValidacion):
        validar_usuario_osint(entrada)


# ---------------------------------------------------------------------------
# Autorizacion sobre datos personales
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tipo", ["correo", "telefono", "usuario"])
def test_tipos_personales_requieren_autorizacion(tipo):
    assert requiere_autorizacion_datos_personales(tipo) is True
    with pytest.raises(ErrorAutorizacionOSINTRequerida):
        verificar_autorizacion_datos_personales(tipo, autorizado=False)
    verificar_autorizacion_datos_personales(tipo, autorizado=True)  # no lanza


def test_dominio_no_requiere_autorizacion_de_datos_personales():
    assert requiere_autorizacion_datos_personales("dominio") is False
    verificar_autorizacion_datos_personales("dominio", autorizado=False)  # no lanza


# ---------------------------------------------------------------------------
# Derivacion de dominio por tipo de objetivo
# ---------------------------------------------------------------------------


def test_extraer_dominio_de_dominio_devuelve_el_mismo_valor():
    assert extraer_dominio_de_objetivo("dominio", "ejemplo.com") == "ejemplo.com"


def test_extraer_dominio_de_correo_devuelve_la_parte_derecha():
    assert extraer_dominio_de_objetivo("correo", "usuario@ejemplo.com") == "ejemplo.com"


@pytest.mark.parametrize("tipo", ["telefono", "usuario"])
def test_extraer_dominio_de_tipos_sin_dominio_devuelve_none(tipo):
    assert extraer_dominio_de_objetivo(tipo, "algo") is None
