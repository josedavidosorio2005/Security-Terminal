"""Pruebas de minimizacion de datos personales (``core/osint/redaccion.py``)."""

from __future__ import annotations

from eurabyte_security.core.osint.redaccion import (
    enmascarar_correo,
    enmascarar_telefono,
    enmascarar_usuario,
    minimizar_objetivo,
)


def test_enmascarar_correo_conserva_dominio():
    assert enmascarar_correo("usuario@ejemplo.com") == "u***o@ejemplo.com"


def test_enmascarar_correo_local_corto_se_oculta_del_todo():
    assert enmascarar_correo("ab@ejemplo.com") == "***@ejemplo.com"


def test_enmascarar_correo_sin_arroba_se_oculta_del_todo():
    assert enmascarar_correo("no-es-un-correo") == "***"


def test_enmascarar_telefono_conserva_extremos():
    resultado = enmascarar_telefono("+573001234567")
    assert resultado.startswith("+57")
    assert resultado.endswith("67")
    assert "3001234" not in resultado


def test_enmascarar_telefono_invalido_se_oculta_del_todo():
    assert enmascarar_telefono("no-es-un-telefono") == "***"


def test_enmascarar_usuario():
    assert enmascarar_usuario("torvalds") == "t***s"
    assert enmascarar_usuario("ab") == "***"


def test_minimizar_objetivo_dominio_no_se_oculta():
    assert minimizar_objetivo("dominio", "ejemplo.com") == "ejemplo.com"


def test_minimizar_objetivo_correo_se_oculta():
    assert minimizar_objetivo("correo", "usuario@ejemplo.com") == "u***o@ejemplo.com"


def test_minimizar_objetivo_tipo_desconocido_se_devuelve_tal_cual():
    assert minimizar_objetivo("otro", "valor") == "valor"
