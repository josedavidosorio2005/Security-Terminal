from __future__ import annotations

from eurabyte_security.marca import (
    ABREVIATURA,
    EMPRESA,
    ESCUDO_ASCII,
    ESCUDO_COMPACTO,
    NOMBRE_PRODUCTO,
)
from eurabyte_security.ui.tui.app import AuraByteApp


def test_nombre_de_marca_exacto():
    assert EMPRESA == "AURABYTE"
    assert NOMBRE_PRODUCTO == "AURABYTE Security Terminal"
    assert ABREVIATURA == "AST"


def test_escudos_son_ascii_puro_compatibles_con_windows_y_linux():
    """El escudo debe verse igual en cualquier terminal: sin Unicode extendido."""
    for caracter in ESCUDO_COMPACTO:
        assert ord(caracter) < 128, f"'{caracter}' no es ASCII puro"
    for caracter in ESCUDO_ASCII:
        assert ord(caracter) < 128, f"'{caracter}' no es ASCII puro"


def test_escudo_compacto_es_una_sola_linea():
    assert "\n" not in ESCUDO_COMPACTO


async def test_encabezado_muestra_el_escudo_compacto():
    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        logo = app.query_one("#encabezado .logo")
        assert str(logo.render()) == ESCUDO_COMPACTO
        assert "logo" in logo.classes


async def test_panel_inicio_muestra_el_escudo_ampliado():
    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        escudo = app.query_one("#inicio-escudo")
        assert str(escudo.render()) == ESCUDO_ASCII


async def test_titulo_de_la_app_usa_el_nombre_completo():
    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        assert app.title == f"{NOMBRE_PRODUCTO} ({ABREVIATURA})"
