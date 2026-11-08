"""Verifica que la interfaz visual no recorte controles esenciales en ningun tamano.

Reproduce, como prueba automatizada, la verificacion visual pedida para el rediseno de
la interfaz: 80x24, 100x30, 120x35 y 160x45. No usa capturas de pantalla (eso se hizo
manualmente con ``App.export_screenshot`` para las capturas de docs/capturas/); aqui se
comprueba la region real (x/y/ancho/alto) de los widgets clave con ``Widget.region``, que
es la misma fuente que detecto el bug original del encabezado (ver docs/ROADMAP.md).
"""

from __future__ import annotations

import pytest
from textual.widgets import ContentSwitcher

from eurabyte_security.ui.tui.app import AuraByteApp

TAMANOS = [(80, 24), (100, 30), (120, 35), (160, 45)]


def _dentro_de_pantalla(region, ancho: int, alto: int) -> bool:
    return (
        region.x >= 0
        and region.y >= 0
        and region.right <= ancho
        and region.bottom <= alto
        and region.width > 0
        and region.height > 0
    )


@pytest.mark.parametrize("ancho,alto", TAMANOS)
async def test_encabezado_nombre_siempre_visible(ancho, alto):
    """Regresion del bug: '.nombre' quedaba casi totalmente fuera de pantalla."""
    app = AuraByteApp()
    async with app.run_test(size=(ancho, alto)) as pilot:
        await pilot.pause()
        nombre = app.query_one(".nombre")
        assert _dentro_de_pantalla(nombre.region, ancho, alto), (
            f"'.nombre' fuera de pantalla en {ancho}x{alto}: {nombre.region}"
        )


@pytest.mark.parametrize("ancho,alto", TAMANOS)
async def test_barra_lateral_y_switcher_no_se_superponen(ancho, alto):
    app = AuraByteApp()
    async with app.run_test(size=(ancho, alto)) as pilot:
        await pilot.pause()
        barra = app.query_one("#barra-lateral")
        switcher = app.query_one("#switcher-central", ContentSwitcher)
        assert barra.region.right <= switcher.region.x
        assert _dentro_de_pantalla(barra.region, ancho, alto)
        assert _dentro_de_pantalla(switcher.region, ancho, alto)


@pytest.mark.parametrize("ancho,alto", TAMANOS)
async def test_formulario_de_proyectos_accesible_sin_recortes(ancho, alto):
    """Los controles del primer formulario que ve el usuario quedan dentro de la pantalla."""
    app = AuraByteApp()
    async with app.run_test(size=(ancho, alto)) as pilot:
        await pilot.pause()
        app.query_one("#switcher-central", ContentSwitcher).current = "panel-proyectos"
        await pilot.pause()
        for selector in ("#proy-nombre", "#proy-crear"):
            widget = app.query_one(selector)
            assert _dentro_de_pantalla(widget.region, ancho, alto), (
                f"{selector} fuera de pantalla en {ancho}x{alto}: {widget.region}"
            )


@pytest.mark.parametrize("ancho,alto", TAMANOS)
async def test_panel_vulnerabilidades_controles_clave_accesibles(ancho, alto):
    """El formulario y los botones de Nuclei quedan accesibles, no solo tras mucho scroll."""
    app = AuraByteApp()
    async with app.run_test(size=(ancho, alto)) as pilot:
        await pilot.pause()
        app.query_one("#switcher-central", ContentSwitcher).current = "panel-vulnerabilidades"
        await pilot.pause()
        panel = app.query_one("#panel-vulnerabilidades")
        for selector in (
            "#nuclei-plantillas",
            "#nuclei-seleccionar-todas",
            "#nuclei-objetivo",
            "#nuclei-analizar",
        ):
            widget = panel.query_one(selector)
            assert widget.region.width > 0 and widget.region.height > 0, (
                f"{selector} sin region visible en {ancho}x{alto}"
            )
