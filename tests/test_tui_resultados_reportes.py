"""Pruebas de los paneles unificados 'Resultados' y 'Reportes' de la interfaz visual.

Usan datos simulados insertados directamente en la base de datos (igual que
``tests/test_resultados_unificados.py``): ninguna requiere Nmap, Nuclei ni OWASP ZAP
instalados.
"""

from __future__ import annotations

from textual.widgets import ContentSwitcher, DataTable, Input, Select

from eurabyte_security.commands._comun import obtener_base_datos
from eurabyte_security.ui.tui.app import AuraByteApp


async def _escribir(pilot, texto: str) -> None:
    for caracter in texto:
        await pilot.press(caracter)


async def _clic_centro(pilot, selector: str) -> bool:
    boton = pilot.app.query_one(selector)
    return await pilot.click(boton, offset=(max(boton.region.width // 2, 1), 1))


async def _crear_proyecto(pilot, nombre: str) -> None:
    app = pilot.app
    app.query_one("#switcher-central", ContentSwitcher).current = "panel-proyectos"
    await pilot.pause()
    app.query_one("#proy-nombre", Input).focus()
    await _escribir(pilot, nombre)
    await _clic_centro(pilot, "#proy-crear")
    await pilot.pause()


def _sembrar_cinco_fuentes(nombre_proyecto: str) -> None:
    base_datos = obtener_base_datos()
    proyecto = base_datos.obtener_proyecto_por_nombre(nombre_proyecto)
    base_datos.agregar_resultado(proyecto.id, "127.0.0.1", 22, "abierto")
    base_datos.agregar_resultados_nmap(
        proyecto.id, "127.0.0.1", [(80, "tcp", "open", "http", None)]
    )
    base_datos.agregar_resultados_web(
        proyecto.id,
        "https://127.0.0.1/",
        "cabeceras",
        [("cabeceras", "Hallazgo web", "alta", "detectado", None, "r", "rec", "ref")],
    )
    base_datos.agregar_resultados_nuclei(
        proyecto.id, "127.0.0.1", [("tpl-1", "v1", "Hallazgo nuclei", "high", "d", None)]
    )
    base_datos.agregar_resultados_zap(
        proyecto.id,
        "http://127.0.0.1/",
        [("10020", "Hallazgo zap", "Medium", "High", "d", None, "s", "r")],
    )


async def test_panel_resultados_muestra_las_cinco_fuentes():
    app = AuraByteApp()
    async with app.run_test(size=(120, 80)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "res-unificados")
        _sembrar_cinco_fuentes("res-unificados")

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-resultados"
        await pilot.pause()
        await _clic_centro(pilot, "#res-refrescar")
        await pilot.pause()

        tabla = app.query_one("#panel-resultados").query_one("#res-tabla", DataTable)
        assert tabla.row_count == 5


async def test_panel_resultados_filtra_por_herramienta():
    app = AuraByteApp()
    async with app.run_test(size=(120, 80)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "res-filtro")
        _sembrar_cinco_fuentes("res-filtro")

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-resultados"
        await pilot.pause()
        panel = app.query_one("#panel-resultados")
        panel.query_one("#res-fuente", Select).value = "nuclei"
        await pilot.pause()

        tabla = panel.query_one("#res-tabla", DataTable)
        assert tabla.row_count == 1


async def test_panel_resultados_no_mezcla_proyectos():
    app = AuraByteApp()
    async with app.run_test(size=(120, 80)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "res-proyecto-a")
        _sembrar_cinco_fuentes("res-proyecto-a")
        await _crear_proyecto(pilot, "res-proyecto-b")

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-resultados"
        await pilot.pause()
        await _clic_centro(pilot, "#res-refrescar")
        await pilot.pause()

        tabla = app.query_one("#panel-resultados").query_one("#res-tabla", DataTable)
        assert tabla.row_count == 0


async def test_panel_reportes_genera_informe_global(tmp_path, monkeypatch):
    from eurabyte_security.commands import reporte as modulo_reporte

    monkeypatch.setattr(modulo_reporte, "ruta_reportes", lambda: tmp_path)

    app = AuraByteApp()
    async with app.run_test(size=(120, 80)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "rep-global")
        _sembrar_cinco_fuentes("rep-global")

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-reportes"
        await pilot.pause()
        await _clic_centro(pilot, "#rep-generar")
        await pilot.pause()

        mensaje = str(app.query_one("#rep-mensaje").render()).lower()
        assert "informe global generado" in mensaje
        archivos = list(tmp_path.glob("informe-global-*.html"))
        assert len(archivos) == 1
