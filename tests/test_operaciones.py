import pytest

from eurabyte_security.core.errores import ErrorValidacion
from eurabyte_security.storage.operaciones import Operaciones


def test_ciclo_y_aislamiento():
    db = Operaciones()
    primero = db.crear_proyecto("primero").id
    otro = db.crear_proyecto("otro").id
    caso = db.crear(primero, "equipo", "hallazgo", "media", "evidencia")
    with pytest.raises(ErrorValidacion):
        db.detalle(otro, caso)
    with pytest.raises(ErrorValidacion):
        db.registrar(primero, caso, "verificar", "pendiente")
    db.registrar(primero, caso, "corregir", "configuración actualizada")
    db.registrar(primero, caso, "verificar", "revisión independiente")
    assert Operaciones().detalle(primero, caso)["estado"] == "verificado"
    db.registrar(primero, caso, "reabrir", "nueva evidencia")
    assert db.listar(primero, "equipo")[0]["estado"] == "abierto"
    assert db.listar(otro) == []


def test_correlacion_de_ejercicio():
    db = Operaciones()
    proyecto = db.crear_proyecto("laboratorio").id
    caso = db.crear(proyecto, "equipo", "ensayo", "baja", "inicio")
    evento = db.registrar(proyecto, caso, "ejercicio", "prueba", "2026-01-01T09:00:00-05:00")
    db.registrar(proyecto, caso, "deteccion", "alerta", "2026-01-01T14:00:11Z", evento)
    alerta = next(e for e in db.detalle(proyecto, caso)["eventos"] if e["tipo"] == "deteccion")
    assert alerta["segundos_hasta_deteccion"] == 11


async def test_cambio_de_proyecto_limpia_formulario():
    from textual.widgets import Input, Static

    from eurabyte_security.commands.proyecto import crear_proyecto
    from eurabyte_security.ui.tui.app import AuraByteApp

    db = Operaciones()
    crear_proyecto(db, "primero")
    app = AuraByteApp()
    async with app.run_test() as pilot:
        app._mostrar_panel("panel-operaciones")
        app.query_one("#ops-evidencia", Input).value = "evidencia del primero"
        app.query_one("#ops-detalle", Static).update("caso anterior")
        crear_proyecto(db, "segundo")
        app.refrescar_estado()
        await pilot.pause()
        assert app.query_one("#ops-evidencia", Input).value == ""
        assert "caso anterior" not in str(app.query_one("#ops-detalle", Static).render())


async def test_crea_y_consulta_un_caso_en_pestanas():
    from textual.widgets import Input, Static, TabbedContent

    from eurabyte_security.commands.proyecto import crear_proyecto
    from eurabyte_security.ui.tui.app import AuraByteApp

    db = Operaciones()
    proyecto = crear_proyecto(db, "laboratorio")
    app = AuraByteApp()
    async with app.run_test(size=(120, 35)) as pilot:
        app._mostrar_panel("panel-operaciones")
        await pilot.pause()
        for selector, valor in (
            ("#ops-activo", "equipo"),
            ("#ops-titulo", "Hallazgo local"),
            ("#ops-evidencia", "Evidencia inicial"),
        ):
            app.query_one(selector, Input).value = valor
        assert await pilot.click("#ops-crear", offset=(2, 1))
        await pilot.pause()

        numero = app.query_one("#ops-caso", Input).value
        assert db.detalle(proyecto.id, int(numero))["titulo"] == "Hallazgo local"

        pestanas = app.query_one("#ops-pestanas", TabbedContent)
        assert await pilot.click(pestanas.get_tab("ops-tab-cronologia"))
        await pilot.pause()
        assert app.query_one("#ops-caso", Input).value == numero
        assert await pilot.click("#ops-ver", offset=(2, 1))
        await pilot.pause()
        assert "Hallazgo local" in str(app.query_one("#ops-detalle", Static).render())


async def test_monitoreo_muestra_sus_controles_en_terminal_compacta():
    from textual.widgets import Button, Static, TabbedContent

    from eurabyte_security.commands.proyecto import crear_proyecto
    from eurabyte_security.ui.tui.app import AuraByteApp

    crear_proyecto(Operaciones(), "laboratorio")
    app = AuraByteApp()
    async with app.run_test(size=(80, 24)) as pilot:
        app._mostrar_panel("panel-operaciones")
        await pilot.pause()
        pestanas = app.query_one("#ops-pestanas", TabbedContent)
        assert await pilot.click(pestanas.get_tab("ops-tab-monitoreo"))
        await pilot.pause()
        inicio = app.query_one("#ops-vigilar", Button)
        assert inicio.region.bottom <= app.query_one("#ops-mensaje").region.y
        assert await pilot.click("#ops-mediciones", offset=(2, 1))
        await pilot.pause()
        assert "Todavía no hay mediciones" in str(app.query_one("#ops-monitor", Static).render())
