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
