"""Pruebas del panel 'OSINT' de la interfaz visual.

``ejecutar_investigacion_osint``/``generar_reporte_osint`` (tal como se importan en
``widgets/paneles.py``) se sustituyen por dobles: ninguna prueba consulta una fuente
OSINT real.
"""

from __future__ import annotations

import time
import types

from textual.widgets import (
    Button,
    ContentSwitcher,
    DataTable,
    Input,
    Select,
    SelectionList,
    TabbedContent,
)

from eurabyte_security.core.errores import ErrorInvestigacionOSINTCancelada
from eurabyte_security.ui.tui.app import AuraByteApp
from eurabyte_security.ui.tui.widgets import paneles as modulo_paneles

TAMANO = (120, 60)


async def _clic_centro(pilot, selector: str) -> bool:
    boton = pilot.app.query_one(selector)
    return await pilot.click(boton, offset=(max(boton.region.width // 2, 1), 1))


async def _escribir(pilot, texto: str) -> None:
    for caracter in texto:
        await pilot.press(caracter)


async def _crear_proyecto(pilot, nombre: str) -> None:
    app = pilot.app
    app.query_one("#switcher-central", ContentSwitcher).current = "panel-proyectos"
    await pilot.pause()
    app.query_one("#proy-nombre", Input).focus()
    await _escribir(pilot, nombre)
    await _clic_centro(pilot, "#proy-crear")
    await pilot.pause()


async def _abrir_panel_osint(pilot) -> None:
    pilot.app.query_one("#switcher-central", ContentSwitcher).current = "panel-osint"
    await pilot.pause()


async def _abrir_pestana_informe(pilot) -> None:
    pilot.app.query_one("#osint-tabs", TabbedContent).active = "osint-tab-informe"
    await pilot.pause()


def _resultado_falso(investigacion_id=1, estado_general="completada", limitaciones=()):
    return types.SimpleNamespace(
        investigacion_id=investigacion_id,
        estado_general=estado_general,
        etapas=(),
        limitaciones=tuple(limitaciones),
        total_hallazgos=0,
    )


def _resultado_persistido(
    base_datos, proyecto, tipo, objetivo, estado_general="completada", etapas=()
):
    """Como ``_resultado_falso``, pero crea de verdad la fila en
    ``investigaciones_osint`` -- el motor real siempre persiste antes de devolver su
    resultado, y ``PanelOSINT._mostrar_resultado`` vuelve a leer de la base de datos
    (en vez de confiar ciegamente en el objeto en memoria) para mostrar exactamente lo
    guardado y para poder recuperar la misma investigacion mas tarde desde el
    historial. Un doble que no persiste nada no refleja ese comportamiento real. Las
    ``etapas`` deben coincidir con las que el doble haya reportado por
    ``callback_progreso``: el motor real persiste esa misma lista antes de devolver el
    resultado (ver ``modulo/osint/motor.py``), asi que la tabla de etapas que ya se
    poblo en vivo durante la ejecucion no debe quedar vacia al recargar desde la base
    de datos al terminar."""
    investigacion = base_datos.crear_investigacion_osint(
        proyecto.id, tipo, objetivo, objetivo, False, []
    )
    base_datos.actualizar_investigacion_osint(
        investigacion.id, estado_general=estado_general, etapas=list(etapas), limitaciones=[]
    )
    return _resultado_falso(investigacion_id=investigacion.id, estado_general=estado_general)


async def test_panel_osint_requiere_objetivo():
    app = AuraByteApp()
    async with app.run_test(size=TAMANO) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "osint-sin-objetivo")
        await _abrir_panel_osint(pilot)

        await _clic_centro(pilot, "#osint-iniciar")
        await pilot.pause()

        mensaje = str(app.query_one("#osint-mensaje").render()).lower()
        assert "objetivo" in mensaje


async def test_panel_osint_correo_sin_autorizar_muestra_aviso():
    app = AuraByteApp()
    async with app.run_test(size=TAMANO) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "osint-sin-autorizar")
        await _abrir_panel_osint(pilot)

        app.query_one("#osint-tipo", Select).value = "correo"
        await pilot.pause()
        app.query_one("#osint-objetivo", Input).focus()
        await _escribir(pilot, "usuario@ejemplo.com")
        # Deliberadamente NO se marca la casilla de autorizacion.

        await _clic_centro(pilot, "#osint-iniciar")
        await pilot.pause()

        mensaje = str(app.query_one("#osint-mensaje").render()).lower()
        assert "autorizacion" in mensaje


async def test_panel_osint_dominio_no_requiere_autorizacion_y_ejecuta(monkeypatch):
    def _fake(base_datos, proyecto, tipo, objetivo, **kwargs):
        progreso = kwargs.get("callback_progreso")
        etapa = {"fuente": "dns", "estado": "completada", "detalle": "1 hallazgo(s)."}
        if progreso is not None:
            progreso(types.SimpleNamespace(**etapa))
        return _resultado_persistido(base_datos, proyecto, tipo, objetivo, etapas=[etapa])

    monkeypatch.setattr(modulo_paneles, "ejecutar_investigacion_osint", _fake)

    app = AuraByteApp()
    async with app.run_test(size=TAMANO) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "osint-dominio")
        await _abrir_panel_osint(pilot)

        app.query_one("#osint-objetivo", Input).focus()
        await _escribir(pilot, "ejemplo.com")

        await _clic_centro(pilot, "#osint-iniciar")
        await app.workers.wait_for_complete()
        await pilot.pause()

        tabla = app.query_one("#osint-tabla-etapas", DataTable)
        assert tabla.row_count == 1
        mensaje = str(app.query_one("#osint-mensaje").render()).lower()
        assert "completa" in mensaje


async def test_panel_osint_cancelar_detiene_la_investigacion(monkeypatch):
    def _tarda(base_datos, proyecto, tipo, objetivo, **kwargs):
        debe_cancelar = kwargs.get("debe_cancelar")
        for _ in range(100):
            if debe_cancelar is not None and debe_cancelar():
                raise ErrorInvestigacionOSINTCancelada("cancelado")
            time.sleep(0.02)
        return _resultado_falso()

    monkeypatch.setattr(modulo_paneles, "ejecutar_investigacion_osint", _tarda)

    app = AuraByteApp()
    async with app.run_test(size=TAMANO) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "osint-cancelar")
        await _abrir_panel_osint(pilot)

        app.query_one("#osint-objetivo", Input).focus()
        await _escribir(pilot, "ejemplo.com")
        await _clic_centro(pilot, "#osint-iniciar")
        await pilot.pause()

        await _clic_centro(pilot, "#osint-cancelar")
        await app.workers.wait_for_complete()
        await pilot.pause()

        mensaje = str(app.query_one("#osint-mensaje").render()).lower()
        assert "cancelada" in mensaje


async def test_panel_osint_error_inesperado_no_cierra_la_interfaz(monkeypatch):
    def _falla(*_args, **_kwargs):
        raise RuntimeError("fallo simulado")

    monkeypatch.setattr(modulo_paneles, "ejecutar_investigacion_osint", _falla)

    app = AuraByteApp()
    async with app.run_test(size=TAMANO) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "osint-error")
        await _abrir_panel_osint(pilot)

        app.query_one("#osint-objetivo", Input).focus()
        await _escribir(pilot, "ejemplo.com")
        await _clic_centro(pilot, "#osint-iniciar")
        await app.workers.wait_for_complete()
        await pilot.pause()

        assert app.is_running
        mensaje = str(app.query_one("#osint-mensaje").render()).lower()
        assert "error inesperado" in mensaje


async def test_panel_osint_tabla_fuentes_poblada_en_mount():
    app = AuraByteApp()
    async with app.run_test(size=TAMANO) as pilot:
        await pilot.pause()
        await _abrir_panel_osint(pilot)

        tabla = app.query_one("#osint-tabla-fuentes", DataTable)
        assert tabla.row_count > 0


async def test_panel_osint_cambiar_tipo_repuebla_fuentes():
    app = AuraByteApp()
    async with app.run_test(size=TAMANO) as pilot:
        await pilot.pause()
        await _abrir_panel_osint(pilot)

        selector = app.query_one("#osint-fuentes", SelectionList)
        opciones_dominio = selector.option_count

        app.query_one("#osint-tipo", Select).value = "usuario"
        await pilot.pause()

        opciones_usuario = selector.option_count
        assert opciones_usuario != opciones_dominio
        assert opciones_usuario > 0


async def test_panel_osint_generar_informe_sin_investigacion_muestra_aviso():
    app = AuraByteApp()
    async with app.run_test(size=TAMANO) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "osint-informe-vacio")
        await _abrir_panel_osint(pilot)
        await _abrir_pestana_informe(pilot)

        app.query_one("#osint-informe-generar", Button).press()
        await pilot.pause()

        mensaje = str(app.query_one("#osint-informe-mensaje").render()).lower()
        assert "primero" in mensaje


async def test_panel_osint_generar_informe_genera_archivo(monkeypatch, tmp_path):
    def _fake(base_datos, proyecto, tipo, objetivo, **kwargs):
        return _resultado_persistido(base_datos, proyecto, tipo, objetivo)

    def _fake_reporte(
        base_datos, proyecto, investigacion_id, formato, *, minimizar=False, salida=None
    ):
        ruta = tmp_path / f"informe.{formato}"
        ruta.write_text("contenido", encoding="utf-8")
        return ruta

    monkeypatch.setattr(modulo_paneles, "ejecutar_investigacion_osint", _fake)
    monkeypatch.setattr(modulo_paneles, "generar_reporte_osint", _fake_reporte)

    app = AuraByteApp()
    async with app.run_test(size=TAMANO) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "osint-informe")
        await _abrir_panel_osint(pilot)

        app.query_one("#osint-objetivo", Input).focus()
        await _escribir(pilot, "ejemplo.com")
        await _clic_centro(pilot, "#osint-iniciar")
        await app.workers.wait_for_complete()
        await pilot.pause()
        await _abrir_pestana_informe(pilot)

        app.query_one("#osint-informe-generar", Button).press()
        # 'press()' solo encola el mensaje Button.Pressed; hace falta un 'pause()' para
        # que la cola de mensajes se procese y el worker realmente arranque ANTES de
        # esperar a que termine (si no, 'wait_for_complete()' puede no ver ningun
        # worker en marcha todavia y devolver de inmediato -- carrera real observada
        # en CI sobre Windows, no reproducida siempre en local).
        await pilot.pause()
        await app.workers.wait_for_complete()
        await pilot.pause()

        mensaje = str(app.query_one("#osint-informe-mensaje").render()).lower()
        assert "informe generado" in mensaje


async def test_osint_aparece_en_la_barra_lateral():
    from eurabyte_security.ui.tui.widgets.navegacion import BarraLateral

    app = AuraByteApp()
    async with app.run_test(size=TAMANO) as pilot:
        await pilot.pause()
        opciones = [str(o.prompt) for o in app.query_one(BarraLateral).options]
        assert "OSINT" in opciones
