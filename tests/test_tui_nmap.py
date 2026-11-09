"""Pruebas del panel 'Reconocimiento' (Nmap) de la interfaz visual.

``ejecutar_nmap`` (tal como se importa en ``widgets/paneles.py``) se sustituye
por un doble en cada prueba: nunca se ejecuta Nmap de verdad desde la TUI.
"""

from __future__ import annotations

import time
import types

from textual.widgets import Checkbox, Collapsible, ContentSwitcher, DataTable, Input

from eurabyte_security.core.errores import ErrorEscaneoCancelado
from eurabyte_security.ui.tui.app import AuraByteApp
from eurabyte_security.ui.tui.widgets import paneles as modulo_paneles


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


async def _abrir_nmap_manual(pilot) -> None:
    """La forma manual de Nmap vive en una seccion 'avanzada' plegable, ahora que el
    panel 'Reconocimiento' tiene tambien el flujo automatico: se expande antes de
    interactuar con sus campos, igual que un usuario real haria clic para abrirla."""
    pilot.app.query_one("#reco-nmap-manual", Collapsible).collapsed = False
    await pilot.pause()


def _puerto_falso(puerto, protocolo="tcp", estado="open", servicio=None, version=None):
    return types.SimpleNamespace(
        puerto=puerto, protocolo=protocolo, estado=estado, servicio=servicio, version=version
    )


async def test_panel_reconocimiento_ejecuta_y_muestra_resultados(monkeypatch):
    resultado_falso = types.SimpleNamespace(
        objetivo="127.0.0.1",
        puertos=[
            _puerto_falso(22, servicio="ssh"),
            _puerto_falso(80, estado="closed"),
        ],
    )

    def ejecutar_nmap_falso(base_datos, proyecto, objetivo, puertos, *, deteccion_version=False,
                             tiempo_limite=120.0, guardar_evidencia=True, debe_cancelar=None):
        return resultado_falso, [], None

    monkeypatch.setattr(modulo_paneles, "ejecutar_nmap", ejecutar_nmap_falso)

    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "nmap-tui")

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-reconocimiento"
        await pilot.pause()
        await _abrir_nmap_manual(pilot)
        app.query_one("#nmap-objetivo", Input).focus()
        await _escribir(pilot, "127.0.0.1")
        app.query_one("#nmap-puertos", Input).focus()
        await _escribir(pilot, "22,80")

        await _clic_centro(pilot, "#nmap-ejecutar")
        await app.workers.wait_for_complete()
        await pilot.pause()

        tabla = app.query_one("#nmap-tabla", DataTable)
        assert tabla.row_count == 2
        mensaje = str(app.query_one("#nmap-mensaje").render())
        assert "completo" in mensaje.lower()


async def test_panel_reconocimiento_servicio_con_marcado_rich_no_crashea(monkeypatch):
    """servicio/version del objetivo escaneado se escapan antes de llegar a la tabla."""
    resultado_falso = types.SimpleNamespace(
        objetivo="127.0.0.1",
        puertos=[_puerto_falso(80, servicio="[/]", version="[bold red]x")],
    )

    def ejecutar_nmap_falso(base_datos, proyecto, objetivo, puertos, *, deteccion_version=False,
                             tiempo_limite=120.0, guardar_evidencia=True, debe_cancelar=None):
        return resultado_falso, [], None

    monkeypatch.setattr(modulo_paneles, "ejecutar_nmap", ejecutar_nmap_falso)

    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "nmap-marcado")

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-reconocimiento"
        await pilot.pause()
        await _abrir_nmap_manual(pilot)
        app.query_one("#nmap-objetivo", Input).focus()
        await _escribir(pilot, "127.0.0.1")
        app.query_one("#nmap-puertos", Input).focus()
        await _escribir(pilot, "80")

        await _clic_centro(pilot, "#nmap-ejecutar")
        await app.workers.wait_for_complete()
        await pilot.pause()

        # No debe haber reventado: la tabla tiene su fila y la app sigue viva.
        assert app.query_one("#nmap-tabla", DataTable).row_count == 1
        app.query_one("#switcher-central", ContentSwitcher).current = "panel-proyectos"
        await pilot.pause()
        assert app.query_one("#switcher-central", ContentSwitcher).current == "panel-proyectos"


async def test_panel_reconocimiento_checkbox_activa_deteccion_version(monkeypatch):
    recibido = {}

    def ejecutar_nmap_falso(base_datos, proyecto, objetivo, puertos, *, deteccion_version=False,
                             tiempo_limite=120.0, guardar_evidencia=True, debe_cancelar=None):
        recibido["deteccion_version"] = deteccion_version
        return types.SimpleNamespace(objetivo=objetivo, puertos=[]), [], None

    monkeypatch.setattr(modulo_paneles, "ejecutar_nmap", ejecutar_nmap_falso)

    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "nmap-sv")

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-reconocimiento"
        await pilot.pause()
        await _abrir_nmap_manual(pilot)
        app.query_one("#nmap-objetivo", Input).focus()
        await _escribir(pilot, "127.0.0.1")
        app.query_one("#nmap-puertos", Input).focus()
        await _escribir(pilot, "80")

        casilla = app.query_one("#nmap-deteccion-version", Checkbox)
        assert casilla.value is False
        await _clic_centro(pilot, "#nmap-deteccion-version")
        await pilot.pause()
        assert casilla.value is True

        await _clic_centro(pilot, "#nmap-ejecutar")
        await app.workers.wait_for_complete()
        await pilot.pause()

        assert recibido["deteccion_version"] is True


async def test_panel_reconocimiento_cancelar_no_guarda_nada(monkeypatch):
    def ejecutar_nmap_que_tarda(base_datos, proyecto, objetivo, puertos, *,
                                 deteccion_version=False, tiempo_limite=120.0,
                                 guardar_evidencia=True, debe_cancelar=None):
        for _ in range(100):
            if debe_cancelar is not None and debe_cancelar():
                raise ErrorEscaneoCancelado(f"El analisis de '{objetivo}' se cancelo.")
            time.sleep(0.02)
        raise AssertionError("Deberia haberse cancelado antes de este punto.")

    monkeypatch.setattr(modulo_paneles, "ejecutar_nmap", ejecutar_nmap_que_tarda)

    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "nmap-cancelar")

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-reconocimiento"
        await pilot.pause()
        await _abrir_nmap_manual(pilot)
        app.query_one("#nmap-objetivo", Input).focus()
        await _escribir(pilot, "127.0.0.1")
        app.query_one("#nmap-puertos", Input).focus()
        await _escribir(pilot, "80")

        await _clic_centro(pilot, "#nmap-ejecutar")
        await pilot.pause()
        await _clic_centro(pilot, "#nmap-cancelar")
        await app.workers.wait_for_complete()
        await pilot.pause()

        assert app.query_one("#nmap-tabla", DataTable).row_count == 0
        mensaje = str(app.query_one("#nmap-mensaje").render()).lower()
        assert "cancel" in mensaje


async def test_panel_reconocimiento_error_inesperado_no_cierra_la_interfaz(monkeypatch):
    def ejecutar_nmap_roto(*args, **kwargs):
        raise RuntimeError("fallo interno simulado en nmap")

    monkeypatch.setattr(modulo_paneles, "ejecutar_nmap", ejecutar_nmap_roto)

    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "nmap-roto")

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-reconocimiento"
        await pilot.pause()
        await _abrir_nmap_manual(pilot)
        app.query_one("#nmap-objetivo", Input).focus()
        await _escribir(pilot, "127.0.0.1")
        app.query_one("#nmap-puertos", Input).focus()
        await _escribir(pilot, "80")

        await _clic_centro(pilot, "#nmap-ejecutar")
        await app.workers.wait_for_complete()
        await pilot.pause()

        mensaje = str(app.query_one("#nmap-mensaje").render())
        assert "inesperado" in mensaje.lower()

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-proyectos"
        await pilot.pause()
        assert app.query_one("#switcher-central", ContentSwitcher).current == "panel-proyectos"


async def test_dos_analisis_de_nmap_consecutivos_no_mezclan_resultados(monkeypatch):
    def ejecutar_nmap_falso(base_datos, proyecto, objetivo, puertos, *, deteccion_version=False,
                             tiempo_limite=120.0, guardar_evidencia=True, debe_cancelar=None):
        if objetivo == "10.0.0.1":
            time.sleep(0.3)
            return types.SimpleNamespace(objetivo=objetivo, puertos=[_puerto_falso(111)]), [], None
        return types.SimpleNamespace(objetivo=objetivo, puertos=[_puerto_falso(222)]), [], None

    monkeypatch.setattr(modulo_paneles, "ejecutar_nmap", ejecutar_nmap_falso)

    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "nmap-consecutivos")

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-reconocimiento"
        await pilot.pause()
        await _abrir_nmap_manual(pilot)

        objetivo_campo = app.query_one("#nmap-objetivo", Input)
        puertos_campo = app.query_one("#nmap-puertos", Input)

        objetivo_campo.focus()
        await _escribir(pilot, "10.0.0.1")
        puertos_campo.focus()
        await _escribir(pilot, "111")
        await _clic_centro(pilot, "#nmap-ejecutar")
        await pilot.pause()

        objetivo_campo.value = ""
        objetivo_campo.focus()
        await _escribir(pilot, "10.0.0.2")
        puertos_campo.value = ""
        puertos_campo.focus()
        await _escribir(pilot, "222")
        await _clic_centro(pilot, "#nmap-ejecutar")

        await app.workers.wait_for_complete()
        await pilot.pause()

        tabla = app.query_one("#nmap-tabla", DataTable)
        assert tabla.row_count == 1
        assert tabla.get_row_at(0)[0] == "222"
