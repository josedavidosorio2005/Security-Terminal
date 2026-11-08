"""Pruebas del panel 'OWASP ZAP' de la interfaz visual.

``ejecutar_zap_pasivo`` (tal como se importa en ``widgets/paneles.py``) se sustituye por
un doble en la mayoria de estas pruebas: nunca se llama a una API de ZAP real desde la
TUI.
"""

from __future__ import annotations

import time

from textual.widgets import Checkbox, ContentSwitcher, DataTable, Input

from eurabyte_security.core.errores import ErrorEscaneoCancelado
from eurabyte_security.storage.database import ResultadoZAP
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


def _hallazgo_guardado(id_=1, plugin_id="10020", riesgo="Medium", estado="nuevo"):
    return ResultadoZAP(
        id=id_,
        proyecto_id=1,
        objetivo="http://127.0.0.1/pagina",
        plugin_id=plugin_id,
        nombre_hallazgo="Missing Anti-clickjacking Header",
        riesgo=riesgo,
        confianza="High",
        descripcion="desc",
        evidencia="",
        solucion="Agrega la cabecera X-Frame-Options.",
        referencia="https://owasp.org/",
        estado_revision=estado,
        creado_en="2026-01-01T00:00:00+00:00",
    )


async def _preparar_panel(pilot, objetivo: str = "http://127.0.0.1/pagina") -> None:
    app = pilot.app
    app.query_one("#switcher-central", ContentSwitcher).current = "panel-zap"
    await pilot.pause()
    app.query_one("#zap-objetivo", Input).focus()
    await _escribir(pilot, objetivo)
    app.query_one("#zap-confirmar", Checkbox).value = True
    await pilot.pause()


async def test_panel_zap_ejecuta_y_muestra_hallazgos(monkeypatch):
    guardados_falsos = [_hallazgo_guardado()]

    def ejecutar_zap_falso(base_datos, proyecto, objetivo, *,
                            tiempo_limite=60.0, guardar_evidencia=True, debe_cancelar=None):
        return None, guardados_falsos

    monkeypatch.setattr(modulo_paneles, "ejecutar_zap_pasivo", ejecutar_zap_falso)

    app = AuraByteApp()
    async with app.run_test(size=(120, 80)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "zap-tui")
        await _preparar_panel(pilot)

        await _clic_centro(pilot, "#zap-analizar")
        await app.workers.wait_for_complete()
        await pilot.pause()

        tabla = app.query_one("#zap-tabla", DataTable)
        assert tabla.row_count == 1
        mensaje = str(app.query_one("#zap-mensaje").render())
        assert "completo" in mensaje.lower()


async def test_panel_zap_exige_confirmacion_antes_de_analizar(monkeypatch):
    llamado = {"veces": 0}

    def ejecutar_zap_falso(*args, **kwargs):
        llamado["veces"] += 1
        return None, []

    monkeypatch.setattr(modulo_paneles, "ejecutar_zap_pasivo", ejecutar_zap_falso)

    app = AuraByteApp()
    async with app.run_test(size=(120, 80)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "zap-sin-confirmar")

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-zap"
        await pilot.pause()
        app.query_one("#zap-objetivo", Input).focus()
        await _escribir(pilot, "http://127.0.0.1/pagina")
        # Deliberadamente NO se marca la casilla de confirmacion.

        await _clic_centro(pilot, "#zap-analizar")
        await pilot.pause()

        assert llamado["veces"] == 0
        mensaje = str(app.query_one("#zap-mensaje").render()).lower()
        assert "confirma" in mensaje


async def test_panel_zap_exige_objetivo(monkeypatch):
    llamado = {"veces": 0}

    def ejecutar_zap_falso(*args, **kwargs):
        llamado["veces"] += 1
        return None, []

    monkeypatch.setattr(modulo_paneles, "ejecutar_zap_pasivo", ejecutar_zap_falso)

    app = AuraByteApp()
    async with app.run_test(size=(120, 80)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "zap-sin-objetivo")

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-zap"
        await pilot.pause()
        app.query_one("#zap-confirmar", Checkbox).value = True
        # Deliberadamente no se escribe ningun objetivo.

        await _clic_centro(pilot, "#zap-analizar")
        await pilot.pause()

        assert llamado["veces"] == 0


async def test_panel_zap_cancelar_no_guarda_nada(monkeypatch):
    def ejecutar_zap_que_tarda(base_datos, proyecto, objetivo, *,
                               tiempo_limite=60.0, guardar_evidencia=True, debe_cancelar=None):
        for _ in range(100):
            if debe_cancelar is not None and debe_cancelar():
                raise ErrorEscaneoCancelado(f"El analisis de '{objetivo}' se cancelo.")
            time.sleep(0.02)
        raise AssertionError("Deberia haberse cancelado antes de este punto.")

    monkeypatch.setattr(modulo_paneles, "ejecutar_zap_pasivo", ejecutar_zap_que_tarda)

    app = AuraByteApp()
    async with app.run_test(size=(120, 80)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "zap-cancelar")
        await _preparar_panel(pilot)

        await _clic_centro(pilot, "#zap-analizar")
        await pilot.pause()
        await _clic_centro(pilot, "#zap-cancelar")
        await app.workers.wait_for_complete()
        await pilot.pause()

        assert app.query_one("#zap-tabla", DataTable).row_count == 0
        mensaje = str(app.query_one("#zap-mensaje").render()).lower()
        assert "cancel" in mensaje


async def test_panel_zap_error_inesperado_no_cierra_la_interfaz(monkeypatch):
    def ejecutar_zap_roto(*args, **kwargs):
        raise RuntimeError("fallo interno simulado en zap")

    monkeypatch.setattr(modulo_paneles, "ejecutar_zap_pasivo", ejecutar_zap_roto)

    app = AuraByteApp()
    async with app.run_test(size=(120, 80)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "zap-roto")
        await _preparar_panel(pilot)

        await _clic_centro(pilot, "#zap-analizar")
        await app.workers.wait_for_complete()
        await pilot.pause()

        mensaje = str(app.query_one("#zap-mensaje").render())
        assert "inesperado" in mensaje.lower()

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-proyectos"
        await pilot.pause()
        assert app.query_one("#switcher-central", ContentSwitcher).current == "panel-proyectos"


async def test_dos_analisis_de_zap_consecutivos_no_mezclan_resultados(monkeypatch):
    def ejecutar_zap_falso(base_datos, proyecto, objetivo, *,
                            tiempo_limite=60.0, guardar_evidencia=True, debe_cancelar=None):
        if objetivo == "http://10.0.0.1/pagina":
            time.sleep(0.3)
            return None, [_hallazgo_guardado(id_=1)]
        return None, [_hallazgo_guardado(id_=2), _hallazgo_guardado(id_=3)]

    monkeypatch.setattr(modulo_paneles, "ejecutar_zap_pasivo", ejecutar_zap_falso)

    app = AuraByteApp()
    async with app.run_test(size=(120, 80)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "zap-consecutivos")

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-zap"
        await pilot.pause()
        app.query_one("#zap-confirmar", Checkbox).value = True

        objetivo_campo = app.query_one("#zap-objetivo", Input)
        objetivo_campo.focus()
        await _escribir(pilot, "http://10.0.0.1/pagina")
        await _clic_centro(pilot, "#zap-analizar")
        await pilot.pause()

        objetivo_campo.value = ""
        objetivo_campo.focus()
        await _escribir(pilot, "http://10.0.0.2/pagina")
        await _clic_centro(pilot, "#zap-analizar")

        await app.workers.wait_for_complete()
        await pilot.pause()

        tabla = app.query_one("#zap-tabla", DataTable)
        assert tabla.row_count == 2


async def test_panel_zap_marcar_falso_positivo_actualiza_tabla(monkeypatch):
    """Usa la logica real de persistencia/revision (solo se simula la API de ZAP)."""
    from eurabyte_security.modules.vulnerability import zap as zap_modulo

    def _peticion_falsa(configuracion, ruta, parametros, *, tiempo_limite):
        if ruta == "/JSON/core/view/version/":
            return {"version": "2.14.0"}
        if ruta == "/JSON/core/action/accessUrl/":
            return {"accessUrl": "OK"}
        if ruta == "/JSON/pscan/view/recordsToScan/":
            return {"recordsToScan": "0"}
        if ruta == "/JSON/core/view/alerts/":
            return {
                "alerts": [
                    {
                        "pluginId": "10020",
                        "name": "Missing Anti-clickjacking Header",
                        "risk": "Medium",
                        "confidence": "High",
                        "url": "http://127.0.0.1/pagina",
                        "evidence": "",
                        "description": "d",
                        "solution": "s",
                        "reference": "r",
                    }
                ]
            }
        raise AssertionError(ruta)

    monkeypatch.setattr(zap_modulo, "_peticion_zap", _peticion_falsa)
    monkeypatch.setattr(zap_modulo.time, "sleep", lambda *_a, **_k: None)

    app = AuraByteApp()
    async with app.run_test(size=(120, 80)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "zap-revision")

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-alcance"
        await pilot.pause()
        app.query_one("#alc-objetivo", Input).focus()
        await _escribir(pilot, "127.0.0.1/32")
        await _clic_centro(pilot, "#alc-agregar")
        await pilot.pause()

        await _preparar_panel(pilot)
        await _clic_centro(pilot, "#zap-analizar")
        await app.workers.wait_for_complete()
        await pilot.pause()

        tabla = app.query_one("#zap-tabla", DataTable)
        assert tabla.row_count == 1

        tabla.focus()
        tabla.cursor_coordinate = (0, 0)
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()

        await _clic_centro(pilot, "#zap-marcar-falso-positivo")
        await pilot.pause()

        mensaje = str(app.query_one("#zap-mensaje").render()).lower()
        assert "falso_positivo" in mensaje
