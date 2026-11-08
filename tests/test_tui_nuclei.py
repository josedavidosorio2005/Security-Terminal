"""Pruebas del panel 'Vulnerabilidades' (Nuclei) de la interfaz visual.

``ejecutar_nuclei`` (tal como se importa en ``widgets/paneles.py``) se sustituye por un
doble en la mayoria de estas pruebas: nunca se ejecuta Nuclei de verdad desde la TUI.
"""

from __future__ import annotations

import time

from textual.widgets import Checkbox, ContentSwitcher, DataTable, Input, SelectionList

from eurabyte_security.core.errores import ErrorEscaneoCancelado
from eurabyte_security.storage.database import ResultadoNuclei
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


def _hallazgo_guardado(id_=1, plantilla_id="exposed-env-file", severidad="high", estado="nuevo"):
    return ResultadoNuclei(
        id=id_,
        proyecto_id=1,
        objetivo="http://127.0.0.1:80",
        plantilla_id=plantilla_id,
        plantilla_version="1",
        nombre_hallazgo="Archivo .env expuesto",
        severidad=severidad,
        descripcion="desc",
        evidencia="http://127.0.0.1/.env (matcher: word)",
        estado_revision=estado,
        creado_en="2026-01-01T00:00:00+00:00",
    )


async def _preparar_panel(pilot, objetivo: str = "127.0.0.1") -> None:
    app = pilot.app
    app.query_one("#switcher-central", ContentSwitcher).current = "panel-vulnerabilidades"
    await pilot.pause()
    app.query_one("#nuclei-objetivo", Input).focus()
    await _escribir(pilot, objetivo)
    app.query_one("#nuclei-plantillas", SelectionList).select("exposed-env-file")
    app.query_one("#nuclei-confirmar", Checkbox).value = True
    await pilot.pause()


async def test_panel_vulnerabilidades_ejecuta_y_muestra_hallazgos(monkeypatch):
    guardados_falsos = [_hallazgo_guardado()]

    def ejecutar_nuclei_falso(base_datos, proyecto, objetivo, plantillas_ids, *,
                               tiempo_limite=60.0, guardar_evidencia=True, debe_cancelar=None):
        return None, guardados_falsos

    monkeypatch.setattr(modulo_paneles, "ejecutar_nuclei", ejecutar_nuclei_falso)

    app = AuraByteApp()
    async with app.run_test(size=(120, 80)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "nuclei-tui")
        await _preparar_panel(pilot)

        await _clic_centro(pilot, "#nuclei-analizar")
        await app.workers.wait_for_complete()
        await pilot.pause()

        tabla = app.query_one("#nuclei-tabla", DataTable)
        assert tabla.row_count == 1
        mensaje = str(app.query_one("#nuclei-mensaje").render())
        assert "completo" in mensaje.lower()


async def test_panel_vulnerabilidades_exige_confirmacion_antes_de_analizar(monkeypatch):
    llamado = {"veces": 0}

    def ejecutar_nuclei_falso(*args, **kwargs):
        llamado["veces"] += 1
        return None, []

    monkeypatch.setattr(modulo_paneles, "ejecutar_nuclei", ejecutar_nuclei_falso)

    app = AuraByteApp()
    async with app.run_test(size=(120, 80)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "nuclei-sin-confirmar")

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-vulnerabilidades"
        await pilot.pause()
        app.query_one("#nuclei-objetivo", Input).focus()
        await _escribir(pilot, "127.0.0.1")
        app.query_one("#nuclei-plantillas", SelectionList).select("exposed-env-file")
        # Deliberadamente NO se marca la casilla de confirmacion.

        await _clic_centro(pilot, "#nuclei-analizar")
        await pilot.pause()

        assert llamado["veces"] == 0
        mensaje = str(app.query_one("#nuclei-mensaje").render()).lower()
        assert "confirma" in mensaje


async def test_panel_vulnerabilidades_exige_al_menos_una_plantilla(monkeypatch):
    llamado = {"veces": 0}

    def ejecutar_nuclei_falso(*args, **kwargs):
        llamado["veces"] += 1
        return None, []

    monkeypatch.setattr(modulo_paneles, "ejecutar_nuclei", ejecutar_nuclei_falso)

    app = AuraByteApp()
    async with app.run_test(size=(120, 80)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "nuclei-sin-plantilla")

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-vulnerabilidades"
        await pilot.pause()
        app.query_one("#nuclei-objetivo", Input).focus()
        await _escribir(pilot, "127.0.0.1")
        app.query_one("#nuclei-confirmar", Checkbox).value = True
        # Deliberadamente no se selecciona ninguna plantilla.

        await _clic_centro(pilot, "#nuclei-analizar")
        await pilot.pause()

        assert llamado["veces"] == 0
        mensaje = str(app.query_one("#nuclei-mensaje").render()).lower()
        assert "plantilla" in mensaje


async def test_panel_vulnerabilidades_cancelar_no_guarda_nada(monkeypatch):
    def ejecutar_nuclei_que_tarda(base_datos, proyecto, objetivo, plantillas_ids, *,
                                   tiempo_limite=60.0, guardar_evidencia=True, debe_cancelar=None):
        for _ in range(100):
            if debe_cancelar is not None and debe_cancelar():
                raise ErrorEscaneoCancelado(f"El analisis de '{objetivo}' se cancelo.")
            time.sleep(0.02)
        raise AssertionError("Deberia haberse cancelado antes de este punto.")

    monkeypatch.setattr(modulo_paneles, "ejecutar_nuclei", ejecutar_nuclei_que_tarda)

    app = AuraByteApp()
    async with app.run_test(size=(120, 80)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "nuclei-cancelar")
        await _preparar_panel(pilot)

        await _clic_centro(pilot, "#nuclei-analizar")
        await pilot.pause()
        await _clic_centro(pilot, "#nuclei-cancelar")
        await app.workers.wait_for_complete()
        await pilot.pause()

        assert app.query_one("#nuclei-tabla", DataTable).row_count == 0
        mensaje = str(app.query_one("#nuclei-mensaje").render()).lower()
        assert "cancel" in mensaje


async def test_panel_vulnerabilidades_error_inesperado_no_cierra_la_interfaz(monkeypatch):
    def ejecutar_nuclei_roto(*args, **kwargs):
        raise RuntimeError("fallo interno simulado en nuclei")

    monkeypatch.setattr(modulo_paneles, "ejecutar_nuclei", ejecutar_nuclei_roto)

    app = AuraByteApp()
    async with app.run_test(size=(120, 80)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "nuclei-roto")
        await _preparar_panel(pilot)

        await _clic_centro(pilot, "#nuclei-analizar")
        await app.workers.wait_for_complete()
        await pilot.pause()

        mensaje = str(app.query_one("#nuclei-mensaje").render())
        assert "inesperado" in mensaje.lower()

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-proyectos"
        await pilot.pause()
        assert app.query_one("#switcher-central", ContentSwitcher).current == "panel-proyectos"


async def test_dos_analisis_de_nuclei_consecutivos_no_mezclan_resultados(monkeypatch):
    def ejecutar_nuclei_falso(base_datos, proyecto, objetivo, plantillas_ids, *,
                               tiempo_limite=60.0, guardar_evidencia=True, debe_cancelar=None):
        if objetivo == "10.0.0.1":
            time.sleep(0.3)
            return None, [_hallazgo_guardado(id_=1)]
        return None, [_hallazgo_guardado(id_=2), _hallazgo_guardado(id_=3)]

    monkeypatch.setattr(modulo_paneles, "ejecutar_nuclei", ejecutar_nuclei_falso)

    app = AuraByteApp()
    async with app.run_test(size=(120, 80)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "nuclei-consecutivos")

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-vulnerabilidades"
        await pilot.pause()
        app.query_one("#nuclei-plantillas", SelectionList).select("exposed-env-file")
        app.query_one("#nuclei-confirmar", Checkbox).value = True

        objetivo_campo = app.query_one("#nuclei-objetivo", Input)
        objetivo_campo.focus()
        await _escribir(pilot, "10.0.0.1")
        await _clic_centro(pilot, "#nuclei-analizar")
        await pilot.pause()

        objetivo_campo.value = ""
        objetivo_campo.focus()
        await _escribir(pilot, "10.0.0.2")
        await _clic_centro(pilot, "#nuclei-analizar")

        await app.workers.wait_for_complete()
        await pilot.pause()

        tabla = app.query_one("#nuclei-tabla", DataTable)
        assert tabla.row_count == 2


async def test_panel_vulnerabilidades_marcar_falso_positivo_actualiza_tabla(monkeypatch):
    """Usa la logica real de persistencia/revision (solo se simula el binario de Nuclei)."""
    import json
    from pathlib import Path

    from eurabyte_security.integrations.nuclei import AdaptadorNuclei
    from eurabyte_security.integrations.proceso import ResultadoProceso

    ayuda = " ".join(
        ["-target", "-t", "-jsonl", "-timeout", "-rate-limit", "-duc", "-ni", "-silent", "-nc"]
    )
    linea = json.dumps(
        {
            "template-id": "exposed-env-file",
            "info": {"name": "Archivo .env expuesto", "severity": "high", "description": "d"},
            "matched-at": "http://127.0.0.1/.env",
            "matcher-name": "word",
        }
    )

    monkeypatch.setattr(AdaptadorNuclei, "esta_instalado", lambda self: True)
    monkeypatch.setattr(AdaptadorNuclei, "ruta_binario", lambda self: "/usr/bin/nuclei")
    # El panel de Herramientas (y el encabezado) tambien detectan Nuclei al montar la
    # app: con esta_instalado() forzado a True, evitamos que intenten de verdad
    # "nuclei -version" (que fallaria, ya que Nuclei no esta instalado en esta maquina).
    monkeypatch.setattr(AdaptadorNuclei, "obtener_version", lambda self: "v0.0.0-prueba")

    def _ejecutar_binario_falso(self, argumentos, *, tiempo_limite, debe_cancelar=None):
        if argumentos == ["-h"]:
            return ResultadoProceso(
                codigo_salida=0, stdout=ayuda, stderr="", agotado_por_tiempo=False
            )
        ruta_salida = Path(argumentos[argumentos.index("-o") + 1])
        ruta_salida.write_text(linea + "\n", encoding="utf-8")
        return ResultadoProceso(codigo_salida=0, stdout="", stderr="", agotado_por_tiempo=False)

    monkeypatch.setattr(AdaptadorNuclei, "_ejecutar_binario", _ejecutar_binario_falso)

    app = AuraByteApp()
    async with app.run_test(size=(120, 80)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "nuclei-revision")

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-alcance"
        await pilot.pause()
        app.query_one("#alc-objetivo", Input).focus()
        await _escribir(pilot, "127.0.0.1/32")
        await _clic_centro(pilot, "#alc-agregar")
        await pilot.pause()

        await _preparar_panel(pilot)
        await _clic_centro(pilot, "#nuclei-analizar")
        await app.workers.wait_for_complete()
        await pilot.pause()

        tabla = app.query_one("#nuclei-tabla", DataTable)
        assert tabla.row_count == 1

        tabla.focus()
        tabla.cursor_coordinate = (0, 0)
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()

        await _clic_centro(pilot, "#nuclei-marcar-falso-positivo")
        await pilot.pause()

        mensaje = str(app.query_one("#nuclei-mensaje").render()).lower()
        assert "falso_positivo" in mensaje
