"""Pruebas del panel 'Analisis web' de la interfaz visual.

``auditar_web`` (tal como se importa en ``widgets/paneles.py``) se sustituye por un
doble en cada prueba: la TUI nunca hace peticiones de red de verdad en estas pruebas.
"""

from __future__ import annotations

import time
import types

from textual.widgets import ContentSwitcher, DataTable, Input

from eurabyte_security.core.errores import ErrorAuditoriaWeb
from eurabyte_security.modules.web.modelos import Hallazgo
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


def _hallazgo_falso(categoria="cabecera", nombre="X", severidad="media") -> Hallazgo:
    return Hallazgo(
        categoria=categoria,
        id_=f"{categoria}-{nombre}",
        nombre=nombre,
        significado="significado",
        proposito="proposito",
        valor_detectado="valor",
        severidad=severidad,
        estado="Ausente",
        riesgo="riesgo",
        recomendacion="recomendacion",
        referencia="https://example.test",
    )


async def test_panel_web_ejecuta_y_muestra_hallazgos(monkeypatch):
    resultado_falso = types.SimpleNamespace(
        codigo_estado=200,
        saltos_seguidos=(),
        hallazgos=[_hallazgo_falso("cabecera", "CSP"), _hallazgo_falso("cookie", "sesion", "alta")],
    )

    def auditar_web_falso(base_datos, proyecto, url, tipo, *, tipos, tiempo_limite,
                           seguir_redirecciones=False, guardar=True, debe_cancelar=None):
        return resultado_falso, []

    monkeypatch.setattr(modulo_paneles, "auditar_web", auditar_web_falso)

    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "web-tui")

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-web"
        await pilot.pause()
        app.query_one("#web-url", Input).focus()
        await _escribir(pilot, "https://127.0.0.1:8443/")

        await _clic_centro(pilot, "#web-analizar")
        await app.workers.wait_for_complete()
        await pilot.pause()

        tabla = app.query_one("#web-tabla", DataTable)
        assert tabla.row_count == 2
        mensaje = str(app.query_one("#web-mensaje").render())
        assert "completo" in mensaje.lower()


async def test_panel_web_cancelar_no_guarda_nada(monkeypatch):
    def auditar_web_que_tarda(base_datos, proyecto, url, tipo, *, tipos, tiempo_limite,
                               seguir_redirecciones=False, guardar=True, debe_cancelar=None):
        for _ in range(100):
            if debe_cancelar is not None and debe_cancelar():
                raise ErrorAuditoriaWeb(f"La auditoria de '{url}' se cancelo.")
            time.sleep(0.02)
        raise AssertionError("Deberia haberse cancelado antes de este punto.")

    monkeypatch.setattr(modulo_paneles, "auditar_web", auditar_web_que_tarda)

    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "web-cancelar")

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-web"
        await pilot.pause()
        app.query_one("#web-url", Input).focus()
        await _escribir(pilot, "https://127.0.0.1:8443/")

        await _clic_centro(pilot, "#web-analizar")
        await pilot.pause()
        await _clic_centro(pilot, "#web-cancelar")
        await app.workers.wait_for_complete()
        await pilot.pause()

        assert app.query_one("#web-tabla", DataTable).row_count == 0
        mensaje = str(app.query_one("#web-mensaje").render()).lower()
        assert "cancel" in mensaje


async def test_panel_web_error_inesperado_no_cierra_la_interfaz(monkeypatch):
    def auditar_web_roto(*args, **kwargs):
        raise RuntimeError("fallo interno simulado en auditoria web")

    monkeypatch.setattr(modulo_paneles, "auditar_web", auditar_web_roto)

    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "web-roto")

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-web"
        await pilot.pause()
        app.query_one("#web-url", Input).focus()
        await _escribir(pilot, "https://127.0.0.1:8443/")

        await _clic_centro(pilot, "#web-analizar")
        await app.workers.wait_for_complete()
        await pilot.pause()

        mensaje = str(app.query_one("#web-mensaje").render())
        assert "inesperado" in mensaje.lower()

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-proyectos"
        await pilot.pause()
        assert app.query_one("#switcher-central", ContentSwitcher).current == "panel-proyectos"


async def test_dos_analisis_web_consecutivos_no_mezclan_resultados(monkeypatch):
    def auditar_web_falso(base_datos, proyecto, url, tipo, *, tipos, tiempo_limite,
                           seguir_redirecciones=False, guardar=True, debe_cancelar=None):
        if "lento" in url:
            time.sleep(0.3)
            return types.SimpleNamespace(
                codigo_estado=200, saltos_seguidos=(), hallazgos=[_hallazgo_falso("tls", "A")]
            ), []
        return types.SimpleNamespace(
            codigo_estado=200, saltos_seguidos=(), hallazgos=[_hallazgo_falso("tls", "B")]
        ), []

    monkeypatch.setattr(modulo_paneles, "auditar_web", auditar_web_falso)

    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "web-consecutivos")

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-web"
        await pilot.pause()

        campo_url = app.query_one("#web-url", Input)
        campo_url.focus()
        await _escribir(pilot, "https://127.0.0.1/lento")
        await _clic_centro(pilot, "#web-analizar")
        await pilot.pause()

        campo_url.value = ""
        campo_url.focus()
        await _escribir(pilot, "https://127.0.0.1/rapido")
        await _clic_centro(pilot, "#web-analizar")

        await app.workers.wait_for_complete()
        await pilot.pause()

        tabla = app.query_one("#web-tabla", DataTable)
        assert tabla.row_count == 1
        assert tabla.get_row_at(0)[1] == "B"


async def test_panel_web_rechaza_objetivo_fuera_de_alcance_real():
    """Sin doble: usa la logica real de alcance contra un objetivo no autorizado."""
    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await _crear_proyecto(pilot, "web-alcance-real")

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-web"
        await pilot.pause()
        app.query_one("#web-url", Input).focus()
        await _escribir(pilot, "http://127.0.0.1:65000/")

        await _clic_centro(pilot, "#web-analizar")
        await app.workers.wait_for_complete()
        await pilot.pause()

        mensaje = str(app.query_one("#web-mensaje").render()).lower()
        assert "alcance" in mensaje
        assert app.query_one("#web-tabla", DataTable).row_count == 0
