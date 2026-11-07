from __future__ import annotations

import pytest
from textual.widgets import ContentSwitcher, DataTable, Input, OptionList

from eurabyte_security.core import config
from eurabyte_security.storage.database import BaseDatos
from eurabyte_security.ui.tui.app import AuraByteApp
from eurabyte_security.ui.tui.widgets.navegacion import SECCIONES

pytestmark = pytest.mark.asyncio


async def _clic_centro(pilot, selector: str) -> bool:
    boton = pilot.app.query_one(selector)
    return await pilot.click(boton, offset=(max(boton.region.width // 2, 1), 1))


async def _escribir(pilot, texto: str) -> None:
    for caracter in texto:
        await pilot.press(caracter)


async def test_arranque_muestra_titulo_y_panel_inicial():
    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        assert "AURABYTE" in app.title
        assert app.query_one("#switcher-central", ContentSwitcher).current == "panel-inicio"


async def test_todos_los_paneles_estan_registrados():
    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        # Las 14 secciones del roadmap deben existir como opciones de navegacion.
        opciones = app.query_one("#barra-lateral", OptionList)
        assert opciones.option_count == len(SECCIONES)
        for _etiqueta, id_panel in SECCIONES:
            assert app.query_one(f"#{id_panel}") is not None


async def test_navegacion_entre_secciones_cambia_el_panel_activo():
    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        opciones = app.query_one("#barra-lateral", OptionList)
        opciones.focus()
        opciones.highlighted = opciones.get_option_index("panel-proyectos")
        await pilot.press("enter")
        await pilot.pause()
        assert app.query_one("#switcher-central", ContentSwitcher).current == "panel-proyectos"


async def test_secciones_no_implementadas_muestran_proximamente():
    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        opciones = app.query_one("#barra-lateral", OptionList)
        opciones.focus()
        opciones.highlighted = opciones.get_option_index("panel-web")
        await pilot.press("enter")
        await pilot.pause()
        panel = app.query_one("#panel-web")
        textos = " ".join(str(estatico.render()) for estatico in panel.query("Static"))
        assert "Proximamente" in textos


async def test_autocompletado_con_tab_en_la_terminal():
    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.query_one("#switcher-central", ContentSwitcher).current = "panel-terminal"
        await pilot.pause()
        entrada = app.query_one("#entrada-terminal", Input)
        entrada.focus()
        await _escribir(pilot, "pro")
        await pilot.press("tab")
        await pilot.pause()
        assert entrada.value == "proyecto "


async def test_historial_con_flechas_en_la_terminal():
    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.query_one("#switcher-central", ContentSwitcher).current = "panel-terminal"
        await pilot.pause()
        entrada = app.query_one("#entrada-terminal", Input)
        entrada.focus()
        await _escribir(pilot, "ayuda")
        await pilot.press("enter")
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert entrada.value == ""
        await pilot.press("up")
        assert entrada.value == "ayuda"


async def test_terminal_ejecuta_comando_real_proyecto_crear():
    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.query_one("#switcher-central", ContentSwitcher).current = "panel-terminal"
        await pilot.pause()
        entrada = app.query_one("#entrada-terminal", Input)
        entrada.focus()
        await _escribir(pilot, "proyecto crear desdeterminal")
        await pilot.press("enter")
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert config.obtener_proyecto_activo() == "desdeterminal"


async def test_crear_y_activar_proyecto_desde_el_panel():
    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.query_one("#switcher-central", ContentSwitcher).current = "panel-proyectos"
        await pilot.pause()

        campo = app.query_one("#proy-nombre", Input)
        campo.focus()
        await _escribir(pilot, "visual")
        assert await _clic_centro(pilot, "#proy-crear")
        await pilot.pause()

        assert config.obtener_proyecto_activo() == "visual"
        tabla = app.query_one("#proy-tabla", DataTable)
        assert tabla.row_count == 1


async def test_alcance_y_rechazo_fuera_de_alcance_en_panel_redes():
    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-proyectos"
        await pilot.pause()
        app.query_one("#proy-nombre", Input).focus()
        await _escribir(pilot, "redlab")
        await _clic_centro(pilot, "#proy-crear")
        await pilot.pause()

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-alcance"
        await pilot.pause()
        app.query_one("#alc-objetivo", Input).focus()
        await _escribir(pilot, "10.0.0.0/24")
        await _clic_centro(pilot, "#alc-agregar")
        await pilot.pause()
        assert "autorizado" in str(app.query_one("#alc-mensaje").render())

        # Intentar escanear un objetivo FUERA del alcance autorizado.
        app.query_one("#switcher-central", ContentSwitcher).current = "panel-redes"
        await pilot.pause()
        app.query_one("#redes-objetivo", Input).focus()
        await _escribir(pilot, "127.0.0.1")
        app.query_one("#redes-puertos", Input).focus()
        await _escribir(pilot, "80")
        await _clic_centro(pilot, "#redes-escanear")
        await app.workers.wait_for_complete()
        await pilot.pause()

        mensaje = str(app.query_one("#redes-mensaje").render())
        assert "alcance" in mensaje.lower()
        base_datos = BaseDatos()
        proyecto = base_datos.obtener_proyecto_por_nombre("redlab")
        assert base_datos.listar_resultados(proyecto.id) == []


async def test_escaneo_dentro_de_alcance_actualiza_resultados():
    import socket

    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.bind(("127.0.0.1", 0))
    servidor.listen(1)
    puerto = servidor.getsockname()[1]

    try:
        app = AuraByteApp()
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()

            app.query_one("#switcher-central", ContentSwitcher).current = "panel-proyectos"
            await pilot.pause()
            app.query_one("#proy-nombre", Input).focus()
            await _escribir(pilot, "escaneolab")
            await _clic_centro(pilot, "#proy-crear")
            await pilot.pause()

            app.query_one("#switcher-central", ContentSwitcher).current = "panel-alcance"
            await pilot.pause()
            app.query_one("#alc-objetivo", Input).focus()
            await _escribir(pilot, "127.0.0.1/32")
            await _clic_centro(pilot, "#alc-agregar")
            await pilot.pause()

            app.query_one("#switcher-central", ContentSwitcher).current = "panel-redes"
            await pilot.pause()
            app.query_one("#redes-objetivo", Input).focus()
            await _escribir(pilot, "127.0.0.1")
            app.query_one("#redes-puertos", Input).focus()
            await _escribir(pilot, str(puerto))
            app.query_one("#redes-timeout", Input).focus()
            await _escribir(pilot, "0.5")
            await _clic_centro(pilot, "#redes-escanear")
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert app.query_one("#redes-tabla", DataTable).row_count == 1

            # El panel de Resultados (seccion independiente) debe reflejar el nuevo dato.
            app.query_one("#switcher-central", ContentSwitcher).current = "panel-resultados"
            await pilot.pause()
            panel_resultados = app.query_one("#panel-resultados")
            panel_resultados.refrescar()
            await pilot.pause()
            assert app.query_one("#panel-resultados #res-tabla", DataTable).row_count == 1
    finally:
        servidor.close()


async def test_panel_resultados_estado_vacio():
    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.query_one("#switcher-central", ContentSwitcher).current = "panel-proyectos"
        await pilot.pause()
        app.query_one("#proy-nombre", Input).focus()
        await _escribir(pilot, "vacio")
        await _clic_centro(pilot, "#proy-crear")
        await pilot.pause()

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-resultados"
        await pilot.pause()
        panel = app.query_one("#panel-resultados")
        panel.refrescar()
        await pilot.pause()
        mensaje = str(app.query_one("#panel-resultados #res-mensaje").render())
        assert "Sin resultados" in mensaje
        assert app.query_one("#panel-resultados #res-tabla", DataTable).row_count == 0


async def test_herramientas_detecta_sin_ejecutar():
    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.query_one("#switcher-central", ContentSwitcher).current = "panel-herramientas"
        await pilot.pause()
        tabla = app.query_one("#herr-tabla", DataTable)
        assert tabla.row_count == 4  # Nmap, Nuclei, OWASP ZAP, tshark


async def test_adaptacion_responsiva_oculta_paneles_secundarios():
    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        assert "oculto" not in app.query_one("#panel-info").classes
        assert "compacta" not in app.query_one("#barra-lateral").classes

        await pilot.resize_terminal(60, 30)
        await pilot.pause()
        assert "oculto" in app.query_one("#panel-info").classes
        assert "compacta" in app.query_one("#barra-lateral").classes

        await pilot.resize_terminal(140, 40)
        await pilot.pause()
        assert "oculto" not in app.query_one("#panel-info").classes
        assert "compacta" not in app.query_one("#barra-lateral").classes


async def test_panel_info_comando_reacciona_a_la_escritura():
    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.query_one("#switcher-central", ContentSwitcher).current = "panel-terminal"
        await pilot.pause()
        entrada = app.query_one("#entrada-terminal", Input)
        entrada.focus()
        await _escribir(pilot, "tcp")
        await pilot.pause()
        cuerpo = str(app.query_one("#info-comando-cuerpo").render())
        assert "connect scan" in cuerpo.lower() or "tcp" in cuerpo.lower()
