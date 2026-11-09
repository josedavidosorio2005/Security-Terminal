"""Pruebas del flujo automatico del panel 'Reconocimiento' de la interfaz visual.

Nmap, Nuclei y OWASP ZAP se sustituyen por dobles; la etapa de auditoria web SI habla
con un servidor HTTP real en ``127.0.0.1`` (``ayudantes_web.py``), igual que en
``tests/test_reconocimiento_orquestador.py``. El formulario de 120x80 (en vez de
120x40) se usa a proposito: este panel es mas largo que los demas y un terminal mas
bajo deja algunos de sus botones fuera del area que Textual Pilot puede clicar de
forma fiable en las pruebas (no es un problema real de uso, solo de la simulacion de
clics en un terminal headless muy bajo).
"""

from __future__ import annotations

import time

from textual.widgets import Checkbox, Collapsible, ContentSwitcher, DataTable, Input, Select

from eurabyte_security.integrations.nmap import AdaptadorNmap
from eurabyte_security.integrations.nuclei import AdaptadorNuclei
from eurabyte_security.integrations.proceso import ResultadoProceso
from eurabyte_security.modules.vulnerability import zap as zap_modulo
from eurabyte_security.ui.tui.app import AuraByteApp
from eurabyte_security.ui.tui.widgets import paneles as modulo_paneles

from .ayudantes_web import RespuestaConfigurada, servidor_prueba

TAMANO = (120, 80)


async def _clic_centro(pilot, selector: str) -> bool:
    boton = pilot.app.query_one(selector)
    return await pilot.click(boton, offset=(max(boton.region.width // 2, 1), 1))


async def _escribir(pilot, texto: str) -> None:
    for caracter in texto:
        await pilot.press(caracter)


async def _crear_proyecto_con_alcance_local(pilot, nombre: str) -> None:
    app = pilot.app
    app.query_one("#switcher-central", ContentSwitcher).current = "panel-proyectos"
    await pilot.pause()
    app.query_one("#proy-nombre", Input).focus()
    await _escribir(pilot, nombre)
    await _clic_centro(pilot, "#proy-crear")
    await pilot.pause()

    app.query_one("#switcher-central", ContentSwitcher).current = "panel-alcance"
    await pilot.pause()
    app.query_one("#alc-objetivo", Input).focus()
    await _escribir(pilot, "127.0.0.1/32")
    await _clic_centro(pilot, "#alc-agregar")
    await pilot.pause()


def _marcar_nmap_ausente(monkeypatch) -> None:
    monkeypatch.setattr(AdaptadorNmap, "esta_instalado", lambda self: False)
    monkeypatch.setattr(AdaptadorNmap, "ruta_binario", lambda self: None)


def _marcar_nuclei_ausente(monkeypatch) -> None:
    monkeypatch.setattr(AdaptadorNuclei, "esta_instalado", lambda self: False)
    monkeypatch.setattr(AdaptadorNuclei, "ruta_binario", lambda self: None)


def _marcar_zap_ausente(monkeypatch) -> None:
    from eurabyte_security.core.errores import ErrorZAPNoDisponible

    def _peticion_falla(configuracion, ruta, parametros, *, tiempo_limite):
        raise ErrorZAPNoDisponible("simulado: ZAP no disponible")

    monkeypatch.setattr(zap_modulo, "_peticion_zap", _peticion_falla)


def _marcar_herramientas_ausentes(monkeypatch) -> None:
    _marcar_nmap_ausente(monkeypatch)
    _marcar_nuclei_ausente(monkeypatch)
    _marcar_zap_ausente(monkeypatch)


async def _preparar_panel(pilot, objetivo: str) -> None:
    app = pilot.app
    app.query_one("#switcher-central", ContentSwitcher).current = "panel-reconocimiento"
    await pilot.pause()
    app.query_one("#reco-auto-objetivo", Input).focus()
    await _escribir(pilot, objetivo)
    app.query_one("#reco-auto-confirmar", Checkbox).value = True
    await pilot.pause()


async def test_flujo_completo_actualiza_etapas_y_resumen(monkeypatch):
    _marcar_herramientas_ausentes(monkeypatch)
    respuestas = {"/": RespuestaConfigurada(codigo_estado=200, cuerpo=b"ok")}

    app = AuraByteApp()
    async with app.run_test(size=TAMANO) as pilot:
        await pilot.pause()
        await _crear_proyecto_con_alcance_local(pilot, "reco-ui-completo")

        with servidor_prueba(respuestas) as (host, puerto):
            await _preparar_panel(pilot, f"http://{host}:{puerto}/")
            await _clic_centro(pilot, "#reco-auto-iniciar")
            await app.workers.wait_for_complete()
            await pilot.pause()

        tabla = app.query_one("#reco-auto-etapas-tabla", DataTable)
        assert tabla.row_count == 6
        mensaje = str(app.query_one("#reco-auto-mensaje").render()).lower()
        assert "completo" in mensaje
        resumen = str(app.query_one("#reco-auto-resumen").render()).lower()
        assert "completada" in resumen


async def test_exige_objetivo_antes_de_iniciar(monkeypatch):
    _marcar_herramientas_ausentes(monkeypatch)

    app = AuraByteApp()
    async with app.run_test(size=TAMANO) as pilot:
        await pilot.pause()
        await _crear_proyecto_con_alcance_local(pilot, "reco-ui-sin-objetivo")

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-reconocimiento"
        await pilot.pause()
        app.query_one("#reco-auto-confirmar", Checkbox).value = True
        await pilot.pause()

        await _clic_centro(pilot, "#reco-auto-iniciar")
        await pilot.pause()

        assert app.query_one("#reco-auto-etapas-tabla", DataTable).row_count == 0
        mensaje = str(app.query_one("#reco-auto-mensaje").render()).lower()
        assert "objetivo" in mensaje


async def test_exige_confirmacion_antes_de_iniciar(monkeypatch):
    _marcar_herramientas_ausentes(monkeypatch)

    app = AuraByteApp()
    async with app.run_test(size=TAMANO) as pilot:
        await pilot.pause()
        await _crear_proyecto_con_alcance_local(pilot, "reco-ui-sin-confirmar")

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-reconocimiento"
        await pilot.pause()
        app.query_one("#reco-auto-objetivo", Input).focus()
        await _escribir(pilot, "127.0.0.1")
        # Deliberadamente NO se marca la casilla de confirmacion.

        await _clic_centro(pilot, "#reco-auto-iniciar")
        await pilot.pause()

        assert app.query_one("#reco-auto-etapas-tabla", DataTable).row_count == 0
        mensaje = str(app.query_one("#reco-auto-mensaje").render()).lower()
        assert "confirma" in mensaje


async def test_perfil_personalizado_sin_puertos_muestra_aviso(monkeypatch):
    _marcar_herramientas_ausentes(monkeypatch)

    app = AuraByteApp()
    async with app.run_test(size=TAMANO) as pilot:
        await pilot.pause()
        await _crear_proyecto_con_alcance_local(pilot, "reco-ui-personalizado")
        await _preparar_panel(pilot, "127.0.0.1")

        app.query_one("#reco-auto-perfil", Select).value = "personalizado"
        await pilot.pause()

        await _clic_centro(pilot, "#reco-auto-iniciar")
        await pilot.pause()

        assert app.query_one("#reco-auto-etapas-tabla", DataTable).row_count == 0


async def test_cancelar_detiene_el_reconocimiento(monkeypatch):
    def nmap_que_tarda(self, argumentos, *, tiempo_limite, debe_cancelar=None):
        for _ in range(100):
            if debe_cancelar is not None and debe_cancelar():
                return ResultadoProceso(
                    codigo_salida=-1, stdout="", stderr="", agotado_por_tiempo=False,
                    cancelado=True,
                )
            time.sleep(0.02)
        raise AssertionError("Deberia haberse cancelado antes de este punto.")

    monkeypatch.setattr(AdaptadorNmap, "esta_instalado", lambda self: True)
    monkeypatch.setattr(AdaptadorNmap, "ruta_binario", lambda self: "/usr/bin/nmap")
    monkeypatch.setattr(AdaptadorNmap, "obtener_version", lambda self: "7.95")
    monkeypatch.setattr(AdaptadorNmap, "_ejecutar_binario", nmap_que_tarda)

    app = AuraByteApp()
    async with app.run_test(size=TAMANO) as pilot:
        await pilot.pause()
        await _crear_proyecto_con_alcance_local(pilot, "reco-ui-cancelar")
        await _preparar_panel(pilot, "127.0.0.1")

        await _clic_centro(pilot, "#reco-auto-iniciar")
        await pilot.pause()
        await _clic_centro(pilot, "#reco-auto-cancelar")
        await app.workers.wait_for_complete()
        await pilot.pause()

        mensaje = str(app.query_one("#reco-auto-mensaje").render()).lower()
        assert "cancel" in mensaje


async def test_error_inesperado_no_cierra_la_interfaz(monkeypatch):
    def reconocimiento_roto(*args, **kwargs):
        raise RuntimeError("fallo interno simulado")

    monkeypatch.setattr(modulo_paneles, "ejecutar_reconocimiento_automatico", reconocimiento_roto)

    app = AuraByteApp()
    async with app.run_test(size=TAMANO) as pilot:
        await pilot.pause()
        await _crear_proyecto_con_alcance_local(pilot, "reco-ui-roto")
        await _preparar_panel(pilot, "127.0.0.1")

        await _clic_centro(pilot, "#reco-auto-iniciar")
        await app.workers.wait_for_complete()
        await pilot.pause()

        mensaje = str(app.query_one("#reco-auto-mensaje").render()).lower()
        assert "inesperado" in mensaje

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-proyectos"
        await pilot.pause()
        assert app.query_one("#switcher-central", ContentSwitcher).current == "panel-proyectos"


async def test_ver_vulnerabilidades_cambia_al_panel_resultados(monkeypatch):
    _marcar_herramientas_ausentes(monkeypatch)

    app = AuraByteApp()
    async with app.run_test(size=TAMANO) as pilot:
        await pilot.pause()
        await _crear_proyecto_con_alcance_local(pilot, "reco-ui-ver-vuln")
        app.query_one("#switcher-central", ContentSwitcher).current = "panel-reconocimiento"
        await pilot.pause()

        await _clic_centro(pilot, "#reco-auto-ver-vulnerabilidades")
        await pilot.pause()

        assert app.query_one("#switcher-central", ContentSwitcher).current == "panel-resultados"


async def test_formulario_nmap_manual_sigue_funcionando_en_seccion_avanzada(monkeypatch):
    """La forma manual de Nmap (identica a la que ya existia) sigue intacta dentro de
    la seccion 'avanzada' plegable: se expande y se usa igual que antes."""
    monkeypatch.setattr(AdaptadorNmap, "esta_instalado", lambda self: True)
    monkeypatch.setattr(AdaptadorNmap, "ruta_binario", lambda self: "/usr/bin/nmap")

    import types

    puerto_falso = types.SimpleNamespace(
        puerto=22, protocolo="tcp", estado="open", servicio="ssh", version=None
    )
    resultado_falso = types.SimpleNamespace(objetivo="127.0.0.1", puertos=[puerto_falso])

    def ejecutar_nmap_falso(base_datos, proyecto, objetivo, puertos, *, deteccion_version=False,
                             tiempo_limite=120.0, guardar_evidencia=True, debe_cancelar=None):
        return resultado_falso, [], None

    monkeypatch.setattr(modulo_paneles, "ejecutar_nmap", ejecutar_nmap_falso)

    app = AuraByteApp()
    async with app.run_test(size=TAMANO) as pilot:
        await pilot.pause()
        await _crear_proyecto_con_alcance_local(pilot, "reco-ui-nmap-manual")

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-reconocimiento"
        await pilot.pause()
        app.query_one("#reco-nmap-manual", Collapsible).collapsed = False
        await pilot.pause()

        app.query_one("#nmap-objetivo", Input).focus()
        await _escribir(pilot, "127.0.0.1")
        app.query_one("#nmap-puertos", Input).focus()
        await _escribir(pilot, "22")

        await _clic_centro(pilot, "#nmap-ejecutar")
        await app.workers.wait_for_complete()
        await pilot.pause()

        tabla = app.query_one("#nmap-tabla", DataTable)
        assert tabla.row_count == 1
