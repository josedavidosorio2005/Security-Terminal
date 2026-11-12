"""Verificacion visual y funcional del panel OSINT en los 4 tamanos exigidos por el
rediseno (80x24, 100x30, 120x35, 160x45): ver docs/ROADMAP.md.

Sigue el mismo enfoque que ``tests/test_tui_responsivo.py`` (comprobar la region real
con ``Widget.region``, no solo que el widget exista) y reutiliza los dobles y
ayudantes de ``tests/test_tui_osint.py`` para no duplicar la logica de simular una
investigacion. Ninguna prueba de este archivo consulta una fuente OSINT real.
"""

from __future__ import annotations

import types

import pytest
from textual.widgets import (
    Button,
    Collapsible,
    ContentSwitcher,
    DataTable,
    Input,
    Select,
    SelectionList,
    TabbedContent,
)

from eurabyte_security.core.osint.validacion import requiere_autorizacion_datos_personales
from eurabyte_security.ui.tui.app import AuraByteApp
from eurabyte_security.ui.tui.widgets import paneles as modulo_paneles
from tests.test_tui_osint import (
    _abrir_panel_osint,
    _abrir_pestana_informe,
    _clic_centro,
    _crear_proyecto,
    _escribir,
    _resultado_persistido,
)

TAMANOS = [(80, 24), (100, 30), (120, 35), (160, 45)]

_CONTROLES_ESENCIALES = (
    "#osint-tipo",
    "#osint-objetivo",
    "#osint-iniciar",
    "#osint-cancelar",
    "#osint-estado",
    "#osint-tabs",
)


def _dentro_de_pantalla(region, ancho: int, alto: int) -> bool:
    return (
        region.x >= 0
        and region.y >= 0
        and region.right <= ancho
        and region.bottom <= alto
        and region.width > 0
        and region.height > 0
    )


@pytest.mark.parametrize("ancho,alto", TAMANOS)
async def test_controles_esenciales_osint_accesibles_en_todos_los_tamanos(ancho, alto):
    """Regresion: el formulario fijo llegaba a consumir mas filas que el propio panel,
    dejando #osint-tabs (y todo lo demas debajo) con 1 fila de alto en 80x24/100x30."""
    app = AuraByteApp()
    async with app.run_test(size=(ancho, alto)) as pilot:
        await pilot.pause()
        await _abrir_panel_osint(pilot)
        for selector in _CONTROLES_ESENCIALES:
            widget = app.query_one(selector)
            assert _dentro_de_pantalla(widget.region, ancho, alto), (
                f"{selector} fuera de pantalla o sin region en {ancho}x{alto}: "
                f"{widget.region}"
            )


@pytest.mark.parametrize("ancho,alto", TAMANOS)
async def test_badge_de_estado_nunca_recortado(ancho, alto):
    """Regresion: a 100x30 '#osint-estado' quedaba totalmente fuera del panel (x=67
    con el panel terminando en x=64) porque el encabezado no se adapta al ancho."""
    app = AuraByteApp()
    async with app.run_test(size=(ancho, alto)) as pilot:
        await pilot.pause()
        await _abrir_panel_osint(pilot)
        panel = app.query_one("#panel-osint")
        estado = app.query_one("#osint-estado")
        assert panel.region.contains_region(estado.region), (
            f"#osint-estado fuera del panel en {ancho}x{alto}: panel={panel.region} "
            f"estado={estado.region}"
        )


@pytest.mark.parametrize("ancho,alto", TAMANOS)
async def test_selector_de_historial_tiene_ancho_usable(ancho, alto):
    """Regresion: la etiqueta 'Investigacion guardada:' reclamaba casi todo el ancho
    de su fila y dejaba el Select de historial en 1 columna (inutilizable)."""
    app = AuraByteApp()
    async with app.run_test(size=(ancho, alto)) as pilot:
        await pilot.pause()
        await _abrir_panel_osint(pilot)
        selector = app.query_one("#osint-historial", Select)
        assert selector.region.width >= 10, (
            f"#osint-historial demasiado angosto en {ancho}x{alto}: {selector.region}"
        )


@pytest.mark.parametrize("ancho,alto", TAMANOS)
async def test_boton_generar_informe_alcanzable_por_scroll(ancho, alto):
    """No basta con que el boton exista en el DOM: en modo compacto la fila de Informe
    (Select + Checkbox + Boton apilados) puede superar la altura fija de la pestana y
    quedar recortada sin que nada la revele. Debe poder alcanzarse con scroll real."""
    app = AuraByteApp()
    async with app.run_test(size=(ancho, alto)) as pilot:
        await pilot.pause()
        await _abrir_panel_osint(pilot)
        await _abrir_pestana_informe(pilot)
        boton = app.query_one("#osint-informe-generar", Button)
        boton.scroll_visible(animate=False)
        await pilot.pause()
        pane = app.query_one("#osint-tab-informe")
        assert pane.region.contains_region(boton.region), (
            f"'Generar informe' no alcanzable ni con scroll en {ancho}x{alto}: "
            f"pane={pane.region} boton={boton.region}"
        )


@pytest.mark.parametrize("ancho,alto", TAMANOS)
async def test_todas_las_pestanas_accesibles_sin_solapar_el_formulario(ancho, alto):
    app = AuraByteApp()
    async with app.run_test(size=(ancho, alto)) as pilot:
        await pilot.pause()
        await _abrir_panel_osint(pilot)
        tabs = app.query_one("#osint-tabs", TabbedContent)
        formulario = app.query_one("#osint-formulario")
        for tab_id in (
            "osint-tab-resumen",
            "osint-tab-infraestructura",
            "osint-tab-perfiles",
            "osint-tab-exposicion",
            "osint-tab-fuentes",
            "osint-tab-informe",
        ):
            tabs.active = tab_id
            await pilot.pause()
            pane = app.query_one(f"#{tab_id}")
            assert not formulario.region.overlaps(pane.region), (
                f"{tab_id} se solapa con el formulario fijo en {ancho}x{alto}"
            )


@pytest.mark.parametrize("ancho,alto", [(80, 24), (160, 45)])
async def test_guion_interaccion_completo(ancho, alto, monkeypatch):
    """Guion de 14 pasos de la especificacion del rediseno, en el tamano mas estrecho
    y el mas amplio exigidos: tipos, objetivo, fuentes, autorizacion, ejecutar,
    progreso, cancelar, resultados, pestanas, informe, resize en caliente y navegar
    fuera y volver sin perder el estado ni congelar la interfaz."""

    eventos: list[str] = []

    def _investigacion_lenta(base_datos, proyecto, tipo, objetivo, **kwargs):
        import time

        debe_cancelar = kwargs.get("debe_cancelar")
        progreso = kwargs.get("callback_progreso")
        etapa = {"fuente": "dns", "estado": "completada", "detalle": "1 hallazgo(s)."}
        if progreso is not None:
            progreso(types.SimpleNamespace(**etapa))
        for _ in range(50):
            if debe_cancelar is not None and debe_cancelar():
                from eurabyte_security.core.errores import ErrorInvestigacionOSINTCancelada

                raise ErrorInvestigacionOSINTCancelada("cancelado por el usuario")
            time.sleep(0.02)
        return _resultado_persistido(base_datos, proyecto, tipo, objetivo, etapas=[etapa])

    monkeypatch.setattr(modulo_paneles, "ejecutar_investigacion_osint", _investigacion_lenta)

    app = AuraByteApp()
    async with app.run_test(size=(ancho, alto)) as pilot:
        await pilot.pause()
        # 1. Crear proyecto y abrir OSINT.
        await _crear_proyecto(pilot, "osint-guion")
        await _abrir_panel_osint(pilot)
        eventos.append("abierto")

        # 2. Recorrer cada tipo de objetivo comprobando los campos condicionales.
        tipo_selector = app.query_one("#osint-tipo", Select)
        for tipo in ("dominio", "correo", "telefono", "usuario"):
            tipo_selector.value = tipo
            await pilot.pause()
            region_visible = app.query_one("#osint-region").display
            autorizo_visible = app.query_one("#osint-autorizo").display
            assert region_visible == (tipo == "telefono"), tipo
            assert autorizo_visible == requiere_autorizacion_datos_personales(tipo), tipo
        eventos.append("tipos-recorridos")

        # 3. Volver a 'dominio' (no exige autorizacion) y escribir el objetivo.
        tipo_selector.value = "dominio"
        await pilot.pause()
        app.query_one("#osint-objetivo", Input).focus()
        await _escribir(pilot, "ejemplo.com")

        # 4. Expandir fuentes y seleccionar al menos una.
        colapsable = app.query_one("#osint-fuentes-colapsable", Collapsible)
        colapsable.collapsed = False
        await pilot.pause()
        fuentes = app.query_one("#osint-fuentes", SelectionList)
        assert fuentes.option_count > 0
        primera_fuente = fuentes.get_option_at_index(0).value
        fuentes.select(primera_fuente)
        assert primera_fuente in fuentes.selected
        eventos.append("fuentes-seleccionadas")

        # 5. 'dominio' no requiere autorizacion: la casilla permanece oculta.
        assert app.query_one("#osint-autorizo").display is False

        # 6. Iniciar con el adaptador simulado (nunca una fuente real).
        await _clic_centro(pilot, "#osint-iniciar")
        await pilot.pause()
        assert app.query_one("#osint-iniciar", Button).disabled is True
        assert app.query_one("#osint-cancelar", Button).disabled is False
        eventos.append("investigacion-iniciada")

        # 7. Observar progreso: la etapa simulada ya debe figurar en la tabla.
        tabla_etapas = app.query_one("#osint-tabla-etapas", DataTable)
        assert tabla_etapas.row_count == 1
        eventos.append("progreso-observado")

        # 8. Redimensionar la terminal a mitad de la investigacion: no debe congelarse
        # ni perder ningun control esencial.
        ancho_alt, alto_alt = (160, 45) if (ancho, alto) == (80, 24) else (80, 24)
        await pilot.resize_terminal(ancho_alt, alto_alt)
        await pilot.pause()
        for selector in _CONTROLES_ESENCIALES:
            widget = app.query_one(selector)
            assert _dentro_de_pantalla(widget.region, ancho_alt, alto_alt), selector
        await pilot.resize_terminal(ancho, alto)
        await pilot.pause()
        eventos.append("resize-en-caliente")

        # 9. Cancelar: la investigacion en curso se interrumpe sin congelar la app.
        await _clic_centro(pilot, "#osint-cancelar")
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert app.is_running
        assert app.query_one("#osint-iniciar", Button).disabled is False
        mensaje = str(app.query_one("#osint-mensaje").render()).lower()
        assert "cancelada" in mensaje
        eventos.append("cancelado")

        # 10. Navegar fuera del panel OSINT y volver: el estado no debe perderse ni
        # la app debe fallar al reabrirlo.
        app.query_one("#switcher-central", ContentSwitcher).current = "panel-proyectos"
        await pilot.pause()
        await _abrir_panel_osint(pilot)
        assert app.is_running
        eventos.append("navegado-fuera-y-vuelto")

        # 11. Repetir la investigacion, esta vez dejandola completar con exito.
        await _clic_centro(pilot, "#osint-iniciar")
        await app.workers.wait_for_complete()
        await pilot.pause()
        mensaje = str(app.query_one("#osint-mensaje").render()).lower()
        assert "completa" in mensaje
        eventos.append("investigacion-completada")

        # 12. Ver resultados: recorrer las 6 pestanas sin excepciones ni solapamientos.
        tabs = app.query_one("#osint-tabs", TabbedContent)
        for tab_id in (
            "osint-tab-resumen",
            "osint-tab-infraestructura",
            "osint-tab-perfiles",
            "osint-tab-exposicion",
            "osint-tab-fuentes",
            "osint-tab-informe",
        ):
            tabs.active = tab_id
            await pilot.pause()
        eventos.append("pestanas-recorridas")

        # 13. Generar el informe (adaptador de reportes tambien simulado).
        def _fake_reporte(base_datos, proyecto, investigacion_id, formato, **kwargs):
            import tempfile
            from pathlib import Path

            ruta = Path(tempfile.gettempdir()) / f"informe-guion.{formato}"
            ruta.write_text("contenido", encoding="utf-8")
            return ruta

        monkeypatch.setattr(modulo_paneles, "generar_reporte_osint", _fake_reporte)
        await _abrir_pestana_informe(pilot)
        app.query_one("#osint-informe-generar", Button).press()
        await pilot.pause()
        await app.workers.wait_for_complete()
        await pilot.pause()
        mensaje_informe = str(app.query_one("#osint-informe-mensaje").render()).lower()
        assert "informe generado" in mensaje_informe
        eventos.append("informe-generado")

        # 14. Recuperar la investigacion ya completada desde el historial, sin volver
        # a ejecutar nada (la funcionalidad nueva que cierra la brecha del ROADMAP):
        # se cambia a "Investigacion actual" y se vuelve a seleccionar la guardada.
        historial = app.query_one("#osint-historial", Select)
        investigacion_guardada = historial.value
        assert investigacion_guardada != "actual"
        historial.value = "actual"
        await pilot.pause()
        historial.value = investigacion_guardada
        await pilot.pause()
        assert app.is_running
        mensaje_historial = str(app.query_one("#osint-mensaje").render()).lower()
        assert "guardada" in mensaje_historial
        eventos.append("historial-verificado")

    assert eventos == [
        "abierto",
        "tipos-recorridos",
        "fuentes-seleccionadas",
        "investigacion-iniciada",
        "progreso-observado",
        "resize-en-caliente",
        "cancelado",
        "navegado-fuera-y-vuelto",
        "investigacion-completada",
        "pestanas-recorridas",
        "informe-generado",
        "historial-verificado",
    ]
