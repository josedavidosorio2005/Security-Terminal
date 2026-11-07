from __future__ import annotations

import socket
import time

import pytest
from textual.widgets import ContentSwitcher, DataTable, Input

from eurabyte_security.commands._comun import obtener_base_datos
from eurabyte_security.commands.escanear import escanear_tcp
from eurabyte_security.commands.proyecto import crear_proyecto
from eurabyte_security.core.errores import ErrorEscaneoCancelado
from eurabyte_security.modules.network.tcp_scanner import escanear_puertos_tcp
from eurabyte_security.ui.consola import texto_seguro
from eurabyte_security.ui.tui.app import AuraByteApp
from eurabyte_security.ui.tui.widgets import paneles as modulo_paneles


def _puerto_libre() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _clic_centro(pilot, selector: str) -> bool:
    boton = pilot.app.query_one(selector)
    return await pilot.click(boton, offset=(max(boton.region.width // 2, 1), 1))


async def _escribir(pilot, texto: str) -> None:
    for caracter in texto:
        await pilot.press(caracter)


# ---------------------------------------------------------------------------
# texto_seguro(): evita que el marcado Rich interprete texto del usuario.
# ---------------------------------------------------------------------------


def test_texto_seguro_escapa_corchetes():
    assert texto_seguro("[red]hola[/red]") == "\\[red]hola\\[/red]"


def test_texto_seguro_no_crashea_con_etiqueta_de_cierre_suelta():
    from rich.console import Console
    from rich.errors import MarkupError

    consola = Console()
    # Sin escapar, esto lanza rich.errors.MarkupError (ver commands/escanear.py,
    # motor_comandos.py y paneles.py: todos escapan antes de mostrar texto).
    with pytest.raises(MarkupError):
        consola.print("[/]")
    consola.print(texto_seguro("[/]"))  # no debe lanzar nada


def test_texto_seguro_preserva_texto_normal():
    assert texto_seguro("127.0.0.1/32") == "127.0.0.1/32"


# ---------------------------------------------------------------------------
# Cancelacion a nivel de logica (sin Textual): escanear_tcp / escanear_puertos_tcp.
# ---------------------------------------------------------------------------


def test_escanear_puertos_tcp_cancelado_desde_el_inicio_no_abre_mas_conexiones():
    puertos = [_puerto_libre() for _ in range(5)]
    resultados = escanear_puertos_tcp(
        "127.0.0.1", puertos, tiempo_espera=2.0, concurrencia=1, debe_cancelar=lambda: True
    )
    assert resultados == []


def test_escanear_puertos_tcp_sin_cancelar_funciona_como_antes():
    puerto = _puerto_libre()
    resultados = escanear_puertos_tcp(
        "127.0.0.1", [puerto], tiempo_espera=0.5, debe_cancelar=lambda: False
    )
    assert len(resultados) == 1
    assert resultados[0].puerto == puerto


def test_escanear_tcp_cancelado_no_persiste_ningun_resultado(tmp_path):
    from eurabyte_security.storage.database import BaseDatos

    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "cancelable")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")
    puerto = _puerto_libre()

    with pytest.raises(ErrorEscaneoCancelado):
        escanear_tcp(
            base_datos,
            proyecto,
            "127.0.0.1",
            str(puerto),
            tiempo_espera=0.5,
            debe_cancelar=lambda: True,
        )

    assert base_datos.listar_resultados(proyecto.id) == []


def test_escanear_tcp_no_cancelado_persiste_normalmente(tmp_path):
    from eurabyte_security.storage.database import BaseDatos

    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "normal")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")
    puerto = _puerto_libre()

    resultados = escanear_tcp(
        base_datos,
        proyecto,
        "127.0.0.1",
        str(puerto),
        tiempo_espera=0.5,
        debe_cancelar=lambda: False,
    )
    assert len(resultados) == 1
    assert base_datos.listar_resultados(proyecto.id) == resultados


def test_escanear_tcp_sin_parametro_debe_cancelar_mantiene_compatibilidad(tmp_path):
    """Las llamadas existentes (CLI, REPL, motor_comandos) no pasan debe_cancelar."""
    from eurabyte_security.storage.database import BaseDatos

    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "compat")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")
    puerto = _puerto_libre()

    resultados = escanear_tcp(base_datos, proyecto, "127.0.0.1", str(puerto), tiempo_espera=0.5)
    assert len(resultados) == 1
    assert base_datos.listar_resultados(proyecto.id) == resultados


def test_escanear_tcp_cancelado_a_mitad_de_camino_no_persiste(tmp_path):
    """Cancelar tras resolverse algunos puertos tambien descarta todo (todo o nada)."""
    from eurabyte_security.storage.database import BaseDatos

    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "parcial")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")
    puertos = [_puerto_libre() for _ in range(6)]

    contador = {"n": 0}

    def debe_cancelar() -> bool:
        contador["n"] += 1
        return contador["n"] > 2  # cancela despues de que resuelvan los primeros puertos

    with pytest.raises(ErrorEscaneoCancelado):
        escanear_tcp(
            base_datos,
            proyecto,
            "127.0.0.1",
            ",".join(str(p) for p in puertos),
            tiempo_espera=1.0,
            concurrencia=1,
            debe_cancelar=debe_cancelar,
        )

    assert base_datos.listar_resultados(proyecto.id) == []


# ---------------------------------------------------------------------------
# Panel "Redes": cancelacion real desde la interfaz y no-mezcla de escaneos.
# ---------------------------------------------------------------------------


async def _preparar_proyecto_y_alcance(pilot, nombre: str = "redes-test") -> None:
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

    app.query_one("#switcher-central", ContentSwitcher).current = "panel-redes"
    await pilot.pause()


async def test_cancelar_desde_el_panel_redes_no_guarda_resultados(monkeypatch):
    def escanear_que_tarda(base_datos, proyecto, objetivo, puertos, *, tiempo_espera=1.0,
                            concurrencia=50, debe_cancelar=None):
        for _ in range(100):  # hasta ~2s, pero deberia cancelarse mucho antes
            if debe_cancelar is not None and debe_cancelar():
                from eurabyte_security.core.errores import ErrorEscaneoCancelado

                raise ErrorEscaneoCancelado(f"El escaneo de '{objetivo}' se cancelo.")
            time.sleep(0.02)
        raise AssertionError("El escaneo deberia haberse cancelado antes de este punto.")

    monkeypatch.setattr(modulo_paneles, "escanear_tcp", escanear_que_tarda)

    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await _preparar_proyecto_y_alcance(pilot)

        app.query_one("#redes-objetivo", Input).focus()
        await _escribir(pilot, "127.0.0.1")
        app.query_one("#redes-puertos", Input).focus()
        await _escribir(pilot, "80")

        await _clic_centro(pilot, "#redes-escanear")
        await pilot.pause()
        await _clic_centro(pilot, "#redes-cancelar")
        await app.workers.wait_for_complete()
        await pilot.pause()

        assert app.query_one("#redes-tabla", DataTable).row_count == 0
        mensaje = str(app.query_one("#redes-mensaje").render()).lower()
        assert "cancel" in mensaje

        base_datos = obtener_base_datos()
        proyecto = base_datos.obtener_proyecto_por_nombre("redes-test")
        assert base_datos.listar_resultados(proyecto.id) == []


async def test_dos_escaneos_consecutivos_no_mezclan_resultados(monkeypatch):
    import types

    def escaneo_falso(base_datos, proyecto, objetivo, puertos, *, tiempo_espera=1.0,
                       concurrencia=50, debe_cancelar=None):
        if objetivo == "10.0.0.1":
            time.sleep(0.3)  # el primer escaneo es deliberadamente lento
            return [types.SimpleNamespace(puerto=111, estado="abierto")]
        return [types.SimpleNamespace(puerto=222, estado="cerrado")]

    monkeypatch.setattr(modulo_paneles, "escanear_tcp", escaneo_falso)

    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await _preparar_proyecto_y_alcance(pilot)

        campo_objetivo = app.query_one("#redes-objetivo", Input)
        campo_puertos = app.query_one("#redes-puertos", Input)

        # Escaneo A: lento (tarda 0.3s en "completarse" dentro del fake).
        campo_objetivo.focus()
        await _escribir(pilot, "10.0.0.1")
        campo_puertos.focus()
        await _escribir(pilot, "111")
        await _clic_centro(pilot, "#redes-escanear")
        await pilot.pause()

        # Escaneo B: se dispara enseguida, sin esperar a que A termine.
        campo_objetivo.value = ""
        campo_objetivo.focus()
        await _escribir(pilot, "10.0.0.2")
        campo_puertos.value = ""
        campo_puertos.focus()
        await _escribir(pilot, "222")
        await _clic_centro(pilot, "#redes-escanear")

        await app.workers.wait_for_complete()
        await pilot.pause()

        tabla = app.query_one("#redes-tabla", DataTable)
        assert tabla.row_count == 1
        assert tabla.get_row_at(0) == ["222", "cerrado"]


async def test_error_inesperado_en_panel_redes_no_cierra_la_interfaz(monkeypatch):
    def escaneo_roto(*args, **kwargs):
        raise RuntimeError("fallo interno simulado")

    monkeypatch.setattr(modulo_paneles, "escanear_tcp", escaneo_roto)

    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await _preparar_proyecto_y_alcance(pilot)

        app.query_one("#redes-objetivo", Input).focus()
        await _escribir(pilot, "127.0.0.1")
        app.query_one("#redes-puertos", Input).focus()
        await _escribir(pilot, "80")
        await _clic_centro(pilot, "#redes-escanear")
        await app.workers.wait_for_complete()
        await pilot.pause()

        mensaje = str(app.query_one("#redes-mensaje").render())
        assert "inesperado" in mensaje.lower()

        # La aplicacion debe seguir viva y respondiendo a otras acciones.
        app.query_one("#switcher-central", ContentSwitcher).current = "panel-proyectos"
        await pilot.pause()
        assert app.query_one("#switcher-central", ContentSwitcher).current == "panel-proyectos"


# ---------------------------------------------------------------------------
# Terminal AST: entradas con marcado Rich no deben romper nada.
# ---------------------------------------------------------------------------


async def test_terminal_sobrevive_a_texto_con_corchetes_rich():
    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.query_one("#switcher-central", ContentSwitcher).current = "panel-terminal"
        await pilot.pause()
        entrada = app.query_one("#entrada-terminal", Input)

        entrada.focus()
        await _escribir(pilot, 'explicar "[/]"')
        await pilot.press("enter")
        await app.workers.wait_for_complete()
        await pilot.pause()

        # La terminal sigue funcionando: un comando normal despues sigue dando resultado.
        entrada.focus()
        await _escribir(pilot, "ayuda")
        await pilot.press("enter")
        await app.workers.wait_for_complete()
        await pilot.pause()


async def test_alcance_con_corchetes_no_crashea_el_panel():
    app = AuraByteApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await _preparar_proyecto_y_alcance(pilot, nombre="alcance-raro")

        app.query_one("#switcher-central", ContentSwitcher).current = "panel-alcance"
        await pilot.pause()
        campo = app.query_one("#alc-objetivo", Input)
        campo.value = ""
        campo.focus()
        await _escribir(pilot, "[/]")
        await _clic_centro(pilot, "#alc-agregar")
        await pilot.pause()

        mensaje = str(app.query_one("#alc-mensaje").render())
        assert "[/]" in mensaje or "valida" in mensaje.lower()
