"""Verifica que la deteccion de herramientas externas no congele la interfaz.

Documenta, con mediciones reales (no supuestos), el problema corregido: medido con
``time.perf_counter()`` fuera de estas pruebas, ``AdaptadorZAP().info()`` sin una
instancia de ZAP corriendo tarda ~2s (timeout de conexion por defecto) y
``detectar_herramientas()`` (cuatro binarios/servicios) tarda ~0.6s -- y antes de este
cambio, ambas se llamaban de forma sincrona justo en el manejador de evento que cambia
de panel (``AuraByteApp._refrescar_panel``) o en ``on_mount``, bloqueando el hilo
principal de Textual cada vez. Estas pruebas simulan ese mismo retraso con un doble y
comprueban que el cambio de panel / el arranque de la app ya no esperan ese tiempo: el
trabajo real ocurre en un worker (ver ``@work(thread=True)`` en ``widgets/paneles.py``
y ``ui/tui/app.py``).
"""

from __future__ import annotations

import time
from threading import Event

from textual.widgets import ContentSwitcher, DataTable, Static

from eurabyte_security.integrations.deteccion import HerramientaExterna
from eurabyte_security.integrations.zap import InfoZAP
from eurabyte_security.ui.tui.app import AuraByteApp
from eurabyte_security.ui.tui.widgets import paneles as modulo_paneles

UMBRAL_SIN_BLOQUEO_SEGUNDOS = 0.5


async def _esperar_hasta(pilot, condicion, *, intentos: int = 50) -> None:
    """Espera a que ``condicion()`` sea verdadera, sin depender de los workers que ya
    estaban en curso al montar el panel (p. ej. el primer 'refrescar()' automatico de
    ``on_mount``, que el 'refrescar()' explicito de la prueba cancela por ser del mismo
    grupo exclusivo): ``app.workers.wait_for_complete()`` propagaria la cancelacion de
    ese worker anterior aunque el mas reciente si haya terminado bien.
    """
    for _ in range(intentos):
        if condicion():
            return
        await pilot.pause(delay=0.05)
    raise AssertionError("La condicion no se cumplio a tiempo.")


async def test_cambiar_a_owasp_zap_no_bloquea_aunque_la_deteccion_tarde(monkeypatch):
    def info_lenta(self):
        time.sleep(1.5)
        return InfoZAP(disponible=False, version=None, mensaje="simulado")

    monkeypatch.setattr(modulo_paneles.AdaptadorZAP, "info", info_lenta)

    app = AuraByteApp()
    async with app.run_test(size=(120, 35)) as pilot:
        await pilot.pause()

        t0 = time.perf_counter()
        app.query_one("#switcher-central", ContentSwitcher).current = "panel-zap"
        app._refrescar_panel("panel-zap")
        duracion = time.perf_counter() - t0

        assert duracion < UMBRAL_SIN_BLOQUEO_SEGUNDOS, (
            f"Cambiar a 'OWASP ZAP' tardo {duracion:.2f}s de forma sincrona: la "
            "deteccion deberia correr en un worker, no bloquear el cambio de panel."
        )

        def _detectado() -> bool:
            texto = str(
                app.query_one("#panel-zap").query_one("#zap-deteccion", Static).render()
            )
            return "comprobando" not in texto.lower()

        await _esperar_hasta(pilot, _detectado)
        texto = str(app.query_one("#panel-zap").query_one("#zap-deteccion", Static).render())
        assert "no disponible" in texto.lower()


async def test_cambiar_a_herramientas_no_bloquea_aunque_la_deteccion_tarde(monkeypatch):
    def deteccion_lenta():
        time.sleep(1.0)
        return [
            HerramientaExterna(
                nombre="Nmap", comando="nmap", instalada=False, version=None, ruta=None
            )
        ]

    monkeypatch.setattr(modulo_paneles, "detectar_herramientas", deteccion_lenta)

    app = AuraByteApp()
    async with app.run_test(size=(120, 35)) as pilot:
        await pilot.pause()

        t0 = time.perf_counter()
        app.query_one("#switcher-central", ContentSwitcher).current = "panel-herramientas"
        app._refrescar_panel("panel-herramientas")
        duracion = time.perf_counter() - t0

        assert duracion < UMBRAL_SIN_BLOQUEO_SEGUNDOS, (
            f"Cambiar a 'Herramientas' tardo {duracion:.2f}s de forma sincrona."
        )

        tabla = app.query_one("#panel-herramientas").query_one("#herr-tabla", DataTable)
        await _esperar_hasta(pilot, lambda: tabla.row_count == 1)


async def test_arranque_de_la_app_no_espera_la_deteccion_de_herramientas(monkeypatch):
    from eurabyte_security.ui.tui import app as modulo_app

    iniciada = Event()
    permitir_finalizar = Event()
    finalizada = Event()

    def deteccion_lenta():
        iniciada.set()
        permitir_finalizar.wait(timeout=10)
        finalizada.set()
        return []

    monkeypatch.setattr(modulo_app, "detectar_herramientas", deteccion_lenta)

    app = AuraByteApp()
    async with app.run_test(size=(120, 35)) as pilot:
        try:
            await _esperar_hasta(pilot, iniciada.is_set)
            assert not finalizada.is_set(), "La interfaz esperó la detección antes de arrancar."
            assert app.query_one("#switcher-central", ContentSwitcher).current == "panel-inicio"
            workers_inicio = [w for w in app.workers if w.group == "deteccion-inicial"]
            assert len(workers_inicio) == 1
        finally:
            permitir_finalizar.set()
        await app.workers.wait_for_complete(workers_inicio)
        assert finalizada.is_set()
