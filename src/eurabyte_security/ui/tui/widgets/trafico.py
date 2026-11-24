"""Panel de tráfico del equipo y de registros de la LAN."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from rich.console import Group
from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.widget import Widget
from textual.widgets import Button, Collapsible, Input, Static, TabbedContent, TabPane

from eurabyte_security.commands.trafico import mostrar_medicion, mostrar_red
from eurabyte_security.core.errores import ErrorEST, ErrorValidacion
from eurabyte_security.modules.network.trafico import medir_equipo, resumir_red


class PanelTrafico(Widget):
    """Presenta los datos que el operador mide o importa explícitamente."""

    DEFAULT_CSS = """
    PanelTrafico, #trafico-pestanas, #trafico-pestanas TabPane {
        height: 1fr;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("Tráfico de red", classes="titulo-panel")
        with TabbedContent(id="trafico-pestanas"):
            with TabPane("Este equipo", id="trafico-equipo"):
                with VerticalScroll():
                    yield Static(
                        "Carga, descarga y velocidad por interfaz. Las aplicaciones se "
                        "identifican por sus conexiones abiertas si el sistema da permiso.",
                        classes="ast-tenue",
                    )
                    yield Button("Medir 1 segundo", id="trafico-medir", variant="primary")
                    yield Static(id="trafico-medicion")
            with TabPane("Registros LAN", id="trafico-lan"):
                with VerticalScroll():
                    yield Static(
                        "Carga registros Zeek en JSON, un objeto por línea.",
                        classes="ast-tenue",
                    )
                    yield Static("Subredes LAN en CIDR", classes="trafico-etiqueta")
                    yield Input(placeholder="Ej. 192.168.1.0/24", id="trafico-cidr")
                    yield Static("Registro de conexiones", classes="trafico-etiqueta")
                    yield Input(placeholder="Ruta a conn.log", id="trafico-conn")
                    yield Button("Analizar registros", id="trafico-analizar", variant="primary")
                    with Collapsible(title="Fuentes de dominios (opcional)", id="trafico-fuentes"):
                        yield Static("Consultas DNS", classes="trafico-etiqueta")
                        yield Input(placeholder="Ruta a dns.log", id="trafico-dns")
                        yield Static("Dominios web observados", classes="trafico-etiqueta")
                        yield Input(placeholder="Ruta a http.log o ssl.log", id="trafico-web")
                    yield Static(id="trafico-resumen")

    @on(Button.Pressed, "#trafico-medir")
    def _medir(self, evento: Button.Pressed) -> None:
        self._procesar(evento.button, "#trafico-medicion", lambda: mostrar_medicion(medir_equipo()))

    @on(Button.Pressed, "#trafico-analizar")
    def _analizar(self, evento: Button.Pressed) -> None:
        cidr = self.query_one("#trafico-cidr", Input).value.strip()
        conn = self.query_one("#trafico-conn", Input).value.strip()
        dns = self.query_one("#trafico-dns", Input).value.strip()
        web = self.query_one("#trafico-web", Input).value.strip()

        def resumen() -> Group:
            if not conn:
                raise ErrorValidacion("Introduce la ruta de conn.log.")
            return mostrar_red(resumir_red(
                Path(conn).expanduser(),
                cidr,
                Path(dns).expanduser() if dns else None,
                Path(web).expanduser() if web else None,
            ))

        self._procesar(evento.button, "#trafico-resumen", resumen)

    def _procesar(self, boton: Button, selector: str, operacion: Callable[[], Group]) -> None:
        salida = self.query_one(selector, Static)
        boton.disabled = True
        salida.update(Text("Procesando…"))
        self._calcular(boton, salida, operacion)

    @work(thread=True, exit_on_error=False)
    def _calcular(self, boton: Button, salida: Static, operacion: Callable[[], Group]) -> None:
        resultado: Group | Text
        try:
            resultado = operacion()
        except ErrorEST as exc:
            resultado = Text(str(exc), style="red")
        except (OSError, RuntimeError, ValueError):
            resultado = Text("No se pudo completar el análisis. Revisa los datos de entrada.",
                             style="red")
        self.app.call_from_thread(salida.update, resultado)
        self.app.call_from_thread(setattr, boton, "disabled", False)
