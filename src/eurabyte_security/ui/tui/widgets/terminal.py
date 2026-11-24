"""Pestaña 'Terminal AST': entrada de comandos, historial y panel de ayuda."""

from __future__ import annotations

from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.suggester import Suggester
from textual.widgets import Input, RichLog, Static

from eurabyte_security.commands.explicar import EXPLICACIONES
from eurabyte_security.integrations.deteccion import HerramientaExterna
from eurabyte_security.ui.consola import texto_seguro
from eurabyte_security.ui.tui.catalogo import Seccion
from eurabyte_security.ui.tui.estado import EstadoAST
from eurabyte_security.ui.tui.motor_comandos import MotorComandos, completar


class _SugeridorComandos(Suggester):
    """Sugiere, mientras el usuario escribe, la unica completion posible."""

    def __init__(self) -> None:
        super().__init__(use_cache=False, case_sensitive=False)

    async def get_suggestion(self, value: str) -> str | None:
        sugerencia = completar(value)
        if sugerencia is None or sugerencia.strip() == value.strip():
            return None
        return sugerencia.rstrip()


class EntradaTerminal(Input):
    """Campo de entrada con historial (flechas) y autocompletado (Tab)."""

    BINDINGS = [
        Binding("up", "historial_arriba", "Anterior", show=False),
        Binding("down", "historial_abajo", "Siguiente", show=False),
        Binding("tab", "autocompletar", "Autocompletar", show=False),
    ]

    def __init__(self, **kwargs: object) -> None:
        super().__init__(suggester=_SugeridorComandos(), **kwargs)
        self._historial: list[str] = []
        self._indice: int | None = None

    def agregar_historial(self, texto: str) -> None:
        texto = texto.strip()
        if texto and (not self._historial or self._historial[-1] != texto):
            self._historial.append(texto)
        self._indice = None

    def action_historial_arriba(self) -> None:
        if not self._historial:
            return
        self._indice = (
            len(self._historial) - 1 if self._indice is None else max(0, self._indice - 1)
        )
        self.value = self._historial[self._indice]
        self.action_end()

    def action_historial_abajo(self) -> None:
        if self._indice is None:
            return
        if self._indice < len(self._historial) - 1:
            self._indice += 1
            self.value = self._historial[self._indice]
        else:
            self._indice = None
            self.value = ""
        self.action_end()

    def action_autocompletar(self) -> None:
        sugerencia = completar(self.value)
        if sugerencia:
            self.value = sugerencia
            self.action_end()


class PanelTerminalAST(Vertical):
    """Terminal interactiva de AST con historial desplazable y entrada."""

    def __init__(self, motor: MotorComandos | None = None, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self.motor = motor or MotorComandos()

    def compose(self) -> ComposeResult:
        yield Static("Tab Completar  ·  ↑ ↓ Historial  ·  Enter Ejecutar", classes="ast-tenue")
        yield RichLog(id="historial-terminal", wrap=True, markup=True, highlight=False)
        yield EntradaTerminal(
            placeholder="est> Escribe «ayuda» para ver los comandos",
            id="entrada-terminal",
        )

    def on_mount(self) -> None:
        self._registro = self.query_one("#historial-terminal", RichLog)
        self._registro.write(
            "[bold cyan]Terminal AST[/bold cyan] - escribe 'ayuda' para ver los comandos."
        )

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "entrada-terminal":
            return
        texto = event.value
        entrada = event.input
        assert isinstance(entrada, EntradaTerminal)
        entrada.agregar_historial(texto)
        entrada.value = ""
        if texto.strip():
            self._registro.write(f"[bold]est>[/bold] {texto_seguro(texto)}")
            self._ejecutar(texto)

    @work(thread=True, exclusive=False, group="terminal-comandos", exit_on_error=False)
    def _ejecutar(self, texto: str) -> None:
        try:
            resultado = self.motor.ejecutar(texto)
        except Exception as exc:  # noqa: BLE001 - frontera de la terminal interactiva
            self.app.call_from_thread(
                self._registro.write,
                f"[bold red]Error inesperado:[/bold red] {texto_seguro(exc)}",
            )
            return

        if resultado is None:
            self.app.call_from_thread(
                self._registro.write,
                "[dim]'salir' no cierra la interfaz visual; usa Ctrl+Q.[/dim]",
            )
            return
        if resultado.exito:
            contenido = (
                texto_seguro(resultado.contenido)
                if isinstance(resultado.contenido, str)
                else resultado.contenido
            )
            self.app.call_from_thread(self._registro.write, contenido)
        else:
            self.app.call_from_thread(
                self._registro.write,
                f"[bold red]Error:[/bold red] {texto_seguro(resultado.contenido)}",
            )
        self.app.call_from_thread(self.app.refrescar_estado)  # type: ignore[attr-defined]


class PanelInfoComando(VerticalScroll):
    """Ficha de la sección abierta, ayuda de la terminal y estado de herramientas."""

    def compose(self) -> ComposeResult:
        yield Static("Inicio", id="info-titulo", classes="titulo-panel", markup=False)
        yield Static(id="info-seccion", markup=False)
        yield Static(id="info-comando-cuerpo", classes="info-comando oculto")
        yield Static(id="info-proyecto", classes="ast-caja", markup=False)
        yield Static("Comprobando herramientas externas…", id="info-herramientas",
                     classes="ast-caja", markup=False)

    def mostrar_seccion(self, seccion: Seccion) -> None:
        self.query_one("#info-titulo", Static).update(seccion.titulo)
        ficha = Text(seccion.descripcion + "\n\n")
        ficha.append("Requisitos\n", style="bold #66e3cd")
        ficha.append(seccion.requisitos)
        self.query_one("#info-seccion", Static).update(ficha)
        self.query_one("#info-comando-cuerpo").set_class(
            seccion.panel != "panel-terminal", "oculto"
        )
        self.scroll_home(animate=False)

    def mostrar_tema(self, token: str | None) -> None:
        texto = EXPLICACIONES.get(token.lower()) if token else None
        self.query_one("#info-comando-cuerpo", Static).update(texto or "")

    def actualizar_estado(self, estado: EstadoAST) -> None:
        proyecto = estado.proyecto_activo or "Sin proyecto activo"
        texto = Text()
        texto.append("Proyecto activo\n", style="bold #e6edf6")
        texto.append(f"{proyecto}\n")
        texto.append(f"Objetivos: {estado.total_alcances}\nResultados: {estado.total_resultados}")
        self.query_one("#info-proyecto", Static).update(texto)

    def actualizar_herramientas(self, herramientas: list[HerramientaExterna]) -> None:
        texto = Text()
        texto.append("Herramientas externas", style="bold #e6edf6")
        for herramienta in herramientas:
            texto.append(f"\n{herramienta.nombre}  ")
            if herramienta.instalada:
                texto.append("Disponible", style="#66e3cd")
                if herramienta.version:
                    texto.append(f" ({herramienta.version})")
            else:
                texto.append("No disponible", style="#a2b1c8")
        self.query_one("#info-herramientas", Static).update(texto)
