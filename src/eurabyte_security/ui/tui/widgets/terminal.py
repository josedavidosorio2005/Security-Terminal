"""Pestaña 'Terminal AST': entrada de comandos, historial y panel de ayuda."""

from __future__ import annotations

from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.suggester import Suggester
from textual.widgets import Input, RichLog, Static

from eurabyte_security.commands.explicar import EXPLICACIONES
from eurabyte_security.integrations.deteccion import HerramientaExterna
from eurabyte_security.marca import BANNER_ASCII
from eurabyte_security.ui.consola import texto_seguro
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
    """Terminal interactiva real de AST: banner, historial desplazable y entrada."""

    def __init__(self, motor: MotorComandos | None = None, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self.motor = motor or MotorComandos()

    def compose(self) -> ComposeResult:
        yield Static(BANNER_ASCII, id="banner-ast")
        yield RichLog(id="historial-terminal", wrap=True, markup=True, highlight=False)
        yield EntradaTerminal(
            placeholder="Escribe un comando (ayuda, proyecto crear NOMBRE, escanear tcp ...)",
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


class PanelInfoComando(Vertical):
    """Panel lateral derecho: ayuda contextual, proyecto actual y herramientas."""

    def compose(self) -> ComposeResult:
        yield Static("Informacion", classes="titulo-panel")
        yield Static(self._texto_por_defecto(), id="info-comando-cuerpo")
        yield Static("", id="info-proyecto", classes="ast-caja")
        yield Static("", id="info-herramientas", classes="ast-caja")

    @staticmethod
    def _texto_por_defecto() -> str:
        temas = ", ".join(sorted(EXPLICACIONES))
        return f"Escribe un comando en la Terminal AST para ver su ayuda aqui.\n\nTemas: {temas}"

    def mostrar_tema(self, token: str | None) -> None:
        cuerpo = self.query_one("#info-comando-cuerpo", Static)
        texto = EXPLICACIONES.get(token.lower()) if token else None
        cuerpo.update(texto if texto else self._texto_por_defecto())

    def actualizar_estado(self, estado: EstadoAST) -> None:
        proyecto = estado.proyecto_activo or "(ninguno)"
        self.query_one("#info-proyecto", Static).update(
            f"Proyecto actual: {proyecto}\n"
            f"Objetivos autorizados: {estado.total_alcances}\n"
            f"Resultados guardados: {estado.total_resultados}"
        )

    def actualizar_herramientas(self, herramientas: list[HerramientaExterna]) -> None:
        lineas = []
        for h in herramientas:
            if h.instalada:
                detalle = f"instalada ({texto_seguro(h.version)})" if h.version else "instalada"
            else:
                detalle = "no instalada"
            lineas.append(f"- {h.nombre}: {detalle}")
        self.query_one("#info-herramientas", Static).update(
            "Herramientas externas (Fase 3):\n" + "\n".join(lineas)
        )
