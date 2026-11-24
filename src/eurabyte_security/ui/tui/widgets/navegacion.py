"""Barra superior, barra lateral de navegacion y barra de estado inferior."""

from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, OptionList, Static
from textual.widgets.option_list import Option

from eurabyte_security import __version__
from eurabyte_security.marca import ABREVIATURA, ESCUDO_COMPACTO, NOMBRE_PRODUCTO
from eurabyte_security.ui.tui.catalogo import GRUPOS, SECCIONES_POR_PANEL, Seccion
from eurabyte_security.ui.tui.estado import EstadoAST


class Encabezado(Horizontal):
    """Barra superior: logo, nombre, version, proyecto activo y sistema operativo."""

    def compose(self) -> ComposeResult:
        yield Static(ESCUDO_COMPACTO, classes="logo")
        yield Static(f" {NOMBRE_PRODUCTO} ({ABREVIATURA}) ", classes="nombre")
        yield Static(f"v{__version__}", id="encabezado-version", classes="dato")
        yield Static("", id="encabezado-proyecto", classes="dato", markup=False)
        yield Static("", id="encabezado-so", classes="dato", markup=False)
        with Horizontal(id="encabezado-acciones"):
            yield Button("F3 Menú", id="encabezado-menu", classes="boton-info")
            yield Button("F2 Info", id="encabezado-info-toggle", classes="boton-info")

    def actualizar(self, estado: EstadoAST) -> None:
        proyecto = estado.proyecto_activo or "Sin proyecto"
        self.query_one("#encabezado-proyecto", Static).update(f"  /  {proyecto} ")
        self.query_one("#encabezado-so", Static).update(f"  ·  {estado.sistema_operativo} ")

    def actualizar_boton_info(self, visible: bool) -> None:
        """Refleja en el boton si el panel derecho esta visible o plegado."""
        boton = self.query_one("#encabezado-info-toggle", Button)
        boton.set_class(visible, "visible")
        boton.tooltip = "Ocultar información (F2)" if visible else "Mostrar información (F2)"


class BarraLateral(OptionList):
    """Navegacion principal entre secciones de AST."""

    _actual = "panel-inicio"

    def on_mount(self) -> None:
        for titulo, secciones in GRUPOS:
            self.add_option(Option(Text(titulo.upper(), style="bold #8493ac"), disabled=True))
            for seccion in secciones:
                self.add_option(Option(self._etiqueta(seccion), id=seccion.panel))
        self.highlighted = self.get_option_index(self._actual)

    def actualizar(self, panel: str) -> None:
        anterior = self._actual
        self._actual = panel
        self.highlighted = self.get_option_index(panel)
        if anterior != panel:
            for destino in (anterior, panel):
                self.replace_option_prompt(destino, self._etiqueta(SECCIONES_POR_PANEL[destino]))

    def _etiqueta(self, seccion: Seccion) -> Text:
        if seccion.panel == self._actual:
            return Text(f"▸ {seccion.titulo}", style="bold #66e3cd")
        return Text(f"  {seccion.titulo}")


class BarraEstado(Static):
    """Barra inferior: alcance, resultados y disponibilidad de SQLite."""

    def actualizar(self, estado: EstadoAST) -> None:
        estado_bd = "SQLite disponible" if estado.base_datos_ok else "Error de SQLite"
        texto = Text(f"Objetivos: {estado.total_alcances}  ·  "
                     f"Resultados: {estado.total_resultados}  ·  ")
        texto.append(estado_bd, style="#66e3cd" if estado.base_datos_ok else "#ff8d9a")
        texto.append("  ·  Ctrl+Q Salir")
        self.update(texto)
