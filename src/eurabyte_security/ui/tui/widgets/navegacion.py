"""Barra superior, barra lateral de navegacion y barra de estado inferior."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import OptionList, Static
from textual.widgets.option_list import Option

from eurabyte_security import __version__
from eurabyte_security.marca import ABREVIATURA, ESCUDO_COMPACTO, NOMBRE_PRODUCTO
from eurabyte_security.ui.tui.estado import EstadoAST

# (etiqueta visible, id del panel asociado en el ContentSwitcher)
SECCIONES: tuple[tuple[str, str], ...] = (
    ("Inicio", "panel-inicio"),
    ("Terminal", "panel-terminal"),
    ("Proyectos", "panel-proyectos"),
    ("Alcance", "panel-alcance"),
    ("Modulos", "panel-modulos"),
    ("Reconocimiento", "panel-reconocimiento"),
    ("Analisis web", "panel-web"),
    ("Vulnerabilidades", "panel-vulnerabilidades"),
    ("OWASP ZAP", "panel-zap"),
    ("Redes", "panel-redes"),
    ("Herramientas", "panel-herramientas"),
    ("Resultados", "panel-resultados"),
    ("Reportes", "panel-reportes"),
    ("Aprendizaje", "panel-aprendizaje"),
    ("Configuracion", "panel-configuracion"),
)


class Encabezado(Horizontal):
    """Barra superior: logo, nombre, version, proyecto activo y sistema operativo."""

    def compose(self) -> ComposeResult:
        yield Static(ESCUDO_COMPACTO, classes="logo")
        yield Static(f" {NOMBRE_PRODUCTO} ({ABREVIATURA}) ", classes="nombre")
        yield Static(f"v{__version__}", id="encabezado-version", classes="dato")
        yield Static("", id="encabezado-proyecto", classes="dato")
        yield Static("", id="encabezado-so", classes="dato")

    def actualizar(self, estado: EstadoAST) -> None:
        proyecto = estado.proyecto_activo or "(sin proyecto activo)"
        self.query_one("#encabezado-proyecto", Static).update(f" | Proyecto: {proyecto} ")
        self.query_one("#encabezado-so", Static).update(f" | {estado.sistema_operativo} ")


class BarraLateral(OptionList):
    """Navegacion principal entre secciones de AST."""

    def on_mount(self) -> None:
        for etiqueta, id_panel in SECCIONES:
            self.add_option(Option(etiqueta, id=id_panel))


class BarraEstado(Static):
    """Barra inferior: estado del sistema, proyecto, alcance, resultados y BD."""

    def actualizar(self, estado: EstadoAST) -> None:
        proyecto = estado.proyecto_activo or "(ninguno)"
        estado_bd = "BD ok" if estado.base_datos_ok else "BD con errores"
        self.update(
            f"Proyecto: {proyecto}  |  Objetivos autorizados: {estado.total_alcances}  |  "
            f"Resultados: {estado.total_resultados}  |  Base de datos: {estado_bd}  |  "
            f"{NOMBRE_PRODUCTO} v{__version__}"
        )
        self.set_classes("ok" if estado.base_datos_ok else "error")
