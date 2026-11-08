"""Aplicacion Textual de AURABYTE Security Terminal (comando ``est interfaz``)."""

from __future__ import annotations

from pathlib import Path

from textual import events
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import ContentSwitcher, Input, OptionList, TabbedContent, TabPane

from eurabyte_security.integrations.deteccion import detectar_herramientas
from eurabyte_security.marca import ABREVIATURA, NOMBRE_PRODUCTO
from eurabyte_security.ui.tui.estado import construir_estado
from eurabyte_security.ui.tui.widgets.navegacion import BarraEstado, BarraLateral, Encabezado
from eurabyte_security.ui.tui.widgets.paneles import (
    PanelAlcance,
    PanelAuditoriaWeb,
    PanelAyuda,
    PanelConfiguracion,
    PanelHerramientas,
    PanelInicio,
    PanelProximamente,
    PanelProyectos,
    PanelReconocimiento,
    PanelRedes,
    PanelReportes,
    PanelResultados,
    PanelVulnerabilidades,
)
from eurabyte_security.ui.tui.widgets.terminal import PanelInfoComando, PanelTerminalAST

_RUTA_CSS = Path(__file__).with_name("estilos.tcss")

# Umbrales de adaptacion responsiva (columnas de terminal disponibles).
ANCHO_OCULTAR_INFO = 100
ANCHO_LATERAL_COMPACTO = 70


class AuraByteApp(App[None]):
    """Interfaz visual completa de AURABYTE Security Terminal."""

    CSS_PATH = _RUTA_CSS
    TITLE = f"{NOMBRE_PRODUCTO} ({ABREVIATURA})"

    BINDINGS = [
        ("ctrl+q", "quit", "Salir"),
    ]

    def compose(self) -> ComposeResult:
        yield Encabezado(id="encabezado")
        with Horizontal(id="cuerpo"):
            yield BarraLateral(id="barra-lateral")
            with ContentSwitcher(initial="panel-inicio", id="switcher-central"):
                yield PanelInicio(id="panel-inicio")
                with TabbedContent(id="panel-terminal"):
                    with TabPane("Terminal AST", id="tab-terminal"):
                        yield PanelTerminalAST(id="terminal-ast")
                    with TabPane("Resultados", id="tab-resultados"):
                        yield PanelResultados(id="resultados-en-terminal")
                    with TabPane("Ayuda", id="tab-ayuda"):
                        yield PanelAyuda(id="ayuda-en-terminal")
                yield PanelProyectos(id="panel-proyectos")
                yield PanelAlcance(id="panel-alcance")
                yield PanelProximamente("Modulos", "Fase 3", id="panel-modulos")
                yield PanelReconocimiento(id="panel-reconocimiento")
                yield PanelAuditoriaWeb(id="panel-web")
                yield PanelVulnerabilidades(id="panel-vulnerabilidades")
                yield PanelRedes(id="panel-redes")
                yield PanelHerramientas(id="panel-herramientas")
                yield PanelResultados(id="panel-resultados")
                yield PanelReportes(id="panel-reportes")
                yield PanelProximamente("Aprendizaje", "Fase 5", id="panel-aprendizaje")
                yield PanelConfiguracion(id="panel-configuracion")
            yield PanelInfoComando(id="panel-info")
        yield BarraEstado(id="barra-estado")

    def on_mount(self) -> None:
        self.refrescar_estado()
        self.query_one(PanelInfoComando).actualizar_herramientas(detectar_herramientas())
        self._ajustar_responsivo(self.size.width)

    def refrescar_estado(self) -> None:
        """Vuelve a leer el estado (proyecto activo, conteos...) y lo propaga a la UI."""
        estado = construir_estado()
        self.query_one(Encabezado).actualizar(estado)
        self.query_one(BarraEstado).actualizar(estado)
        self.query_one(PanelInicio).actualizar_estado(estado)
        self.query_one(PanelInfoComando).actualizar_estado(estado)

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if not event.option_id:
            return
        self.query_one("#switcher-central", ContentSwitcher).current = event.option_id
        self._refrescar_panel(event.option_id)

    def _refrescar_panel(self, id_panel: str) -> None:
        try:
            panel = self.query_one(f"#{id_panel}")
        except Exception:
            return
        refrescar = getattr(panel, "refrescar", None)
        if callable(refrescar):
            refrescar()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "entrada-terminal":
            return
        texto = event.value.strip()
        primer_token = texto.split(" ")[0] if texto else None
        self.query_one(PanelInfoComando).mostrar_tema(primer_token)

    def on_resize(self, event: events.Resize) -> None:
        self._ajustar_responsivo(event.size.width)

    def _ajustar_responsivo(self, ancho: int) -> None:
        self.query_one("#panel-info").set_classes("oculto" if ancho < ANCHO_OCULTAR_INFO else "")
        self.query_one("#barra-lateral").set_classes(
            "compacta" if ancho < ANCHO_LATERAL_COMPACTO else ""
        )
