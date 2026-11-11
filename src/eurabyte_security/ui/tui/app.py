"""Aplicacion Textual de AURABYTE Security Terminal (comando ``est interfaz``)."""

from __future__ import annotations

from pathlib import Path

from textual import events, on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, ContentSwitcher, Input, OptionList, TabbedContent, TabPane

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
    PanelOSINT,
    PanelOWASPZAP,
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
ANCHO_LATERAL_COMPACTO = 90
ANCHO_ENCABEZADO_COMPACTO = 90


class AuraByteApp(App[None]):
    """Interfaz visual completa de AURABYTE Security Terminal."""

    CSS_PATH = _RUTA_CSS
    TITLE = f"{NOMBRE_PRODUCTO} ({ABREVIATURA})"

    BINDINGS = [
        ("ctrl+q", "quit", "Salir"),
        ("f2", "alternar_info", "Info"),
    ]

    # None = sigue el ancho de la terminal (ver _info_debe_mostrarse); True/False = el
    # usuario lo forzo con el boton "Info" del encabezado o con F2, y eso prevalece sobre
    # el ancho hasta que lo vuelva a cambiar.
    _info_forzado: bool | None = None

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
                yield PanelOWASPZAP(id="panel-zap")
                yield PanelOSINT(id="panel-osint")
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
        self._ajustar_responsivo(self.size.width)
        self._detectar_herramientas_en_fondo()

    # 'detectar_herramientas()' comprueba 4 binarios/servicios externos (~0.6s medido
    # empiricamente, ver docs/ROADMAP.md): ejecutarla aqui directamente retrasaria el
    # primer pintado interactivo de toda la interfaz. Un worker deja que la app responda
    # de inmediato y la lista de 'Herramientas' se complete un instante despues.
    @work(thread=True, exclusive=True, group="deteccion-inicial", exit_on_error=False)
    def _detectar_herramientas_en_fondo(self) -> None:
        herramientas = detectar_herramientas()
        self.call_from_thread(
            self.query_one(PanelInfoComando).actualizar_herramientas, herramientas
        )

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

    def action_alternar_info(self) -> None:
        """Pliega/despliega el panel contextual derecho a demanda (tecla F2 o boton)."""
        visible_actual = self._info_debe_mostrarse(self.size.width)
        self._info_forzado = not visible_actual
        self._ajustar_responsivo(self.size.width)

    @on(Button.Pressed, "#encabezado-info-toggle")
    def _alternar_info_click(self, _evento: Button.Pressed) -> None:
        self.action_alternar_info()

    def _info_debe_mostrarse(self, ancho: int) -> bool:
        if self._info_forzado is not None:
            return self._info_forzado
        return ancho >= ANCHO_OCULTAR_INFO

    def _ajustar_responsivo(self, ancho: int) -> None:
        info_visible = self._info_debe_mostrarse(ancho)
        self.query_one("#panel-info").set_classes("" if info_visible else "oculto")
        self.query_one(Encabezado).actualizar_boton_info(info_visible)
        self.query_one("#barra-lateral").set_classes(
            "compacta" if ancho < ANCHO_LATERAL_COMPACTO else ""
        )
        self.query_one("#encabezado").set_classes(
            "compacto" if ancho < ANCHO_ENCABEZADO_COMPACTO else ""
        )
