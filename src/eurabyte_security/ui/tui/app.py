"""Aplicacion Textual de AURABYTE Security Terminal (comando ``est interfaz``)."""

from __future__ import annotations

from pathlib import Path

from textual import events, on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.css.query import NoMatches
from textual.widgets import Button, ContentSwitcher, Input, OptionList, TabbedContent, TabPane

from eurabyte_security.integrations.deteccion import HerramientaExterna, detectar_herramientas
from eurabyte_security.marca import ABREVIATURA, NOMBRE_PRODUCTO
from eurabyte_security.ui.tui.catalogo import SECCIONES_POR_PANEL
from eurabyte_security.ui.tui.estado import construir_estado
from eurabyte_security.ui.tui.widgets.navegacion import BarraEstado, BarraLateral, Encabezado
from eurabyte_security.ui.tui.widgets.operaciones import PanelOperaciones
from eurabyte_security.ui.tui.widgets.paneles import (
    PanelAlcance,
    PanelAuditoriaWeb,
    PanelAyuda,
    PanelConfiguracion,
    PanelHerramientas,
    PanelInicio,
    PanelModulos,
    PanelOSINT,
    PanelOWASPZAP,
    PanelProyectos,
    PanelReconocimiento,
    PanelRedes,
    PanelReportes,
    PanelResultados,
    PanelVulnerabilidades,
)
from eurabyte_security.ui.tui.widgets.terminal import (
    EntradaTerminal,
    PanelInfoComando,
    PanelTerminalAST,
)
from eurabyte_security.ui.tui.widgets.trafico import PanelTrafico

_RUTA_CSS = Path(__file__).with_name("estilos.tcss")

# Umbrales de adaptacion responsiva (columnas de terminal disponibles).
ANCHO_OCULTAR_INFO = 100
ANCHO_LATERAL_COMPACTO = 90
ANCHO_ENCABEZADO_COMPACTO = 110
ANCHO_ENCABEZADO_MINIMO = 66


class AuraByteApp(App[None]):
    """Interfaz visual completa de AURABYTE Security Terminal."""

    CSS_PATH = _RUTA_CSS
    TITLE = f"{NOMBRE_PRODUCTO} ({ABREVIATURA})"

    BINDINGS = [
        ("ctrl+q", "quit", "Salir"),
        ("f1", "abrir_modulos", "Módulos"),
        ("f2", "alternar_info", "Info"),
        ("f3", "enfocar_menu", "Menú"),
        ("f4", "abrir_terminal", "Terminal"),
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
                yield PanelModulos(id="panel-modulos")
                yield PanelReconocimiento(id="panel-reconocimiento")
                yield PanelAuditoriaWeb(id="panel-web")
                yield PanelVulnerabilidades(id="panel-vulnerabilidades")
                yield PanelOWASPZAP(id="panel-zap")
                yield PanelOSINT(id="panel-osint")
                yield PanelRedes(id="panel-redes")
                yield PanelTrafico(id="panel-trafico")
                yield PanelHerramientas(id="panel-herramientas")
                yield PanelResultados(id="panel-resultados")
                yield PanelOperaciones(id="panel-operaciones")
                yield PanelReportes(id="panel-reportes")
                yield PanelAyuda(id="panel-aprendizaje")
                yield PanelConfiguracion(id="panel-configuracion")
            yield PanelInfoComando(id="panel-info")
        yield BarraEstado(id="barra-estado", markup=False)

    def on_mount(self) -> None:
        switcher = self.query_one("#switcher-central", ContentSwitcher)
        self.watch(switcher, "current", self._sincronizar_panel, init=False)
        self._sincronizar_panel(switcher.current)
        self.query_one(BarraLateral).focus()
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
        self.call_from_thread(self.actualizar_herramientas_info, herramientas)

    def actualizar_herramientas_info(self, herramientas: list[HerramientaExterna]) -> None:
        self.query_one(PanelInfoComando).actualizar_herramientas(herramientas)

    def refrescar_estado(self) -> None:
        """Vuelve a leer el estado (proyecto activo, conteos...) y lo propaga a la UI."""
        estado = construir_estado()
        self.query_one(PanelOperaciones).cambiar_proyecto(estado.proyecto_activo)
        self.query_one(Encabezado).actualizar(estado)
        self.query_one(BarraEstado).actualizar(estado)
        self.query_one(PanelInicio).actualizar_estado(estado)
        self.query_one(PanelInfoComando).actualizar_estado(estado)

    @on(OptionList.OptionSelected, "#barra-lateral")
    def _seleccionar_panel(self, evento: OptionList.OptionSelected) -> None:
        if evento.option_id:
            self._mostrar_panel(evento.option_id)

    @on(Button.Pressed, ".acceso-panel")
    def _abrir_acceso(self, evento: Button.Pressed) -> None:
        destino = evento.button.name
        if destino:
            self._mostrar_panel(destino)
            self.action_enfocar_menu()

    def _sincronizar_panel(self, id_panel: str | None) -> None:
        if id_panel in SECCIONES_POR_PANEL:
            self.query_one(BarraLateral).actualizar(id_panel)
            self.query_one(PanelInfoComando).mostrar_seccion(SECCIONES_POR_PANEL[id_panel])

    def _mostrar_panel(self, id_panel: str) -> None:
        if self.size.width < ANCHO_OCULTAR_INFO and self._info_forzado:
            self._info_forzado = None
            self._ajustar_responsivo(self.size.width)
        self.query_one("#switcher-central", ContentSwitcher).current = id_panel
        self._refrescar_panel(id_panel)

    def _refrescar_panel(self, id_panel: str) -> None:
        try:
            panel = self.query_one(f"#{id_panel}")
        except NoMatches:
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

    def action_abrir_modulos(self) -> None:
        self._mostrar_panel("panel-modulos")
        self.action_enfocar_menu()

    def action_enfocar_menu(self) -> None:
        barra = self.query_one(BarraLateral)
        barra.focus()
        barra.scroll_to_highlight()

    @on(Button.Pressed, "#encabezado-menu")
    def _enfocar_menu_click(self, _evento: Button.Pressed) -> None:
        self.action_enfocar_menu()

    def action_abrir_terminal(self) -> None:
        self._mostrar_panel("panel-terminal")
        self.query_one("#panel-terminal", TabbedContent).active = "tab-terminal"
        self.query_one(EntradaTerminal).focus()

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
        info_ampliada = info_visible and ancho < ANCHO_OCULTAR_INFO
        info = self.query_one(PanelInfoComando)
        info.set_class(not info_visible, "oculto")
        info.set_class(info_ampliada, "ampliado")
        self.query_one("#switcher-central").set_class(info_ampliada, "info-en-primer-plano")
        self.query_one(BarraLateral).set_class(ancho < ANCHO_LATERAL_COMPACTO, "compacta")
        encabezado = self.query_one(Encabezado)
        encabezado.set_class(ancho < ANCHO_ENCABEZADO_COMPACTO, "compacto")
        encabezado.set_class(ancho < ANCHO_ENCABEZADO_MINIMO, "minimo")
        encabezado.actualizar_boton_info(info_visible)
