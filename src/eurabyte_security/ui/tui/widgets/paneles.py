"""Paneles de la interfaz AST: proyectos, alcance, redes, resultados, etc."""

from __future__ import annotations

from textual import on, work
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, DataTable, Input, Select, Static
from textual.worker import get_current_worker

from eurabyte_security.commands._comun import obtener_base_datos, resolver_proyecto
from eurabyte_security.commands.alcance import agregar_alcance, listar_alcance
from eurabyte_security.commands.escanear import escanear_tcp
from eurabyte_security.commands.explicar import EXPLICACIONES
from eurabyte_security.commands.proyecto import crear_proyecto, listar_proyectos, usar_proyecto
from eurabyte_security.commands.reporte import generar_reporte
from eurabyte_security.commands.resultados import obtener_resultados
from eurabyte_security.core.config import directorio_datos, ruta_base_datos, ruta_historial
from eurabyte_security.core.errores import ErrorEST
from eurabyte_security.integrations.deteccion import detectar_herramientas
from eurabyte_security.marca import BANNER_ASCII
from eurabyte_security.ui.tui.estado import EstadoAST


class PanelInicio(Vertical):
    """Panel de bienvenida: banner, resumen y atajos de navegacion."""

    def compose(self):
        yield Static(BANNER_ASCII, classes="ast-acento")
        yield Static("", id="inicio-resumen", classes="ast-caja")
        yield Static(
            "Sugerencias rapidas:\n"
            "  - 'Terminal': usa comandos de texto (ayuda, proyecto, alcance...).\n"
            "  - 'Proyectos': crea o activa un proyecto de auditoria.\n"
            "  - 'Alcance': autoriza objetivos antes de poder escanearlos.\n"
            "  - 'Redes': formulario de comprobacion TCP con cancelacion.\n"
            "  - 'Resultados' / 'Reportes': consulta y exporta lo encontrado.",
            classes="ast-tenue",
        )

    def actualizar_estado(self, estado: EstadoAST) -> None:
        proyecto = estado.proyecto_activo or "(ninguno)"
        self.query_one("#inicio-resumen", Static).update(
            f"Proyecto activo: {proyecto}\n"
            f"Objetivos autorizados: {estado.total_alcances}\n"
            f"Resultados guardados: {estado.total_resultados}\n"
            f"Sistema: {estado.sistema_operativo}"
        )


class PanelProyectos(Vertical):
    """Crear, listar y activar proyectos de auditoria."""

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._seleccionado: str | None = None

    def compose(self):
        yield Static("Proyectos de auditoria", classes="titulo-panel")
        with Horizontal():
            yield Input(placeholder="Nombre de nuevo proyecto", id="proy-nombre")
            yield Button("Crear", id="proy-crear", variant="primary")
        yield DataTable(id="proy-tabla", cursor_type="row")
        yield Button("Marcar seleccionado como activo", id="proy-usar")
        yield Static(
            "Selecciona una fila (Enter o clic) y luego 'Marcar como activo'.",
            id="proy-mensaje",
            classes="ast-tenue",
        )

    def on_mount(self) -> None:
        self.query_one("#proy-tabla", DataTable).add_columns("Activo", "Nombre", "Creado")
        self.refrescar()

    def _mensaje(self, texto: str, clase: str = "ast-tenue") -> None:
        msg = self.query_one("#proy-mensaje", Static)
        msg.update(texto)
        msg.set_classes(clase)

    def refrescar(self) -> None:
        base_datos = obtener_base_datos()
        proyectos, activo = listar_proyectos(base_datos)
        tabla = self.query_one("#proy-tabla", DataTable)
        tabla.clear()
        for proyecto in proyectos:
            tabla.add_row(
                "*" if proyecto.nombre == activo else "",
                proyecto.nombre,
                proyecto.creado_en,
                key=proyecto.nombre,
            )
        if not proyectos:
            self._mensaje("No hay proyectos todavia. Crea el primero arriba.")

    @on(Button.Pressed, "#proy-crear")
    def _crear(self, _evento: Button.Pressed) -> None:
        campo = self.query_one("#proy-nombre", Input)
        try:
            proyecto = crear_proyecto(obtener_base_datos(), campo.value)
            self._mensaje(
                f"Proyecto '{proyecto.nombre}' creado y marcado como activo.", "ast-exito"
            )
            campo.value = ""
            self.refrescar()
            self.app.refrescar_estado()  # type: ignore[attr-defined]
        except ErrorEST as exc:
            self._mensaje(str(exc), "ast-error")

    @on(DataTable.RowSelected, "#proy-tabla")
    def _fila_seleccionada(self, event: DataTable.RowSelected) -> None:
        self._seleccionado = event.row_key.value

    @on(Button.Pressed, "#proy-usar")
    def _usar(self, _evento: Button.Pressed) -> None:
        if not self._seleccionado:
            self._mensaje("Selecciona primero un proyecto en la tabla.", "ast-aviso")
            return
        try:
            proyecto = usar_proyecto(obtener_base_datos(), self._seleccionado)
            self._mensaje(f"Proyecto activo: '{proyecto.nombre}'.", "ast-exito")
            self.refrescar()
            self.app.refrescar_estado()  # type: ignore[attr-defined]
        except ErrorEST as exc:
            self._mensaje(str(exc), "ast-error")


class PanelAlcance(Vertical):
    """Registrar y consultar el alcance autorizado del proyecto activo."""

    def compose(self):
        yield Static("Alcance autorizado", classes="titulo-panel")
        yield Static(
            "Solo se puede escanear lo registrado aqui (ver panel 'Redes').",
            classes="ast-tenue",
        )
        with Horizontal():
            yield Input(placeholder="IP o red CIDR, ej: 127.0.0.1/32", id="alc-objetivo")
            yield Button("Agregar", id="alc-agregar", variant="primary")
        yield DataTable(id="alc-tabla")
        yield Static("", id="alc-mensaje", classes="ast-tenue")

    def on_mount(self) -> None:
        self.query_one("#alc-tabla", DataTable).add_columns("Red", "Registrado")
        self.refrescar()

    def _mensaje(self, texto: str, clase: str = "ast-tenue") -> None:
        msg = self.query_one("#alc-mensaje", Static)
        msg.update(texto)
        msg.set_classes(clase)

    def refrescar(self) -> None:
        """Vuelve a cargar la tabla. No toca el mensaje salvo que haya un error."""
        tabla = self.query_one("#alc-tabla", DataTable)
        tabla.clear()
        try:
            base_datos = obtener_base_datos()
            proyecto = resolver_proyecto(base_datos, None)
            for alcance in listar_alcance(base_datos, proyecto):
                tabla.add_row(alcance.red, alcance.creado_en)
        except ErrorEST as exc:
            self._mensaje(str(exc), "ast-error")

    @on(Button.Pressed, "#alc-agregar")
    def _agregar(self, _evento: Button.Pressed) -> None:
        campo = self.query_one("#alc-objetivo", Input)
        try:
            base_datos = obtener_base_datos()
            proyecto = resolver_proyecto(base_datos, None)
            alcance = agregar_alcance(base_datos, proyecto, campo.value)
            self.refrescar()
            self._mensaje(
                f"Alcance '{alcance.red}' autorizado para '{proyecto.nombre}'.", "ast-exito"
            )
            campo.value = ""
            self.app.refrescar_estado()  # type: ignore[attr-defined]
        except ErrorEST as exc:
            self._mensaje(str(exc), "ast-error")


class PanelRedes(Vertical):
    """Comprobacion de puertos TCP (formulario) contra el alcance autorizado."""

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._worker = None

    def compose(self):
        yield Static("Comprobacion de puertos TCP", classes="titulo-panel")
        yield Static(
            "Actua sobre el proyecto activo. El objetivo debe estar autorizado en 'Alcance'.",
            classes="ast-tenue",
        )
        with Horizontal():
            yield Input(placeholder="Objetivo (IPv4)", id="redes-objetivo")
            yield Input(placeholder="Puertos, ej: 22,80,443", id="redes-puertos")
        with Horizontal():
            yield Input(placeholder="Timeout en segundos (1.0)", id="redes-timeout")
            yield Input(placeholder="Concurrencia (50)", id="redes-concurrencia")
        with Horizontal():
            yield Button("Escanear", id="redes-escanear", variant="primary")
            yield Button("Cancelar", id="redes-cancelar")
        yield Static("", id="redes-mensaje", classes="ast-tenue")
        yield DataTable(id="redes-tabla")

    def on_mount(self) -> None:
        self.query_one("#redes-tabla", DataTable).add_columns("Puerto", "Estado")

    def _mensaje(self, texto: str, clase: str = "ast-tenue") -> None:
        msg = self.query_one("#redes-mensaje", Static)
        msg.update(texto)
        msg.set_classes(clase)

    @on(Button.Pressed, "#redes-escanear")
    def _iniciar(self, _evento: Button.Pressed) -> None:
        objetivo = self.query_one("#redes-objetivo", Input).value.strip()
        puertos = self.query_one("#redes-puertos", Input).value.strip()
        timeout_txt = self.query_one("#redes-timeout", Input).value.strip()
        concurrencia_txt = self.query_one("#redes-concurrencia", Input).value.strip()
        try:
            timeout = float(timeout_txt) if timeout_txt else 1.0
            concurrencia = int(concurrencia_txt) if concurrencia_txt else 50
        except ValueError:
            self._mensaje("Timeout y concurrencia deben ser numericos.", "ast-error")
            return

        self._mensaje("Escaneando... (puedes cancelar mientras se ejecuta)", "ast-aviso")
        self._worker = self._escanear(objetivo, puertos, timeout, concurrencia)

    @on(Button.Pressed, "#redes-cancelar")
    def _cancelar(self, _evento: Button.Pressed) -> None:
        if self._worker is not None and self._worker.is_running:
            self._worker.cancel()
            self._mensaje(
                "Cancelacion solicitada: se descartara el resultado de este escaneo.", "ast-aviso"
            )

    @work(thread=True, exclusive=True, group="redes-escaneo")
    def _escanear(self, objetivo: str, puertos: str, timeout: float, concurrencia: int) -> None:
        worker = get_current_worker()
        try:
            base_datos = obtener_base_datos()
            proyecto = resolver_proyecto(base_datos, None)
            resultados = escanear_tcp(
                base_datos,
                proyecto,
                objetivo,
                puertos,
                tiempo_espera=timeout,
                concurrencia=concurrencia,
            )
        except ErrorEST as exc:
            if not worker.is_cancelled:
                self.app.call_from_thread(self._mensaje, str(exc), "ast-error")
            return

        if worker.is_cancelled:
            return
        self.app.call_from_thread(self._mostrar_resultados, resultados)

    def _mostrar_resultados(self, resultados) -> None:
        tabla = self.query_one("#redes-tabla", DataTable)
        tabla.clear()
        for resultado in resultados:
            tabla.add_row(str(resultado.puerto), resultado.estado)
        self._mensaje(f"Escaneo completo: {len(resultados)} puertos comprobados.", "ast-exito")
        self.app.refrescar_estado()  # type: ignore[attr-defined]


class PanelResultados(Vertical):
    """Resultados guardados del proyecto activo."""

    def compose(self):
        yield Static("Resultados guardados", classes="titulo-panel")
        yield Button("Actualizar", id="res-refrescar")
        yield DataTable(id="res-tabla")
        yield Static("", id="res-mensaje", classes="ast-tenue")

    def on_mount(self) -> None:
        self.query_one("#res-tabla", DataTable).add_columns("Objetivo", "Puerto", "Estado", "Fecha")
        self.refrescar()

    def refrescar(self) -> None:
        tabla = self.query_one("#res-tabla", DataTable)
        tabla.clear()
        msg = self.query_one("#res-mensaje", Static)
        try:
            base_datos = obtener_base_datos()
            proyecto = resolver_proyecto(base_datos, None)
            resultados = obtener_resultados(base_datos, proyecto, limite=200)
            for resultado in resultados:
                tabla.add_row(
                    resultado.objetivo,
                    str(resultado.puerto),
                    resultado.estado,
                    resultado.creado_en,
                )
            msg.update("" if resultados else f"Sin resultados todavia para '{proyecto.nombre}'.")
            msg.set_classes("ast-tenue")
        except ErrorEST as exc:
            msg.update(str(exc))
            msg.set_classes("ast-error")

    @on(Button.Pressed, "#res-refrescar")
    def _refrescar_click(self, _evento: Button.Pressed) -> None:
        self.refrescar()


class PanelReportes(Vertical):
    """Generacion de informes HTML/JSON del proyecto activo."""

    def compose(self):
        yield Static("Generar informe", classes="titulo-panel")
        with Horizontal():
            yield Select(
                [("HTML", "html"), ("JSON", "json")],
                value="html",
                allow_blank=False,
                id="rep-formato",
            )
            yield Button("Generar", id="rep-generar", variant="primary")
        yield Static("", id="rep-mensaje", classes="ast-tenue")

    @on(Button.Pressed, "#rep-generar")
    def _generar(self, _evento: Button.Pressed) -> None:
        formato = self.query_one("#rep-formato", Select).value
        msg = self.query_one("#rep-mensaje", Static)
        try:
            base_datos = obtener_base_datos()
            proyecto = resolver_proyecto(base_datos, None)
            ruta = generar_reporte(base_datos, proyecto, str(formato))
            msg.update(f"Informe generado en: {ruta}")
            msg.set_classes("ast-exito")
            self.app.refrescar_estado()  # type: ignore[attr-defined]
        except ErrorEST as exc:
            msg.update(str(exc))
            msg.set_classes("ast-error")


class PanelHerramientas(Vertical):
    """Deteccion (sin ejecucion) de herramientas externas de la Fase 3."""

    def compose(self):
        yield Static("Herramientas externas", classes="titulo-panel")
        yield Static(
            "AST detecta si estan instaladas en el sistema, pero no las ejecuta "
            "todavia (integracion prevista para la Fase 3, ver docs/ROADMAP.md).",
            classes="ast-tenue",
        )
        yield DataTable(id="herr-tabla")
        yield Button("Volver a detectar", id="herr-refrescar")

    def on_mount(self) -> None:
        self.query_one("#herr-tabla", DataTable).add_columns(
            "Herramienta", "Comando", "Estado", "Ruta"
        )
        self.refrescar()

    def refrescar(self) -> None:
        tabla = self.query_one("#herr-tabla", DataTable)
        tabla.clear()
        for herramienta in detectar_herramientas():
            estado = "Instalada" if herramienta.instalada else "No instalada"
            tabla.add_row(herramienta.nombre, herramienta.comando, estado, herramienta.ruta or "-")

    @on(Button.Pressed, "#herr-refrescar")
    def _refrescar_click(self, _evento: Button.Pressed) -> None:
        self.refrescar()


class PanelConfiguracion(Vertical):
    """Configuracion local: rutas de datos y cambio de proyecto activo."""

    def compose(self):
        yield Static("Configuracion", classes="titulo-panel")
        yield Static("", id="conf-rutas", classes="ast-caja")
        with Horizontal():
            yield Input(placeholder="Nombre de proyecto a activar", id="conf-proyecto")
            yield Button("Activar", id="conf-activar")
        yield Static("", id="conf-mensaje", classes="ast-tenue")

    def on_mount(self) -> None:
        self.query_one("#conf-rutas", Static).update(
            f"Directorio de datos: {directorio_datos()}\n"
            f"Base de datos: {ruta_base_datos()}\n"
            f"Historial de la terminal interactiva: {ruta_historial()}"
        )

    @on(Button.Pressed, "#conf-activar")
    def _activar(self, _evento: Button.Pressed) -> None:
        campo = self.query_one("#conf-proyecto", Input)
        msg = self.query_one("#conf-mensaje", Static)
        try:
            proyecto = usar_proyecto(obtener_base_datos(), campo.value)
            msg.update(f"Proyecto activo: '{proyecto.nombre}'.")
            msg.set_classes("ast-exito")
            campo.value = ""
            self.app.refrescar_estado()  # type: ignore[attr-defined]
        except ErrorEST as exc:
            msg.update(str(exc))
            msg.set_classes("ast-error")


class PanelAyuda(VerticalScroll):
    """Documentacion de todos los comandos, siempre disponible y desplazable."""

    def compose(self):
        yield Static("Ayuda y documentacion", classes="titulo-panel")
        for tema, texto in sorted(EXPLICACIONES.items()):
            yield Static(f"[bold cyan]{tema}[/bold cyan]\n{texto}", classes="ast-caja")


class PanelProximamente(Vertical):
    """Marcador honesto para secciones aun no implementadas (nunca simula datos)."""

    def __init__(self, nombre: str, fase: str = "Fase 3", **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._nombre = nombre
        self._fase = fase

    def compose(self):
        yield Static(self._nombre, classes="titulo-panel")
        yield Static(
            f"Proximamente ({self._fase} del roadmap).\n\n"
            "Esta seccion todavia no esta implementada: no hay datos reales que "
            "mostrar aqui. Consulta docs/ROADMAP.md para el detalle de cada fase.",
            classes="ast-aviso",
        )
