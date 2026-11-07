"""Paneles de la interfaz AST: proyectos, alcance, redes, resultados, etc."""

from __future__ import annotations

from textual import on, work
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Checkbox, DataTable, Input, Select, Static
from textual.worker import get_current_worker

from eurabyte_security.commands._comun import obtener_base_datos, resolver_proyecto
from eurabyte_security.commands.alcance import agregar_alcance, listar_alcance
from eurabyte_security.commands.escanear import escanear_tcp
from eurabyte_security.commands.explicar import EXPLICACIONES
from eurabyte_security.commands.nmap import ejecutar_nmap
from eurabyte_security.commands.proyecto import crear_proyecto, listar_proyectos, usar_proyecto
from eurabyte_security.commands.reporte import generar_reporte
from eurabyte_security.commands.resultados import obtener_resultados
from eurabyte_security.commands.web import TIPOS_VALIDOS as TIPOS_WEB_VALIDOS
from eurabyte_security.commands.web import auditar_web
from eurabyte_security.core.config import directorio_datos, ruta_base_datos, ruta_historial
from eurabyte_security.core.errores import ErrorEscaneoCancelado, ErrorEST
from eurabyte_security.integrations.deteccion import detectar_herramientas
from eurabyte_security.marca import BANNER_ASCII, ESCUDO_ASCII
from eurabyte_security.modules.web.modelos import Hallazgo
from eurabyte_security.ui.consola import texto_seguro
from eurabyte_security.ui.tui.estado import EstadoAST


class PanelInicio(Vertical):
    """Panel de bienvenida: escudo, banner, resumen y atajos de navegacion."""

    def compose(self):
        with Horizontal(id="inicio-marca"):
            yield Static(ESCUDO_ASCII, id="inicio-escudo", classes="logo")
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
        try:
            base_datos = obtener_base_datos()
            proyectos, activo = listar_proyectos(base_datos)
        except Exception as exc:  # noqa: BLE001 - frontera de la interfaz visual
            self._mensaje(f"Error inesperado: {texto_seguro(exc)}", "ast-error")
            return

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
                f"Proyecto '{texto_seguro(proyecto.nombre)}' creado y marcado como activo.",
                "ast-exito",
            )
            campo.value = ""
            self.refrescar()
            self.app.refrescar_estado()  # type: ignore[attr-defined]
        except ErrorEST as exc:
            self._mensaje(texto_seguro(exc), "ast-error")
        except Exception as exc:  # noqa: BLE001 - frontera de la interfaz visual
            self._mensaje(f"Error inesperado: {texto_seguro(exc)}", "ast-error")

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
            self._mensaje(f"Proyecto activo: '{texto_seguro(proyecto.nombre)}'.", "ast-exito")
            self.refrescar()
            self.app.refrescar_estado()  # type: ignore[attr-defined]
        except ErrorEST as exc:
            self._mensaje(texto_seguro(exc), "ast-error")
        except Exception as exc:  # noqa: BLE001 - frontera de la interfaz visual
            self._mensaje(f"Error inesperado: {texto_seguro(exc)}", "ast-error")


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
            self._mensaje(texto_seguro(exc), "ast-error")
        except Exception as exc:  # noqa: BLE001 - frontera de la interfaz visual
            self._mensaje(f"Error inesperado: {texto_seguro(exc)}", "ast-error")

    @on(Button.Pressed, "#alc-agregar")
    def _agregar(self, _evento: Button.Pressed) -> None:
        campo = self.query_one("#alc-objetivo", Input)
        try:
            base_datos = obtener_base_datos()
            proyecto = resolver_proyecto(base_datos, None)
            alcance = agregar_alcance(base_datos, proyecto, campo.value)
            self.refrescar()
            self._mensaje(
                f"Alcance '{texto_seguro(alcance.red)}' autorizado para "
                f"'{texto_seguro(proyecto.nombre)}'.",
                "ast-exito",
            )
            campo.value = ""
            self.app.refrescar_estado()  # type: ignore[attr-defined]
        except ErrorEST as exc:
            self._mensaje(texto_seguro(exc), "ast-error")
        except Exception as exc:  # noqa: BLE001 - frontera de la interfaz visual
            self._mensaje(f"Error inesperado: {texto_seguro(exc)}", "ast-error")


class PanelRedes(Vertical):
    """Comprobacion de puertos TCP (formulario) contra el alcance autorizado.

    Cancelacion: ``escanear_tcp`` solo persiste resultados en la base de datos
    si el escaneo llego a terminar sin que se solicitara cancelacion (ver
    ``commands/escanear.py``); un escaneo cancelado no guarda nada, aunque
    alguna conexion ya iniciada termine en segundo plano. Ademas, cada clic en
    "Escanear" incrementa ``_secuencia``: solo el resultado del escaneo mas
    reciente puede actualizar la tabla, por lo que dos escaneos solapados
    nunca mezclan sus resultados en la interfaz.
    """

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._worker = None
        self._secuencia = 0

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

        # Cada escaneo recibe un numero de secuencia propio: si llega a
        # terminar un escaneo mas antiguo (p. ej. por una condicion de
        # carrera de hilos), su resultado se descarta en _mostrar_resultados.
        self._secuencia += 1
        secuencia = self._secuencia

        self._mensaje("Escaneando... (puedes cancelar mientras se ejecuta)", "ast-aviso")
        self._worker = self._escanear(secuencia, objetivo, puertos, timeout, concurrencia)

    @on(Button.Pressed, "#redes-cancelar")
    def _cancelar(self, _evento: Button.Pressed) -> None:
        if self._worker is not None and self._worker.is_running:
            self._worker.cancel()
            self._mensaje(
                "Cancelacion solicitada: no se guardara ningun resultado de este escaneo "
                "(las conexiones ya iniciadas pueden completarse en segundo plano).",
                "ast-aviso",
            )

    @work(thread=True, exclusive=True, group="redes-escaneo", exit_on_error=False)
    def _escanear(
        self, secuencia: int, objetivo: str, puertos: str, timeout: float, concurrencia: int
    ) -> None:
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
                debe_cancelar=lambda: worker.is_cancelled,
            )
        except ErrorEscaneoCancelado as exc:
            if secuencia == self._secuencia:
                self.app.call_from_thread(self._mensaje, texto_seguro(exc), "ast-aviso")
            return
        except ErrorEST as exc:
            if not worker.is_cancelled and secuencia == self._secuencia:
                self.app.call_from_thread(self._mensaje, texto_seguro(exc), "ast-error")
            return
        except Exception as exc:  # noqa: BLE001 - frontera de la interfaz visual
            if not worker.is_cancelled and secuencia == self._secuencia:
                self.app.call_from_thread(
                    self._mensaje, f"Error inesperado: {texto_seguro(exc)}", "ast-error"
                )
            return

        if worker.is_cancelled:
            return
        self.app.call_from_thread(self._mostrar_resultados, secuencia, resultados)

    def _mostrar_resultados(self, secuencia: int, resultados: list) -> None:
        if secuencia != self._secuencia:
            # Un escaneo mas reciente ya se inicio: este resultado es obsoleto.
            return
        tabla = self.query_one("#redes-tabla", DataTable)
        tabla.clear()
        for resultado in resultados:
            tabla.add_row(str(resultado.puerto), resultado.estado)
        self._mensaje(f"Escaneo completo: {len(resultados)} puertos comprobados.", "ast-exito")
        self.app.refrescar_estado()  # type: ignore[attr-defined]


class PanelReconocimiento(Vertical):
    """Descubrimiento de puertos y servicios con Nmap, dentro del alcance autorizado.

    Misma politica de cancelacion que PanelRedes: numero de secuencia propio
    por analisis (solo el mas reciente puede actualizar la tabla) y
    cancelacion real del proceso de Nmap via ``debe_cancelar`` (ver
    integrations/proceso.py). Un analisis cancelado nunca persiste ningun
    resultado (``commands/nmap.py`` -> ``ErrorEscaneoCancelado``).
    """

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._worker = None
        self._secuencia = 0

    def compose(self):
        yield Static("Reconocimiento (Nmap)", classes="titulo-panel")
        yield Static(
            "Actua sobre el proyecto activo. El objetivo debe estar autorizado en "
            "'Alcance'. Requiere tener Nmap instalado (ver panel 'Herramientas').",
            classes="ast-tenue",
        )
        with Horizontal():
            yield Input(placeholder="Objetivo (IPv4)", id="nmap-objetivo")
            yield Input(placeholder="Puertos, ej: 22,80,443", id="nmap-puertos")
        yield Checkbox(
            "Deteccion de servicios/version (-sV) - solo si esta autorizado",
            id="nmap-deteccion-version",
        )
        with Horizontal():
            yield Button("Ejecutar Nmap", id="nmap-ejecutar", variant="primary")
            yield Button("Cancelar", id="nmap-cancelar")
        yield Static("", id="nmap-mensaje", classes="ast-tenue")
        yield DataTable(id="nmap-tabla")

    def on_mount(self) -> None:
        self.query_one("#nmap-tabla", DataTable).add_columns(
            "Puerto", "Protocolo", "Estado", "Servicio", "Version"
        )

    def _mensaje(self, texto: str, clase: str = "ast-tenue") -> None:
        msg = self.query_one("#nmap-mensaje", Static)
        msg.update(texto)
        msg.set_classes(clase)

    @on(Button.Pressed, "#nmap-ejecutar")
    def _iniciar(self, _evento: Button.Pressed) -> None:
        objetivo = self.query_one("#nmap-objetivo", Input).value.strip()
        puertos = self.query_one("#nmap-puertos", Input).value.strip()
        deteccion_version = self.query_one("#nmap-deteccion-version", Checkbox).value

        self._secuencia += 1
        secuencia = self._secuencia

        self._mensaje("Ejecutando Nmap... (puedes cancelar mientras se ejecuta)", "ast-aviso")
        self._worker = self._ejecutar(secuencia, objetivo, puertos, deteccion_version)

    @on(Button.Pressed, "#nmap-cancelar")
    def _cancelar(self, _evento: Button.Pressed) -> None:
        if self._worker is not None and self._worker.is_running:
            self._worker.cancel()
            self._mensaje(
                "Cancelacion solicitada: no se guardara ningun resultado de este "
                "analisis (el proceso de Nmap se detiene).",
                "ast-aviso",
            )

    @work(thread=True, exclusive=True, group="nmap-analisis", exit_on_error=False)
    def _ejecutar(
        self, secuencia: int, objetivo: str, puertos: str, deteccion_version: bool
    ) -> None:
        worker = get_current_worker()
        try:
            base_datos = obtener_base_datos()
            proyecto = resolver_proyecto(base_datos, None)
            resultado, _guardados, ruta_xml = ejecutar_nmap(
                base_datos,
                proyecto,
                objetivo,
                puertos,
                deteccion_version=deteccion_version,
                debe_cancelar=lambda: worker.is_cancelled,
            )
        except ErrorEscaneoCancelado as exc:
            if secuencia == self._secuencia:
                self.app.call_from_thread(self._mensaje, texto_seguro(exc), "ast-aviso")
            return
        except ErrorEST as exc:
            if not worker.is_cancelled and secuencia == self._secuencia:
                self.app.call_from_thread(self._mensaje, texto_seguro(exc), "ast-error")
            return
        except Exception as exc:  # noqa: BLE001 - frontera de la interfaz visual
            if not worker.is_cancelled and secuencia == self._secuencia:
                self.app.call_from_thread(
                    self._mensaje, f"Error inesperado: {texto_seguro(exc)}", "ast-error"
                )
            return

        if worker.is_cancelled:
            return
        self.app.call_from_thread(self._mostrar_resultados, secuencia, resultado, ruta_xml)

    def _mostrar_resultados(self, secuencia: int, resultado, ruta_xml) -> None:
        if secuencia != self._secuencia:
            return
        tabla = self.query_one("#nmap-tabla", DataTable)
        tabla.clear()
        for puerto in resultado.puertos:
            tabla.add_row(
                str(puerto.puerto), puerto.protocolo, puerto.estado,
                puerto.servicio or "-", puerto.version or "-",
            )
        mensaje = f"Analisis completo: {len(resultado.puertos)} puertos comprobados."
        if ruta_xml is not None:
            mensaje += f" Evidencia: {texto_seguro(ruta_xml)}"
        self._mensaje(mensaje, "ast-exito")
        self.app.refrescar_estado()  # type: ignore[attr-defined]


class PanelAuditoriaWeb(Vertical):
    """Auditoria web no intrusiva: cabeceras, TLS, cookies y redirecciones.

    Misma politica de cancelacion y de secuencia que ``PanelRedes``/
    ``PanelReconocimiento``: cada clic en "Analizar" tiene su propio numero de
    secuencia (solo el analisis mas reciente puede actualizar la tabla) y la
    cancelacion detiene la peticion en curso sin persistir ningun hallazgo
    parcial (ver ``commands/web.py`` -> ``auditar_web``). La URL solo se
    acepta si su host esta autorizado en el alcance del proyecto elegido.
    """

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._worker = None
        self._secuencia = 0
        self._hallazgos: list[Hallazgo] = []

    def compose(self):
        yield Static("Analisis web", classes="titulo-panel")
        yield Static(
            "Auditoria no intrusiva de cabeceras, TLS, cookies y redirecciones. La URL "
            "debe usar una IP autorizada en el alcance del proyecto elegido (sin nombres "
            "de dominio por ahora).",
            classes="ast-tenue",
        )
        with Horizontal():
            yield Select([], allow_blank=True, prompt="Proyecto (activo)", id="web-proyecto")
            yield Select(
                [
                    ("Cabeceras HTTP", "cabeceras"),
                    ("TLS/certificado", "tls"),
                    ("Cookies", "cookies"),
                    ("Auditoria completa", "auditar"),
                ],
                value="auditar",
                allow_blank=False,
                id="web-tipo",
            )
        yield Input(placeholder="URL, ej: https://127.0.0.1:8443/panel", id="web-url")
        with Horizontal():
            yield Input(placeholder="Tiempo limite en segundos (10)", id="web-tiempo-limite")
            yield Checkbox("Seguir redirecciones autorizadas", id="web-seguir-redirecciones")
        with Horizontal():
            yield Button("Analizar", id="web-analizar", variant="primary")
            yield Button("Cancelar", id="web-cancelar")
        yield Static("", id="web-mensaje", classes="ast-tenue")
        yield DataTable(id="web-tabla", cursor_type="row")
        yield Static("", id="web-detalle", classes="ast-caja")

    def on_mount(self) -> None:
        self.query_one("#web-tabla", DataTable).add_columns(
            "Categoria", "Hallazgo", "Estado", "Severidad"
        )
        self._cargar_proyectos()

    def _cargar_proyectos(self) -> None:
        """Recarga las opciones de proyecto, preservando la seleccion actual si sigue valida."""
        try:
            base_datos = obtener_base_datos()
            proyectos, activo = listar_proyectos(base_datos)
        except Exception:  # noqa: BLE001 - frontera de la interfaz visual
            return
        nombres = [p.nombre for p in proyectos]
        selector = self.query_one("#web-proyecto", Select)
        seleccion_previa = selector.value
        selector.set_options((nombre, nombre) for nombre in nombres)
        if seleccion_previa in nombres:
            selector.value = seleccion_previa
        elif activo in nombres:
            selector.value = activo

    def _mensaje(self, texto: str, clase: str = "ast-tenue") -> None:
        msg = self.query_one("#web-mensaje", Static)
        msg.update(texto)
        msg.set_classes(clase)

    @on(Button.Pressed, "#web-analizar")
    def _iniciar(self, _evento: Button.Pressed) -> None:
        # Se recarga la lista justo antes de leerla: un proyecto creado despues de
        # que este panel se monto (p. ej. el primer proyecto de la sesion) debe
        # poder elegirse sin tener que revisitar esta seccion.
        self._cargar_proyectos()
        proyecto_nombre = self.query_one("#web-proyecto", Select).value
        tipo = str(self.query_one("#web-tipo", Select).value or "auditar")
        url = self.query_one("#web-url", Input).value.strip()
        tiempo_limite_txt = self.query_one("#web-tiempo-limite", Input).value.strip()
        seguir_redirecciones = self.query_one(
            "#web-seguir-redirecciones", Checkbox
        ).value

        try:
            tiempo_limite = float(tiempo_limite_txt) if tiempo_limite_txt else 10.0
        except ValueError:
            self._mensaje("El tiempo limite debe ser numerico.", "ast-error")
            return

        proyecto_nombre_str = None if proyecto_nombre == Select.BLANK else str(proyecto_nombre)
        tipos = TIPOS_WEB_VALIDOS if tipo == "auditar" else frozenset({tipo})

        self._secuencia += 1
        secuencia = self._secuencia
        self.query_one("#web-detalle", Static).update("")

        self._mensaje("Auditando... (puedes cancelar mientras se ejecuta)", "ast-aviso")
        self._worker = self._analizar(
            secuencia, proyecto_nombre_str, url, tipo, tipos, tiempo_limite, seguir_redirecciones
        )

    @on(Button.Pressed, "#web-cancelar")
    def _cancelar(self, _evento: Button.Pressed) -> None:
        if self._worker is not None and self._worker.is_running:
            self._worker.cancel()
            self._mensaje(
                "Cancelacion solicitada: no se guardara ningun hallazgo de este analisis.",
                "ast-aviso",
            )

    @work(thread=True, exclusive=True, group="web-auditoria", exit_on_error=False)
    def _analizar(
        self,
        secuencia: int,
        proyecto_nombre: str | None,
        url: str,
        tipo: str,
        tipos: frozenset[str],
        tiempo_limite: float,
        seguir_redirecciones: bool,
    ) -> None:
        worker = get_current_worker()
        try:
            base_datos = obtener_base_datos()
            proyecto = resolver_proyecto(base_datos, proyecto_nombre)
            resultado, _guardados = auditar_web(
                base_datos,
                proyecto,
                url,
                tipo,
                tipos=tipos,
                tiempo_limite=tiempo_limite,
                seguir_redirecciones=seguir_redirecciones,
                debe_cancelar=lambda: worker.is_cancelled,
            )
        except ErrorEST as exc:
            if not worker.is_cancelled and secuencia == self._secuencia:
                self.app.call_from_thread(self._mensaje, texto_seguro(exc), "ast-error")
            return
        except Exception as exc:  # noqa: BLE001 - frontera de la interfaz visual
            if not worker.is_cancelled and secuencia == self._secuencia:
                self.app.call_from_thread(
                    self._mensaje, f"Error inesperado: {texto_seguro(exc)}", "ast-error"
                )
            return

        if worker.is_cancelled:
            return
        self.app.call_from_thread(self._mostrar_resultados, secuencia, resultado)

    def _mostrar_resultados(self, secuencia: int, resultado) -> None:
        if secuencia != self._secuencia:
            return
        self._hallazgos = resultado.hallazgos
        tabla = self.query_one("#web-tabla", DataTable)
        tabla.clear()
        for indice, hallazgo in enumerate(resultado.hallazgos):
            tabla.add_row(
                texto_seguro(hallazgo.categoria),
                texto_seguro(hallazgo.nombre),
                texto_seguro(hallazgo.estado),
                texto_seguro(hallazgo.severidad),
                key=str(indice),
            )
        codigo_estado_texto = (
            str(resultado.codigo_estado)
            if resultado.codigo_estado is not None
            else "N/A (peticion HTTP no completada)"
        )
        mensaje = (
            f"Analisis completo: codigo {codigo_estado_texto}, "
            f"{len(resultado.hallazgos)} hallazgos."
        )
        if resultado.saltos_seguidos:
            mensaje += f" Redirecciones seguidas: {len(resultado.saltos_seguidos)}."
        self._mensaje(mensaje, "ast-exito")
        self.app.refrescar_estado()  # type: ignore[attr-defined]

    @on(DataTable.RowSelected, "#web-tabla")
    def _fila_seleccionada(self, event: DataTable.RowSelected) -> None:
        if event.row_key.value is None:
            return
        try:
            hallazgo = self._hallazgos[int(event.row_key.value)]
        except (ValueError, IndexError):
            return
        self.query_one("#web-detalle", Static).update(
            f"[bold]{texto_seguro(hallazgo.nombre)}[/bold]\n"
            f"Significado: {texto_seguro(hallazgo.significado)}\n"
            f"Proposito: {texto_seguro(hallazgo.proposito)}\n"
            f"Valor detectado: {texto_seguro(hallazgo.valor_detectado or '-')}\n"
            f"Riesgo: {texto_seguro(hallazgo.riesgo)}\n"
            f"Recomendacion: {texto_seguro(hallazgo.recomendacion)}\n"
            f"Referencia: {texto_seguro(hallazgo.referencia)}"
        )


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
            msg.update(
                ""
                if resultados
                else f"Sin resultados todavia para '{texto_seguro(proyecto.nombre)}'."
            )
            msg.set_classes("ast-tenue")
        except ErrorEST as exc:
            msg.update(texto_seguro(exc))
            msg.set_classes("ast-error")
        except Exception as exc:  # noqa: BLE001 - frontera de la interfaz visual
            msg.update(f"Error inesperado: {texto_seguro(exc)}")
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
            msg.update(f"Informe generado en: {texto_seguro(ruta)}")
            msg.set_classes("ast-exito")
            self.app.refrescar_estado()  # type: ignore[attr-defined]
        except ErrorEST as exc:
            msg.update(texto_seguro(exc))
            msg.set_classes("ast-error")
        except Exception as exc:  # noqa: BLE001 - frontera de la interfaz visual
            msg.update(f"Error inesperado: {texto_seguro(exc)}")
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
            "Herramienta", "Comando", "Estado", "Version", "Ruta"
        )
        self.refrescar()

    def refrescar(self) -> None:
        tabla = self.query_one("#herr-tabla", DataTable)
        tabla.clear()
        for herramienta in detectar_herramientas():
            estado = "Instalada" if herramienta.instalada else "No instalada"
            tabla.add_row(
                herramienta.nombre,
                herramienta.comando,
                estado,
                texto_seguro(herramienta.version) if herramienta.version else "-",
                texto_seguro(herramienta.ruta) if herramienta.ruta else "-",
            )

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
            msg.update(f"Proyecto activo: '{texto_seguro(proyecto.nombre)}'.")
            msg.set_classes("ast-exito")
            campo.value = ""
            self.app.refrescar_estado()  # type: ignore[attr-defined]
        except ErrorEST as exc:
            msg.update(texto_seguro(exc))
            msg.set_classes("ast-error")
        except Exception as exc:  # noqa: BLE001 - frontera de la interfaz visual
            msg.update(f"Error inesperado: {texto_seguro(exc)}")
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
