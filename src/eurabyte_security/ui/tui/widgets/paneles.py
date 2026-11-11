"""Paneles de la interfaz AST: proyectos, alcance, redes, resultados, etc."""

from __future__ import annotations

import ipaddress
from dataclasses import replace

from textual import on, work
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    Checkbox,
    Collapsible,
    DataTable,
    Input,
    Select,
    SelectionList,
    Static,
    TabbedContent,
    TabPane,
)
from textual.worker import get_current_worker

from eurabyte_security.commands._comun import obtener_base_datos, resolver_proyecto
from eurabyte_security.commands.alcance import agregar_alcance, listar_alcance
from eurabyte_security.commands.escanear import escanear_tcp
from eurabyte_security.commands.explicar import EXPLICACIONES
from eurabyte_security.commands.nmap import ejecutar_nmap
from eurabyte_security.commands.nuclei import ejecutar_nuclei
from eurabyte_security.commands.osint import generar_reporte_osint
from eurabyte_security.commands.proyecto import crear_proyecto, listar_proyectos, usar_proyecto
from eurabyte_security.commands.reconocimiento import (
    PERFILES_VALIDOS,
    EtapaReconocimiento,
    ejecutar_reconocimiento_automatico,
)
from eurabyte_security.commands.reporte import generar_reporte
from eurabyte_security.commands.resultados import obtener_resultados_unificados
from eurabyte_security.commands.web import TIPOS_VALIDOS as TIPOS_WEB_VALIDOS
from eurabyte_security.commands.web import auditar_web
from eurabyte_security.commands.zap import ejecutar_zap_pasivo
from eurabyte_security.core.config import directorio_datos, ruta_base_datos, ruta_historial
from eurabyte_security.core.errores import ErrorEscaneoCancelado, ErrorEST
from eurabyte_security.core.objetivo import interpretar_entrada, resolver_y_autorizar
from eurabyte_security.core.osint.validacion import (
    requiere_autorizacion_datos_personales,
)
from eurabyte_security.integrations.deteccion import detectar_herramientas
from eurabyte_security.integrations.nuclei import PLANTILLAS_APROBADAS, AdaptadorNuclei
from eurabyte_security.integrations.osint.registro import FUENTES_OSINT, fuentes_para_tipo
from eurabyte_security.integrations.zap import AdaptadorZAP
from eurabyte_security.marca import BANNER_ASCII, ESCUDO_ASCII
from eurabyte_security.modules.osint.exposicion import construir_resumen_exposicion
from eurabyte_security.modules.osint.modelos import EtapaFuenteOSINT
from eurabyte_security.modules.osint.motor import ejecutar_investigacion_osint
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


_ESTILOS_ETAPA_RECONOCIMIENTO = {
    "completada": "bold green",
    "ejecutando": "bold yellow",
    "pendiente": "grey70",
    "omitida": "grey70",
    "fallida": "bold red",
    "cancelada": "bold red",
}


class PanelReconocimiento(VerticalScroll):
    """Pantalla principal de auditoria: un solo objetivo, reconocimiento automatico.

    Un solo campo de objetivo (IP, dominio o URL) dispara
    ``commands/reconocimiento.py:ejecutar_reconocimiento_automatico()`` -- el mismo
    motor que usa ``est reconocimiento ejecutar`` -- en un worker, con una tabla de
    etapas que se actualiza en vivo via el callback de progreso (nunca un porcentaje
    inventado: solo los estados reales que ya reporta el orquestador). El formulario
    manual de Nmap (identico al que ya existia) se conserva intacto dentro de una
    seccion "avanzada" plegable, para quien prefiera ejecutarlo por separado.
    """

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._worker = None
        self._secuencia = 0
        self._reco_worker = None
        self._reco_secuencia = 0
        self._ultimo_resultado = None

    def compose(self):
        yield Static("Reconocimiento automatico", classes="titulo-panel")
        yield Static("", id="reco-auto-proyecto", classes="ast-tenue")
        yield Static(
            "Escribe el objetivo una sola vez: AST descubre puertos con Nmap (si esta "
            "instalado), identifica servicios HTTP/HTTPS, los audita automaticamente y "
            "ejecuta Nuclei/OWASP ZAP solo contra los que respondieron. Una herramienta "
            "ausente omite su etapa sin detener las demas.",
            classes="ast-caja",
        )
        yield Input(
            placeholder="IP, dominio o URL (ej: 127.0.0.1, ejemplo.com, https://127.0.0.1:8765)",
            id="reco-auto-objetivo",
        )
        with Horizontal():
            yield Select(
                [
                    ("Rapido", "rapido"),
                    ("Completo", "completo"),
                    ("Personalizado", "personalizado"),
                ],
                value="rapido",
                allow_blank=False,
                id="reco-auto-perfil",
            )
            yield Button("Verificar objetivo", id="reco-auto-verificar")
        with Collapsible(title="Opciones avanzadas", collapsed=True):
            yield Input(
                placeholder="Puertos para el perfil 'personalizado' (ej: 22,80,1000-2000)",
                id="reco-auto-puertos-personalizados",
            )
            yield Input(
                placeholder="Tiempo limite de Nmap en segundos (120)",
                id="reco-auto-tiempo-limite",
            )
        yield Checkbox(
            "Confirmo que el objetivo esta autorizado", id="reco-auto-confirmar"
        )
        with Horizontal():
            yield Button(
                "Iniciar reconocimiento automatico", id="reco-auto-iniciar", variant="primary"
            )
            yield Button("Cancelar", id="reco-auto-cancelar")
        yield Static("", id="reco-auto-mensaje", classes="ast-tenue")
        with Collapsible(title="Etapas", collapsed=False):
            yield DataTable(id="reco-auto-etapas-tabla", cursor_type="row")
        with Collapsible(title="Puertos y servicios detectados", collapsed=True):
            yield DataTable(id="reco-auto-puertos-tabla", cursor_type="row")
        yield Static("", id="reco-auto-resumen", classes="ast-caja")
        with Horizontal():
            yield Button("Ver vulnerabilidades", id="reco-auto-ver-vulnerabilidades")
            yield Button("Generar informe", id="reco-auto-generar-informe")

        with Collapsible(title="Nmap manual (avanzado)", collapsed=True, id="reco-nmap-manual"):
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
        self.query_one("#reco-auto-etapas-tabla", DataTable).add_columns(
            "Etapa", "Estado", "Detalle"
        )
        self.query_one("#reco-auto-puertos-tabla", DataTable).add_columns(
            "Puerto", "Estado", "Servicio"
        )
        self._refrescar_proyecto_auto()

    def _refrescar_proyecto_auto(self) -> None:
        etiqueta = self.query_one("#reco-auto-proyecto", Static)
        try:
            proyecto = resolver_proyecto(obtener_base_datos(), None)
            etiqueta.update(f"Proyecto activo: {texto_seguro(proyecto.nombre)}")
        except ErrorEST as exc:
            etiqueta.update(texto_seguro(exc))

    def _mensaje_auto(self, texto: str, clase: str = "ast-tenue") -> None:
        msg = self.query_one("#reco-auto-mensaje", Static)
        msg.update(texto)
        msg.set_classes(clase)

    @on(Button.Pressed, "#reco-auto-verificar")
    def _verificar_objetivo(self, _evento: Button.Pressed) -> None:
        objetivo = self.query_one("#reco-auto-objetivo", Input).value.strip()
        if not objetivo:
            self._mensaje_auto("Escribe un objetivo antes de verificar.", "ast-aviso")
            return
        self._mensaje_auto("Verificando objetivo...", "ast-aviso")
        self._verificar(objetivo)

    @work(thread=True, exclusive=True, group="reco-auto-verificar", exit_on_error=False)
    def _verificar(self, objetivo: str) -> None:
        try:
            base_datos = obtener_base_datos()
            proyecto = resolver_proyecto(base_datos, None)
            entrada = interpretar_entrada(objetivo)
            redes = [
                ipaddress.IPv4Network(a.red) for a in base_datos.listar_alcance(proyecto.id)
            ]
            resuelto = resolver_y_autorizar(entrada, redes)
        except ErrorEST as exc:
            self.app.call_from_thread(self._mensaje_auto, texto_seguro(exc), "ast-error")
            return
        except Exception as exc:  # noqa: BLE001 - frontera de la interfaz visual
            self.app.call_from_thread(
                self._mensaje_auto, f"Error inesperado: {texto_seguro(exc)}", "ast-error"
            )
            return

        detalle = f"Objetivo autorizado: {resuelto.ip}"
        if resuelto.nombre_host:
            otras = ", ".join(str(ip) for ip in resuelto.ips_resueltas)
            detalle += f" (dominio '{texto_seguro(resuelto.nombre_host)}', IPs: {otras})"
        self.app.call_from_thread(self._mensaje_auto, detalle, "ast-exito")

    @on(Button.Pressed, "#reco-auto-iniciar")
    def _iniciar_automatico(self, _evento: Button.Pressed) -> None:
        self._refrescar_proyecto_auto()
        objetivo = self.query_one("#reco-auto-objetivo", Input).value.strip()
        perfil = str(self.query_one("#reco-auto-perfil", Select).value)
        puertos_personalizados = (
            self.query_one("#reco-auto-puertos-personalizados", Input).value.strip() or None
        )
        tiempo_limite_txt = self.query_one("#reco-auto-tiempo-limite", Input).value.strip()
        confirmado = self.query_one("#reco-auto-confirmar", Checkbox).value

        if not objetivo:
            self._mensaje_auto("Escribe un objetivo antes de iniciar.", "ast-aviso")
            return
        if not confirmado:
            self._mensaje_auto(
                "Confirma que el objetivo esta autorizado (casilla) antes de iniciar.",
                "ast-aviso",
            )
            return
        if perfil not in PERFILES_VALIDOS:
            self._mensaje_auto(f"Perfil '{perfil}' no reconocido.", "ast-error")
            return
        if perfil == "personalizado" and not puertos_personalizados:
            self._mensaje_auto(
                "El perfil 'personalizado' requiere una especificacion de puertos "
                "en 'Opciones avanzadas'.",
                "ast-aviso",
            )
            return
        try:
            tiempo_limite = float(tiempo_limite_txt) if tiempo_limite_txt else 120.0
        except ValueError:
            self._mensaje_auto("El tiempo limite de Nmap debe ser numerico.", "ast-error")
            return

        self._reco_secuencia += 1
        secuencia = self._reco_secuencia
        self._ultimo_resultado = None
        self.query_one("#reco-auto-etapas-tabla", DataTable).clear()
        self.query_one("#reco-auto-puertos-tabla", DataTable).clear()
        self.query_one("#reco-auto-resumen", Static).update("")

        self._mensaje_auto(
            "Ejecutando reconocimiento automatico... (puedes cancelar mientras se ejecuta)",
            "ast-aviso",
        )
        self._reco_worker = self._ejecutar_automatico(
            secuencia, objetivo, perfil, puertos_personalizados, tiempo_limite
        )

    @on(Button.Pressed, "#reco-auto-cancelar")
    def _cancelar_automatico(self, _evento: Button.Pressed) -> None:
        if self._reco_worker is not None and self._reco_worker.is_running:
            self._reco_worker.cancel()
            self._mensaje_auto(
                "Cancelacion solicitada: las etapas ya completadas se conservan, "
                "las siguientes no se ejecutaran.",
                "ast-aviso",
            )

    @work(thread=True, exclusive=True, group="reco-auto-ejecucion", exit_on_error=False)
    def _ejecutar_automatico(
        self,
        secuencia: int,
        objetivo: str,
        perfil: str,
        puertos_personalizados: str | None,
        tiempo_limite_nmap: float,
    ) -> None:
        worker = get_current_worker()

        def _progreso(etapa: EtapaReconocimiento) -> None:
            if secuencia == self._reco_secuencia:
                self.app.call_from_thread(self._actualizar_etapa, etapa)

        try:
            base_datos = obtener_base_datos()
            proyecto = resolver_proyecto(base_datos, None)
            resultado = ejecutar_reconocimiento_automatico(
                base_datos,
                proyecto,
                objetivo,
                perfil=perfil,
                especificacion_puertos_personalizada=puertos_personalizados,
                tiempo_limite_nmap=tiempo_limite_nmap,
                callback_progreso=_progreso,
                debe_cancelar=lambda: worker.is_cancelled,
            )
        except ErrorEscaneoCancelado as exc:
            if secuencia == self._reco_secuencia:
                self.app.call_from_thread(self._mensaje_auto, texto_seguro(exc), "ast-aviso")
            return
        except ErrorEST as exc:
            if not worker.is_cancelled and secuencia == self._reco_secuencia:
                self.app.call_from_thread(self._mensaje_auto, texto_seguro(exc), "ast-error")
            return
        except Exception as exc:  # noqa: BLE001 - frontera de la interfaz visual
            if not worker.is_cancelled and secuencia == self._reco_secuencia:
                self.app.call_from_thread(
                    self._mensaje_auto, f"Error inesperado: {texto_seguro(exc)}", "ast-error"
                )
            return

        if worker.is_cancelled:
            return
        self.app.call_from_thread(self._mostrar_resultado_automatico, secuencia, resultado)

    def _actualizar_etapa(self, etapa: EtapaReconocimiento) -> None:
        tabla = self.query_one("#reco-auto-etapas-tabla", DataTable)
        estilo = _ESTILOS_ETAPA_RECONOCIMIENTO.get(etapa.estado, "")
        estado_texto = (
            f"[{estilo}]{texto_seguro(etapa.estado)}[/{estilo}]"
            if estilo
            else texto_seguro(etapa.estado)
        )
        fila = (texto_seguro(etapa.nombre), estado_texto, texto_seguro(etapa.detalle))
        try:
            tabla.remove_row(etapa.nombre)
        except Exception:  # noqa: BLE001 - la fila puede no existir todavia
            pass
        tabla.add_row(*fila, key=etapa.nombre)

    def _mostrar_resultado_automatico(self, secuencia: int, resultado) -> None:
        if secuencia != self._reco_secuencia:
            return
        self._ultimo_resultado = resultado

        tabla_puertos = self.query_one("#reco-auto-puertos-tabla", DataTable)
        tabla_puertos.clear()
        base_datos = obtener_base_datos()
        try:
            proyecto = resolver_proyecto(base_datos, None)
            puertos = base_datos.listar_resultados_nmap(proyecto.id, limite=500)
            for puerto in puertos[:200]:
                tabla_puertos.add_row(
                    str(puerto.puerto),
                    texto_seguro(puerto.estado),
                    texto_seguro(puerto.servicio) if puerto.servicio else "-",
                )
        except ErrorEST:
            pass

        resumen = (
            f"Estado general: {texto_seguro(resultado.estado_general)}  |  "
            f"Objetivo: {texto_seguro(resultado.ip or resultado.objetivo_original)}"
        )
        if resultado.limitaciones:
            resumen += "\n\n[bold yellow]Limitaciones:[/bold yellow]\n" + "\n".join(
                f"- {texto_seguro(lim)}" for lim in resultado.limitaciones
            )
        self.query_one("#reco-auto-resumen", Static).update(resumen)
        self._mensaje_auto("Reconocimiento automatico completo.", "ast-exito")
        self.app.refrescar_estado()  # type: ignore[attr-defined]

    @on(Button.Pressed, "#reco-auto-ver-vulnerabilidades")
    def _ver_vulnerabilidades(self, _evento: Button.Pressed) -> None:
        from textual.widgets import ContentSwitcher

        switcher = self.app.query_one("#switcher-central", ContentSwitcher)
        switcher.current = "panel-resultados"
        panel = self.app.query_one("#panel-resultados", PanelResultados)
        panel.query_one("#res-fuente", Select).value = "vulnerabilidades"
        if self._ultimo_resultado is not None:
            panel.seleccionar_sesion(self._ultimo_resultado.sesion_id)
        panel.refrescar()

    @on(Button.Pressed, "#reco-auto-generar-informe")
    def _generar_informe_cmd(self, _evento: Button.Pressed) -> None:
        self._mensaje_auto("Generando informe global...", "ast-aviso")
        self._generar_informe()

    @work(thread=True, exclusive=True, group="reco-auto-informe", exit_on_error=False)
    def _generar_informe(self) -> None:
        try:
            base_datos = obtener_base_datos()
            proyecto = resolver_proyecto(base_datos, None)
            ruta = generar_reporte(base_datos, proyecto, "html")
        except ErrorEST as exc:
            self.app.call_from_thread(self._mensaje_auto, texto_seguro(exc), "ast-error")
            return
        except Exception as exc:  # noqa: BLE001 - frontera de la interfaz visual
            self.app.call_from_thread(
                self._mensaje_auto, f"Error inesperado: {texto_seguro(exc)}", "ast-error"
            )
            return
        self.app.call_from_thread(
            self._mensaje_auto, f"Informe generado en: {texto_seguro(ruta)}", "ast-exito"
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
        # protocolo/estado/servicio/version vienen de la respuesta del objetivo
        # escaneado: se escapan siempre antes de mostrarlos (ver ui/consola.py).
        for puerto in resultado.puertos:
            tabla.add_row(
                str(puerto.puerto),
                texto_seguro(puerto.protocolo),
                texto_seguro(puerto.estado),
                texto_seguro(puerto.servicio) if puerto.servicio else "-",
                texto_seguro(puerto.version) if puerto.version else "-",
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



class PanelVulnerabilidades(VerticalScroll):
    """Nuclei: plantillas HTTP aprobadas de bajo impacto, dentro del alcance autorizado.

    Misma politica de cancelacion y de secuencia que ``PanelReconocimiento``: cada
    analisis tiene su propio numero de secuencia (solo el mas reciente puede actualizar
    la tabla) y la cancelacion detiene el proceso de Nuclei de verdad sin guardar ningun
    hallazgo parcial (ver ``commands/nuclei.py``). El boton "Analizar" exige, ademas,
    haber marcado la casilla de confirmacion: es la "confirmacion antes de iniciar" que
    pide el panel, para que un clic accidental no dispare un analisis real.
    """

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._worker = None
        self._secuencia = 0
        self._guardados: list = []
        self._id_seleccionado: int | None = None

    _DESCRIPCION_PLANTILLA_POR_DEFECTO = (
        "Navega con las flechas o el raton para ver aqui la descripcion completa de "
        "cada plantilla; marca su casilla (barra espaciadora o clic) para incluirla "
        "en el analisis."
    )

    def compose(self):
        yield Static("Vulnerabilidades (Nuclei)", classes="titulo-panel")
        yield Static("", id="nuclei-deteccion", classes="ast-tenue")
        yield Static("", id="nuclei-proyecto", classes="ast-tenue")

        yield Static("1. Elige las plantillas aprobadas", classes="ast-subtitulo")
        yield SelectionList(
            *[
                (f"{info.id_} ({info.severidad_esperada}) - {info.nombre}", info.id_)
                for info in PLANTILLAS_APROBADAS.values()
            ],
            id="nuclei-plantillas",
        )
        yield Button("Seleccionar todas las aprobadas", id="nuclei-seleccionar-todas")
        yield Static(
            self._DESCRIPCION_PLANTILLA_POR_DEFECTO, id="nuclei-plantilla-detalle",
            classes="ast-caja",
        )

        yield Static("2. Confirma el objetivo autorizado", classes="ast-subtitulo")
        yield Input(
            placeholder="Objetivo autorizado (IP o esquema://IP:puerto)", id="nuclei-objetivo"
        )
        with Horizontal():
            yield Input(placeholder="Tiempo limite en segundos (60)", id="nuclei-tiempo-limite")
            yield Checkbox("Confirmo que el objetivo esta autorizado", id="nuclei-confirmar")
        with Horizontal():
            yield Button("Analizar", id="nuclei-analizar", variant="primary")
            yield Button("Cancelar", id="nuclei-cancelar")
        yield Static("", id="nuclei-mensaje", classes="ast-tenue")

        yield Static("3. Resultados", classes="ast-subtitulo")
        yield DataTable(id="nuclei-tabla", cursor_type="row")
        yield Static("", id="nuclei-detalle", classes="ast-caja")
        with Horizontal():
            yield Button("Marcar confirmado", id="nuclei-marcar-confirmado")
            yield Button("Marcar falso positivo", id="nuclei-marcar-falso-positivo")

    def on_mount(self) -> None:
        self.query_one("#nuclei-tabla", DataTable).add_columns(
            "Id", "Plantilla", "Hallazgo", "Severidad", "Revision"
        )
        self.refrescar()

    def refrescar(self) -> None:
        self._refrescar_deteccion()
        self._refrescar_proyecto()

    def _refrescar_deteccion(self) -> None:
        self.query_one("#nuclei-deteccion", Static).update("Nuclei: comprobando...")
        self._detectar_nuclei()

    @work(thread=True, exclusive=True, group="nuclei-deteccion", exit_on_error=False)
    def _detectar_nuclei(self) -> None:
        info = AdaptadorNuclei().info()
        self.app.call_from_thread(self._mostrar_deteccion_nuclei, info)

    def _mostrar_deteccion_nuclei(self, info) -> None:
        estado = "Instalada" if info.instalada else "No instalada"
        version = f" (version {texto_seguro(info.version)})" if info.version else ""
        self.query_one("#nuclei-deteccion", Static).update(f"Nuclei: {estado}{version}")

    def _refrescar_proyecto(self) -> None:
        etiqueta = self.query_one("#nuclei-proyecto", Static)
        try:
            proyecto = resolver_proyecto(obtener_base_datos(), None)
            etiqueta.update(f"Proyecto activo: {texto_seguro(proyecto.nombre)}")
        except ErrorEST as exc:
            etiqueta.update(texto_seguro(exc))

    def _mensaje(self, texto: str, clase: str = "ast-tenue") -> None:
        msg = self.query_one("#nuclei-mensaje", Static)
        msg.update(texto)
        msg.set_classes(clase)

    @on(Button.Pressed, "#nuclei-seleccionar-todas")
    def _seleccionar_todas(self, _evento: Button.Pressed) -> None:
        self.query_one("#nuclei-plantillas", SelectionList).select_all()

    @on(SelectionList.SelectionHighlighted, "#nuclei-plantillas")
    def _plantilla_resaltada(self, event: SelectionList.SelectionHighlighted) -> None:
        info = PLANTILLAS_APROBADAS.get(str(event.selection.value))
        detalle = self.query_one("#nuclei-plantilla-detalle", Static)
        if info is None:
            detalle.update(self._DESCRIPCION_PLANTILLA_POR_DEFECTO)
            return
        detalle.update(
            f"[bold]{texto_seguro(info.id_)}[/bold] - {texto_seguro(info.nombre)}\n"
            f"Severidad esperada: {texto_seguro(info.severidad_esperada)}\n"
            f"{texto_seguro(info.descripcion)}"
        )

    @on(Button.Pressed, "#nuclei-analizar")
    def _iniciar(self, _evento: Button.Pressed) -> None:
        self._refrescar_proyecto()
        objetivo = self.query_one("#nuclei-objetivo", Input).value.strip()
        plantillas_ids = list(self.query_one("#nuclei-plantillas", SelectionList).selected)
        tiempo_limite_txt = self.query_one("#nuclei-tiempo-limite", Input).value.strip()
        confirmado = self.query_one("#nuclei-confirmar", Checkbox).value

        if not plantillas_ids:
            self._mensaje("Selecciona al menos una plantilla aprobada.", "ast-aviso")
            return
        if not confirmado:
            self._mensaje(
                "Confirma que el objetivo esta autorizado (casilla) antes de analizar.",
                "ast-aviso",
            )
            return
        try:
            tiempo_limite = float(tiempo_limite_txt) if tiempo_limite_txt else 60.0
        except ValueError:
            self._mensaje("El tiempo limite debe ser numerico.", "ast-error")
            return

        self._secuencia += 1
        secuencia = self._secuencia
        self._id_seleccionado = None
        self.query_one("#nuclei-detalle", Static).update("")

        self._mensaje("Ejecutando Nuclei... (puedes cancelar mientras se ejecuta)", "ast-aviso")
        self._worker = self._analizar(secuencia, objetivo, plantillas_ids, tiempo_limite)

    @on(Button.Pressed, "#nuclei-cancelar")
    def _cancelar(self, _evento: Button.Pressed) -> None:
        if self._worker is not None and self._worker.is_running:
            self._worker.cancel()
            self._mensaje(
                "Cancelacion solicitada: no se guardara ningun hallazgo de este "
                "analisis (el proceso de Nuclei se detiene).",
                "ast-aviso",
            )

    @work(thread=True, exclusive=True, group="nuclei-analisis", exit_on_error=False)
    def _analizar(
        self, secuencia: int, objetivo: str, plantillas_ids: list[str], tiempo_limite: float
    ) -> None:
        worker = get_current_worker()
        try:
            base_datos = obtener_base_datos()
            proyecto = resolver_proyecto(base_datos, None)
            _resultado, guardados = ejecutar_nuclei(
                base_datos,
                proyecto,
                objetivo,
                plantillas_ids,
                tiempo_limite=tiempo_limite,
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
        self.app.call_from_thread(self._mostrar_resultados, secuencia, guardados)

    def _mostrar_resultados(self, secuencia: int, guardados: list) -> None:
        if secuencia != self._secuencia:
            return
        self._guardados = guardados
        self._redibujar_tabla()
        self._mensaje(f"Analisis completo: {len(guardados)} hallazgos.", "ast-exito")
        self.app.refrescar_estado()  # type: ignore[attr-defined]

    def _redibujar_tabla(self) -> None:
        tabla = self.query_one("#nuclei-tabla", DataTable)
        tabla.clear()
        for g in self._guardados:
            tabla.add_row(
                str(g.id), texto_seguro(g.plantilla_id), texto_seguro(g.nombre_hallazgo),
                texto_seguro(g.severidad), texto_seguro(g.estado_revision), key=str(g.id),
            )

    @on(DataTable.RowSelected, "#nuclei-tabla")
    def _fila_seleccionada(self, event: DataTable.RowSelected) -> None:
        if event.row_key.value is None:
            return
        try:
            id_seleccionado = int(event.row_key.value)
        except ValueError:
            return
        hallazgo = next((g for g in self._guardados if g.id == id_seleccionado), None)
        if hallazgo is None:
            return
        self._id_seleccionado = id_seleccionado
        info = PLANTILLAS_APROBADAS.get(hallazgo.plantilla_id)
        recomendacion = info.recomendacion if info is not None else "-"
        self.query_one("#nuclei-detalle", Static).update(
            f"[bold]{texto_seguro(hallazgo.nombre_hallazgo)}[/bold]\n"
            f"Severidad: {texto_seguro(hallazgo.severidad)}\n"
            f"Descripcion: {texto_seguro(hallazgo.descripcion)}\n"
            f"Evidencia: {texto_seguro(hallazgo.evidencia or '-')}\n"
            f"Recomendacion: {texto_seguro(recomendacion)}\n"
            f"Estado de revision: {texto_seguro(hallazgo.estado_revision)} (revisa la "
            "evidencia antes de confirmar: podria ser un falso positivo)."
        )

    def _marcar_revision(self, estado: str) -> None:
        if self._id_seleccionado is None:
            self._mensaje("Selecciona primero un hallazgo en la tabla.", "ast-aviso")
            return
        try:
            obtener_base_datos().actualizar_estado_revision_nuclei(self._id_seleccionado, estado)
        except ErrorEST as exc:
            self._mensaje(texto_seguro(exc), "ast-error")
            return
        self._guardados = [
            g if g.id != self._id_seleccionado else replace(g, estado_revision=estado)
            for g in self._guardados
        ]
        self._redibujar_tabla()
        self._mensaje(f"Hallazgo {self._id_seleccionado} marcado como '{estado}'.", "ast-exito")

    @on(Button.Pressed, "#nuclei-marcar-confirmado")
    def _marcar_confirmado(self, _evento: Button.Pressed) -> None:
        self._marcar_revision("confirmado")

    @on(Button.Pressed, "#nuclei-marcar-falso-positivo")
    def _marcar_falso_positivo(self, _evento: Button.Pressed) -> None:
        self._marcar_revision("falso_positivo")


class PanelOWASPZAP(VerticalScroll):
    """OWASP ZAP: analisis pasivo unicamente, dentro del alcance autorizado.

    Misma politica de cancelacion y de secuencia que ``PanelVulnerabilidades``: cada
    analisis tiene su propio numero de secuencia (solo el mas reciente puede actualizar
    la tabla) y la cancelacion no guarda ningun hallazgo parcial (ver
    ``commands/zap.py``). El boton "Analizar" exige, ademas, haber marcado la casilla de
    confirmacion. Esta seccion nunca ofrece active scan, spider ni fuzzing: solo hace
    una unica peticion GET controlada (a traves de la propia API de ZAP) para alimentar
    su analizador pasivo.
    """

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._worker = None
        self._secuencia = 0
        self._guardados: list = []
        self._id_seleccionado: int | None = None

    def compose(self):
        yield Static("OWASP ZAP (analisis pasivo)", classes="titulo-panel")
        yield Static("", id="zap-deteccion", classes="ast-tenue")
        yield Static("", id="zap-proyecto", classes="ast-tenue")
        yield Static(
            "Solo analisis pasivo: nunca active scan, spider, ajaxSpider ni fuzzing. "
            "AST hace una unica peticion GET (via la API de ZAP) para alimentar el "
            "analizador pasivo, y lee solo las alertas del objetivo indicado.",
            classes="ast-caja",
        )
        yield Input(
            placeholder="URL autorizada (http://IP:puerto/ruta)", id="zap-objetivo"
        )
        with Horizontal():
            yield Input(placeholder="Tiempo limite en segundos (60)", id="zap-tiempo-limite")
            yield Checkbox("Confirmo que el objetivo esta autorizado", id="zap-confirmar")
        with Horizontal():
            yield Button("Analizar", id="zap-analizar", variant="primary")
            yield Button("Cancelar", id="zap-cancelar")
        yield Static("", id="zap-mensaje", classes="ast-tenue")
        yield DataTable(id="zap-tabla", cursor_type="row")
        yield Static("", id="zap-detalle", classes="ast-caja")
        with Horizontal():
            yield Button("Marcar confirmado", id="zap-marcar-confirmado")
            yield Button("Marcar falso positivo", id="zap-marcar-falso-positivo")

    def on_mount(self) -> None:
        self.query_one("#zap-tabla", DataTable).add_columns(
            "Id", "Regla", "Hallazgo", "Riesgo", "Revision"
        )
        self.refrescar()

    def refrescar(self) -> None:
        self._refrescar_deteccion()
        self._refrescar_proyecto()

    def _refrescar_deteccion(self) -> None:
        self.query_one("#zap-deteccion", Static).update("OWASP ZAP: comprobando...")
        self._detectar_zap()

    @work(thread=True, exclusive=True, group="zap-deteccion", exit_on_error=False)
    def _detectar_zap(self) -> None:
        # Sin instancia de ZAP corriendo (el caso comun en desarrollo), AdaptadorZAP().info()
        # puede tardar ~2s en el timeout de conexion por defecto: medido empiricamente, es
        # el mayor bloqueo que sufria la interfaz al cambiar de panel (ver docs/ROADMAP.md).
        # Ejecutarlo en un worker evita congelar la UI cada vez que se visita esta seccion.
        info = AdaptadorZAP().info()
        self.app.call_from_thread(self._mostrar_deteccion_zap, info)

    def _mostrar_deteccion_zap(self, info) -> None:
        estado = "Disponible" if info.disponible else "No disponible"
        version = f" (version {texto_seguro(info.version)})" if info.version else ""
        self.query_one("#zap-deteccion", Static).update(f"OWASP ZAP: {estado}{version}")

    def _refrescar_proyecto(self) -> None:
        etiqueta = self.query_one("#zap-proyecto", Static)
        try:
            proyecto = resolver_proyecto(obtener_base_datos(), None)
            etiqueta.update(f"Proyecto activo: {texto_seguro(proyecto.nombre)}")
        except ErrorEST as exc:
            etiqueta.update(texto_seguro(exc))

    def _mensaje(self, texto: str, clase: str = "ast-tenue") -> None:
        msg = self.query_one("#zap-mensaje", Static)
        msg.update(texto)
        msg.set_classes(clase)

    @on(Button.Pressed, "#zap-analizar")
    def _iniciar(self, _evento: Button.Pressed) -> None:
        self._refrescar_proyecto()
        objetivo = self.query_one("#zap-objetivo", Input).value.strip()
        tiempo_limite_txt = self.query_one("#zap-tiempo-limite", Input).value.strip()
        confirmado = self.query_one("#zap-confirmar", Checkbox).value

        if not objetivo:
            self._mensaje("Indica la URL autorizada a auditar.", "ast-aviso")
            return
        if not confirmado:
            self._mensaje(
                "Confirma que el objetivo esta autorizado (casilla) antes de analizar.",
                "ast-aviso",
            )
            return
        try:
            tiempo_limite = float(tiempo_limite_txt) if tiempo_limite_txt else 60.0
        except ValueError:
            self._mensaje("El tiempo limite debe ser numerico.", "ast-error")
            return

        self._secuencia += 1
        secuencia = self._secuencia
        self._id_seleccionado = None
        self.query_one("#zap-detalle", Static).update("")

        self._mensaje(
            "Ejecutando analisis pasivo de ZAP... (puedes cancelar mientras se ejecuta)",
            "ast-aviso",
        )
        self._worker = self._analizar(secuencia, objetivo, tiempo_limite)

    @on(Button.Pressed, "#zap-cancelar")
    def _cancelar(self, _evento: Button.Pressed) -> None:
        if self._worker is not None and self._worker.is_running:
            self._worker.cancel()
            self._mensaje(
                "Cancelacion solicitada: no se guardara ningun hallazgo de este analisis.",
                "ast-aviso",
            )

    @work(thread=True, exclusive=True, group="zap-analisis", exit_on_error=False)
    def _analizar(self, secuencia: int, objetivo: str, tiempo_limite: float) -> None:
        worker = get_current_worker()
        try:
            base_datos = obtener_base_datos()
            proyecto = resolver_proyecto(base_datos, None)
            _resultado, guardados = ejecutar_zap_pasivo(
                base_datos,
                proyecto,
                objetivo,
                tiempo_limite=tiempo_limite,
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
        self.app.call_from_thread(self._mostrar_resultados, secuencia, guardados)

    def _mostrar_resultados(self, secuencia: int, guardados: list) -> None:
        if secuencia != self._secuencia:
            return
        self._guardados = guardados
        self._redibujar_tabla()
        self._mensaje(f"Analisis completo: {len(guardados)} hallazgos.", "ast-exito")
        self.app.refrescar_estado()  # type: ignore[attr-defined]

    def _redibujar_tabla(self) -> None:
        tabla = self.query_one("#zap-tabla", DataTable)
        tabla.clear()
        for g in self._guardados:
            tabla.add_row(
                str(g.id), texto_seguro(g.plugin_id), texto_seguro(g.nombre_hallazgo),
                texto_seguro(g.riesgo), texto_seguro(g.estado_revision), key=str(g.id),
            )

    @on(DataTable.RowSelected, "#zap-tabla")
    def _fila_seleccionada(self, event: DataTable.RowSelected) -> None:
        if event.row_key.value is None:
            return
        try:
            id_seleccionado = int(event.row_key.value)
        except ValueError:
            return
        hallazgo = next((g for g in self._guardados if g.id == id_seleccionado), None)
        if hallazgo is None:
            return
        self._id_seleccionado = id_seleccionado
        self.query_one("#zap-detalle", Static).update(
            f"[bold]{texto_seguro(hallazgo.nombre_hallazgo)}[/bold]\n"
            f"Riesgo: {texto_seguro(hallazgo.riesgo)}  |  "
            f"Confianza: {texto_seguro(hallazgo.confianza)}\n"
            f"Descripcion: {texto_seguro(hallazgo.descripcion)}\n"
            f"Evidencia: {texto_seguro(hallazgo.evidencia or '-')}\n"
            f"Solucion: {texto_seguro(hallazgo.solucion)}\n"
            f"Referencia: {texto_seguro(hallazgo.referencia or '-')}\n"
            f"Estado de revision: {texto_seguro(hallazgo.estado_revision)} (revisa la "
            "evidencia antes de confirmar: podria ser un falso positivo)."
        )

    def _marcar_revision(self, estado: str) -> None:
        if self._id_seleccionado is None:
            self._mensaje("Selecciona primero un hallazgo en la tabla.", "ast-aviso")
            return
        try:
            obtener_base_datos().actualizar_estado_revision_zap(self._id_seleccionado, estado)
        except ErrorEST as exc:
            self._mensaje(texto_seguro(exc), "ast-error")
            return
        self._guardados = [
            g if g.id != self._id_seleccionado else replace(g, estado_revision=estado)
            for g in self._guardados
        ]
        self._redibujar_tabla()
        self._mensaje(f"Hallazgo {self._id_seleccionado} marcado como '{estado}'.", "ast-exito")

    @on(Button.Pressed, "#zap-marcar-confirmado")
    def _marcar_confirmado(self, _evento: Button.Pressed) -> None:
        self._marcar_revision("confirmado")

    @on(Button.Pressed, "#zap-marcar-falso-positivo")
    def _marcar_falso_positivo(self, _evento: Button.Pressed) -> None:
        self._marcar_revision("falso_positivo")


class PanelResultados(VerticalScroll):
    """Resultados y hallazgos guardados del proyecto activo, de las cinco herramientas.

    Es una vista de solo lectura/filtrado: para marcar un hallazgo de Nuclei u OWASP ZAP
    como confirmado o falso positivo se usan sus paneles dedicados ('Vulnerabilidades',
    'OWASP ZAP'), que son los que escriben ese estado de revision. Reutiliza
    ``commands/resultados.py:obtener_resultados_unificados`` (y, por lo tanto,
    ``BaseDatos.listar_resultados_unificados``): nunca consulta las tablas directamente.
    """

    _ETIQUETAS_FUENTE = {
        "tcp": "TCP", "nmap": "Nmap", "web": "Web", "nuclei": "Nuclei", "zap": "OWASP ZAP",
    }
    # 'vulnerabilidades' agrupa las tres fuentes que reportan hallazgos de seguridad,
    # para distinguirlas de 'tcp'/'nmap' (conectividad/puertos, nunca una
    # vulnerabilidad -- ver core de BaseDatos.listar_resultados_unificados).
    _FUENTES_VULNERABILIDAD = frozenset({"web", "nuclei", "zap"})

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._resultados: list = []
        self._sesion_preseleccionada: int | None = None

    def compose(self):
        yield Static("Resultados guardados (todas las herramientas)", classes="titulo-panel")
        yield Static("", id="res-proyecto", classes="ast-tenue")
        with Horizontal():
            yield Select(
                [
                    ("Todas las herramientas", "todas"),
                    ("Solo vulnerabilidades (web+Nuclei+ZAP)", "vulnerabilidades"),
                    ("TCP", "tcp"),
                    ("Nmap", "nmap"),
                    ("Web", "web"),
                    ("Nuclei", "nuclei"),
                    ("OWASP ZAP", "zap"),
                ],
                value="todas",
                allow_blank=False,
                id="res-fuente",
            )
            yield Select(
                [("Todas las sesiones", "todas")],
                value="todas",
                allow_blank=False,
                id="res-sesion",
            )
            yield Button("Actualizar", id="res-refrescar")
        yield DataTable(id="res-tabla", cursor_type="row")
        yield Static("", id="res-detalle", classes="ast-caja")
        yield Static("", id="res-mensaje", classes="ast-tenue")

    def on_mount(self) -> None:
        self.query_one("#res-tabla", DataTable).add_columns(
            "Fuente", "Objetivo", "Hallazgo", "Severidad", "Estado", "Revision", "Fecha"
        )
        self.refrescar()

    def _refrescar_proyecto(self):
        etiqueta = self.query_one("#res-proyecto", Static)
        try:
            proyecto = resolver_proyecto(obtener_base_datos(), None)
            etiqueta.update(f"Proyecto activo: {texto_seguro(proyecto.nombre)}")
            return proyecto
        except ErrorEST as exc:
            etiqueta.update(texto_seguro(exc))
            return None

    def _refrescar_opciones_sesion(self, proyecto) -> None:
        """Repuebla el selector de sesiones con las sesiones de reconocimiento
        automatico guardadas del proyecto, conservando la seleccion actual si sigue
        existiendo (nunca mezcla resultados de dos sesiones distintas: filtrar por una
        sesion filtra por su ventana de tiempo -- creado_en/actualizado_en)."""
        selector = self.query_one("#res-sesion", Select)
        valor_actual = selector.value
        sesiones = obtener_base_datos().listar_sesiones_reconocimiento(proyecto.id, limite=50)
        opciones = [("Todas las sesiones", "todas")] + [
            (
                f"#{s.id} {s.objetivo_original[:30]} ({s.estado_general}, {s.creado_en[:19]})",
                str(s.id),
            )
            for s in sesiones
        ]
        selector.set_options(opciones)
        valores_validos = {valor for _etiqueta, valor in opciones}
        if self._sesion_preseleccionada is not None and str(
            self._sesion_preseleccionada
        ) in valores_validos:
            selector.value = str(self._sesion_preseleccionada)
            self._sesion_preseleccionada = None
        elif valor_actual in valores_validos:
            selector.value = valor_actual
        else:
            selector.value = "todas"

    def refrescar(self) -> None:
        proyecto = self._refrescar_proyecto()
        tabla = self.query_one("#res-tabla", DataTable)
        tabla.clear()
        self.query_one("#res-detalle", Static).update("")
        msg = self.query_one("#res-mensaje", Static)
        if proyecto is None:
            return
        self._refrescar_opciones_sesion(proyecto)

        fuente_valor = self.query_one("#res-fuente", Select).value
        sesion_valor = self.query_one("#res-sesion", Select).value
        try:
            base_datos = obtener_base_datos()
            if fuente_valor in (None, "todas"):
                fuentes = None
            elif fuente_valor == "vulnerabilidades":
                fuentes = self._FUENTES_VULNERABILIDAD
            else:
                fuentes = frozenset({str(fuente_valor)})

            desde = hasta = None
            if sesion_valor not in (None, "todas"):
                sesion = base_datos.obtener_sesion_reconocimiento(int(str(sesion_valor)))
                desde, hasta = sesion.creado_en, sesion.actualizado_en

            resultados = obtener_resultados_unificados(
                base_datos, proyecto, fuentes=fuentes, desde=desde, hasta=hasta, limite=200
            )
            self._resultados = resultados
            for r in resultados:
                tabla.add_row(
                    self._ETIQUETAS_FUENTE.get(r.fuente, r.fuente),
                    texto_seguro(r.objetivo),
                    texto_seguro(r.nombre),
                    texto_seguro(r.severidad) if r.severidad else "-",
                    texto_seguro(r.estado) if r.estado else "-",
                    texto_seguro(r.estado_revision) if r.estado_revision else "-",
                    r.creado_en,
                    key=f"{r.fuente}:{r.id_origen}",
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

    def seleccionar_sesion(self, sesion_id: int) -> None:
        """Preselecciona una sesion antes del siguiente ``refrescar()`` (usado por
        'Ver vulnerabilidades' en el panel Reconocimiento para abrir directamente en
        la sesion que se acaba de ejecutar)."""
        self._sesion_preseleccionada = sesion_id

    @on(Button.Pressed, "#res-refrescar")
    def _refrescar_click(self, _evento: Button.Pressed) -> None:
        self.refrescar()

    @on(Select.Changed, "#res-fuente")
    def _fuente_cambiada(self, _evento: Select.Changed) -> None:
        self.refrescar()

    @on(Select.Changed, "#res-sesion")
    def _sesion_cambiada(self, _evento: Select.Changed) -> None:
        self.refrescar()

    @on(DataTable.RowSelected, "#res-tabla")
    def _fila_seleccionada(self, event: DataTable.RowSelected) -> None:
        if event.row_key.value is None:
            return
        fuente, _separador, id_txt = str(event.row_key.value).partition(":")
        try:
            id_origen = int(id_txt)
        except ValueError:
            return
        r = next(
            (x for x in self._resultados if x.fuente == fuente and x.id_origen == id_origen),
            None,
        )
        if r is None:
            return
        self.query_one("#res-detalle", Static).update(
            f"[bold]{texto_seguro(r.nombre)}[/bold] "
            f"({self._ETIQUETAS_FUENTE.get(r.fuente, r.fuente)})\n"
            f"Tipo: {texto_seguro(r.tipo)}\n"
            f"Descripcion: {texto_seguro(r.descripcion or '-')}\n"
            f"Evidencia: {texto_seguro(r.evidencia or '-')}\n"
            f"Recomendacion: {texto_seguro(r.recomendacion or '-')}\n"
            f"Referencia: {texto_seguro(r.referencia or '-')}"
        )


_ESTILOS_ESTADO_FUENTE_OSINT = {
    "completada": "bold green",
    "ejecutando": "bold yellow",
    "pendiente": "grey70",
    "omitida": "grey70",
    "fallida": "bold red",
    "cancelada": "bold red",
}
_ESTILOS_CONFIANZA_OSINT = {
    "confirmado": "bold green",
    "probable": "yellow",
    "no_verificado": "grey70",
}
_CATEGORIAS_INFRAESTRUCTURA_OSINT = frozenset(
    {"dns", "rdap", "infraestructura", "certificados", "correo", "historial_escaneos"}
)


class PanelOSINT(VerticalScroll):
    """Investigacion de fuentes publicas (OSINT) sobre un objetivo autorizado.

    Reutiliza integramente ``modules/osint/motor.py`` (igual que ``PanelReconocimiento``
    reutiliza su propio orquestador): este panel solo construye el formulario, lanza la
    investigacion en un worker y presenta sus hallazgos ya guardados, nunca duplica la
    logica de validacion, autorizacion ni persistencia.
    """

    _OPCIONES_TIPO = [
        ("Dominio / empresa", "dominio"),
        ("Correo electronico", "correo"),
        ("Telefono", "telefono"),
        ("Nombre de usuario", "usuario"),
    ]

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._worker = None
        self._secuencia = 0
        self._investigacion_actual_id: int | None = None
        self._hallazgos: list = []

    def compose(self):
        yield Static("OSINT: investigacion de fuentes publicas", classes="titulo-panel")
        yield Static("", id="osint-proyecto", classes="ast-tenue")
        yield Static(
            "Investiga fuentes publicas verificables sobre un dominio, correo, telefono "
            "o nombre de usuario. Nunca ejecuta un escaneo activo contra el objetivo: solo "
            "consulta fuentes publicas ya documentadas (DNS, RDAP, Certificate "
            "Transparency, APIs publicas...). Correo/telefono/usuario exigen confirmar "
            "que el objetivo es propio o su revision esta autorizada.",
            classes="ast-caja",
        )
        with Horizontal():
            yield Select(self._OPCIONES_TIPO, value="dominio", allow_blank=False, id="osint-tipo")
            yield Input(placeholder="Objetivo a investigar", id="osint-objetivo")
        yield Input(
            placeholder="Region ISO (opcional, solo para telefono sin '+pais', ej. CO)",
            id="osint-region",
        )
        yield Checkbox(
            "Confirmo que el objetivo es propio o su revision esta autorizada "
            "(obligatorio para correo/telefono/usuario)",
            id="osint-autorizo",
        )
        with Collapsible(title="Fuentes a consultar (todas las aplicables si no eliges)"):
            yield SelectionList(id="osint-fuentes")
        with Horizontal():
            yield Button("Iniciar investigacion", id="osint-iniciar", variant="primary")
            yield Button("Cancelar", id="osint-cancelar")
        yield Static("", id="osint-mensaje", classes="ast-tenue")

        with TabbedContent(id="osint-tabs"):
            with TabPane("Resumen", id="osint-tab-resumen"):
                yield DataTable(id="osint-tabla-etapas", cursor_type="row")
                yield Static("", id="osint-resumen", classes="ast-caja")
            with TabPane("Infraestructura", id="osint-tab-infraestructura"):
                yield DataTable(id="osint-tabla-infraestructura", cursor_type="row")
                yield Static("", id="osint-detalle-infraestructura", classes="ast-caja")
            with TabPane("Perfiles publicos", id="osint-tab-perfiles"):
                yield DataTable(id="osint-tabla-perfiles", cursor_type="row")
                yield Static("", id="osint-detalle-perfiles", classes="ast-caja")
            with TabPane("Exposicion", id="osint-tab-exposicion"):
                yield DataTable(id="osint-tabla-exposicion", cursor_type="row")
                yield Static("", id="osint-detalle-exposicion", classes="ast-caja")
            with TabPane("Fuentes", id="osint-tab-fuentes"):
                yield DataTable(id="osint-tabla-fuentes", cursor_type="row")
            with TabPane("Informe", id="osint-tab-informe"):
                with Horizontal():
                    yield Select(
                        [("HTML", "html"), ("JSON", "json")],
                        value="html",
                        allow_blank=False,
                        id="osint-informe-formato",
                    )
                    yield Checkbox(
                        "Minimizar objetivo (correo/telefono/usuario) en el informe",
                        id="osint-informe-minimizar",
                    )
                    yield Button("Generar informe", id="osint-informe-generar", variant="primary")
                yield Static("", id="osint-informe-mensaje", classes="ast-tenue")

    def on_mount(self) -> None:
        for id_tabla, columnas in (
            ("osint-tabla-etapas", ("Fuente", "Estado", "Detalle")),
            (
                "osint-tabla-infraestructura",
                ("Fuente", "Titulo", "Confianza", "Indicador", "Fecha"),
            ),
            ("osint-tabla-perfiles", ("Fuente", "Titulo", "Confianza", "Fecha")),
            ("osint-tabla-exposicion", ("Fuente", "Titulo", "Confianza", "Indicador", "Fecha")),
            ("osint-tabla-fuentes", ("Id", "Nombre", "Tipos de objetivo", "Estado")),
        ):
            self.query_one(f"#{id_tabla}", DataTable).add_columns(*columnas)
        self._repoblar_fuentes()
        self._refrescar_catalogo_fuentes()
        self.refrescar()

    def refrescar(self) -> None:
        self._refrescar_proyecto()

    def _refrescar_proyecto(self):
        etiqueta = self.query_one("#osint-proyecto", Static)
        try:
            proyecto = resolver_proyecto(obtener_base_datos(), None)
            etiqueta.update(f"Proyecto activo: {texto_seguro(proyecto.nombre)}")
            return proyecto
        except ErrorEST as exc:
            etiqueta.update(texto_seguro(exc))
            return None

    def _mensaje(self, texto: str, clase: str = "ast-tenue") -> None:
        msg = self.query_one("#osint-mensaje", Static)
        msg.update(texto)
        msg.set_classes(clase)

    def _repoblar_fuentes(self) -> None:
        tipo = str(self.query_one("#osint-tipo", Select).value)
        selector = self.query_one("#osint-fuentes", SelectionList)
        selector.clear_options()
        selector.add_options(
            [
                (adaptador.nombre, id_fuente)
                for id_fuente, adaptador in fuentes_para_tipo(tipo).items()
            ]
        )

    def _refrescar_catalogo_fuentes(self) -> None:
        tabla = self.query_one("#osint-tabla-fuentes", DataTable)
        tabla.clear()
        for id_fuente, adaptador in FUENTES_OSINT.items():
            estado = "Disponible" if adaptador.configurada() else "Requiere configuracion"
            tabla.add_row(
                id_fuente,
                adaptador.nombre,
                ", ".join(sorted(adaptador.tipos_objetivo)),
                estado,
            )

    @on(Select.Changed, "#osint-tipo")
    def _tipo_cambiado(self, _evento: Select.Changed) -> None:
        self._repoblar_fuentes()

    @on(Button.Pressed, "#osint-iniciar")
    def _iniciar(self, _evento: Button.Pressed) -> None:
        self._refrescar_proyecto()
        tipo = str(self.query_one("#osint-tipo", Select).value)
        objetivo = self.query_one("#osint-objetivo", Input).value.strip()
        region = self.query_one("#osint-region", Input).value.strip() or None
        autorizado = self.query_one("#osint-autorizo", Checkbox).value
        fuentes_ids = set(self.query_one("#osint-fuentes", SelectionList).selected)

        if not objetivo:
            self._mensaje("Escribe un objetivo antes de iniciar.", "ast-aviso")
            return
        if requiere_autorizacion_datos_personales(tipo) and not autorizado:
            self._mensaje(
                "Este tipo de objetivo puede exponer datos personales: marca la casilla "
                "de autorizacion antes de iniciar.",
                "ast-aviso",
            )
            return

        self._secuencia += 1
        secuencia = self._secuencia
        self._investigacion_actual_id = None
        self._hallazgos = []
        self.query_one("#osint-tabla-etapas", DataTable).clear()
        self._limpiar_tablas_resultados()
        self.query_one("#osint-resumen", Static).update("")

        self._mensaje(
            "Ejecutando investigacion OSINT... (puedes cancelar mientras se ejecuta)",
            "ast-aviso",
        )
        self._worker = self._ejecutar(
            secuencia,
            tipo,
            objetivo,
            autorizado,
            region,
            frozenset(fuentes_ids) if fuentes_ids else None,
        )

    @on(Button.Pressed, "#osint-cancelar")
    def _cancelar(self, _evento: Button.Pressed) -> None:
        if self._worker is not None and self._worker.is_running:
            self._worker.cancel()
            self._mensaje(
                "Cancelacion solicitada: la fuente en curso no se persiste; las ya "
                "completadas se conservan.",
                "ast-aviso",
            )

    @work(thread=True, exclusive=True, group="osint-investigacion", exit_on_error=False)
    def _ejecutar(
        self,
        secuencia: int,
        tipo: str,
        objetivo: str,
        autorizado: bool,
        region: str | None,
        fuentes: frozenset[str] | None,
    ) -> None:
        worker = get_current_worker()

        def _progreso(etapa: EtapaFuenteOSINT) -> None:
            if secuencia == self._secuencia:
                self.app.call_from_thread(self._actualizar_etapa, etapa)

        try:
            base_datos = obtener_base_datos()
            proyecto = resolver_proyecto(base_datos, None)
            resultado = ejecutar_investigacion_osint(
                base_datos,
                proyecto,
                tipo,
                objetivo,
                autorizado_datos_personales=autorizado,
                region_telefono=region,
                fuentes_seleccionadas=fuentes,
                callback_progreso=_progreso,
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
        self.app.call_from_thread(self._mostrar_resultado, secuencia, resultado)

    def _actualizar_etapa(self, etapa: EtapaFuenteOSINT) -> None:
        tabla = self.query_one("#osint-tabla-etapas", DataTable)
        estilo = _ESTILOS_ESTADO_FUENTE_OSINT.get(etapa.estado, "")
        estado_texto = (
            f"[{estilo}]{texto_seguro(etapa.estado)}[/{estilo}]"
            if estilo
            else texto_seguro(etapa.estado)
        )
        adaptador = FUENTES_OSINT.get(etapa.fuente)
        nombre_fuente = texto_seguro(adaptador.nombre if adaptador is not None else etapa.fuente)
        try:
            tabla.remove_row(etapa.fuente)
        except Exception:  # noqa: BLE001 - la fila puede no existir todavia
            pass
        tabla.add_row(nombre_fuente, estado_texto, texto_seguro(etapa.detalle), key=etapa.fuente)

    def _limpiar_tablas_resultados(self) -> None:
        for id_tabla in (
            "osint-tabla-infraestructura", "osint-tabla-perfiles", "osint-tabla-exposicion",
        ):
            self.query_one(f"#{id_tabla}", DataTable).clear()

    def _mostrar_resultado(self, secuencia: int, resultado) -> None:
        if secuencia != self._secuencia:
            return
        self._investigacion_actual_id = resultado.investigacion_id
        base_datos = obtener_base_datos()
        self._hallazgos = base_datos.listar_hallazgos_osint(
            investigacion_id=resultado.investigacion_id, limite=10_000
        )

        self._limpiar_tablas_resultados()
        tabla_infra = self.query_one("#osint-tabla-infraestructura", DataTable)
        tabla_perfiles = self.query_one("#osint-tabla-perfiles", DataTable)
        tabla_exposicion = self.query_one("#osint-tabla-exposicion", DataTable)

        for h in self._hallazgos:
            fila_comun = (
                texto_seguro(h.fuente),
                texto_seguro(h.titulo),
                self._confianza_coloreada(h.nivel_confianza),
            )
            if h.categoria in _CATEGORIAS_INFRAESTRUCTURA_OSINT:
                tabla_infra.add_row(
                    *fila_comun,
                    texto_seguro(h.indicador_exposicion) if h.indicador_exposicion else "-",
                    h.creado_en,
                    key=str(h.id),
                )
            if h.categoria == "perfil_publico":
                tabla_perfiles.add_row(*fila_comun, h.creado_en, key=str(h.id))
            if h.categoria == "exposicion" or h.indicador_exposicion:
                tabla_exposicion.add_row(
                    *fila_comun,
                    texto_seguro(h.indicador_exposicion) if h.indicador_exposicion else "-",
                    h.creado_en,
                    key=str(h.id),
                )

        resumen = construir_resumen_exposicion(self._hallazgos)
        texto_resumen = (
            f"Estado general: {texto_seguro(resultado.estado_general)}  |  "
            f"Total de hallazgos: {resumen.total_hallazgos}  |  "
            f"Indicadores de exposicion: {resumen.total_indicadores}"
        )
        if resultado.limitaciones:
            texto_resumen += "\n\n[bold yellow]Limitaciones:[/bold yellow]\n" + "\n".join(
                f"- {texto_seguro(lim)}" for lim in resultado.limitaciones
            )
        self.query_one("#osint-resumen", Static).update(texto_resumen)
        self._mensaje("Investigacion OSINT completa.", "ast-exito")
        self.app.refrescar_estado()  # type: ignore[attr-defined]

    @staticmethod
    def _confianza_coloreada(nivel: str) -> str:
        estilo = _ESTILOS_CONFIANZA_OSINT.get(nivel, "")
        nivel_seguro = texto_seguro(nivel)
        return f"[{estilo}]{nivel_seguro}[/{estilo}]" if estilo else nivel_seguro

    def _detalle_hallazgo(self, id_hallazgo_txt: str | None) -> str:
        if id_hallazgo_txt is None:
            return ""
        hallazgo = next((h for h in self._hallazgos if str(h.id) == id_hallazgo_txt), None)
        if hallazgo is None:
            return ""
        return (
            f"[bold]{texto_seguro(hallazgo.titulo)}[/bold] ({texto_seguro(hallazgo.fuente)})\n"
            f"Categoria: {texto_seguro(hallazgo.categoria)}  |  "
            f"Confianza: {texto_seguro(hallazgo.nivel_confianza)}\n"
            f"Descripcion: {texto_seguro(hallazgo.descripcion)}\n"
            f"Indicador de exposicion: {texto_seguro(hallazgo.indicador_exposicion or '-')}\n"
            f"Fecha de consulta: {texto_seguro(hallazgo.creado_en)}"
        )

    @on(DataTable.RowSelected, "#osint-tabla-infraestructura")
    def _fila_infraestructura_seleccionada(self, event: DataTable.RowSelected) -> None:
        detalle = self._detalle_hallazgo(
            str(event.row_key.value) if event.row_key.value is not None else None
        )
        self.query_one("#osint-detalle-infraestructura", Static).update(detalle)

    @on(DataTable.RowSelected, "#osint-tabla-perfiles")
    def _fila_perfiles_seleccionada(self, event: DataTable.RowSelected) -> None:
        detalle = self._detalle_hallazgo(
            str(event.row_key.value) if event.row_key.value is not None else None
        )
        self.query_one("#osint-detalle-perfiles", Static).update(detalle)

    @on(DataTable.RowSelected, "#osint-tabla-exposicion")
    def _fila_exposicion_seleccionada(self, event: DataTable.RowSelected) -> None:
        detalle = self._detalle_hallazgo(
            str(event.row_key.value) if event.row_key.value is not None else None
        )
        self.query_one("#osint-detalle-exposicion", Static).update(detalle)

    @on(Button.Pressed, "#osint-informe-generar")
    def _generar_informe_click(self, _evento: Button.Pressed) -> None:
        if self._investigacion_actual_id is None:
            self.query_one("#osint-informe-mensaje", Static).update(
                "Ejecuta una investigacion primero."
            )
            self.query_one("#osint-informe-mensaje", Static).set_classes("ast-aviso")
            return
        formato = str(self.query_one("#osint-informe-formato", Select).value)
        minimizar = self.query_one("#osint-informe-minimizar", Checkbox).value
        self._generar_informe(self._investigacion_actual_id, formato, minimizar)

    @work(thread=True, exclusive=True, group="osint-informe", exit_on_error=False)
    def _generar_informe(self, investigacion_id: int, formato: str, minimizar: bool) -> None:
        msg = self.query_one("#osint-informe-mensaje", Static)
        try:
            base_datos = obtener_base_datos()
            proyecto = resolver_proyecto(base_datos, None)
            ruta = generar_reporte_osint(
                base_datos, proyecto, investigacion_id, formato, minimizar=minimizar
            )
        except ErrorEST as exc:
            self.app.call_from_thread(msg.update, texto_seguro(exc))
            self.app.call_from_thread(msg.set_classes, "ast-error")
            return
        except Exception as exc:  # noqa: BLE001 - frontera de la interfaz visual
            self.app.call_from_thread(msg.update, f"Error inesperado: {texto_seguro(exc)}")
            self.app.call_from_thread(msg.set_classes, "ast-error")
            return
        self.app.call_from_thread(msg.update, f"Informe generado en: {texto_seguro(ruta)}")
        self.app.call_from_thread(msg.set_classes, "ast-exito")


class PanelReportes(Vertical):
    """Generacion del informe global (todas las herramientas) del proyecto activo."""

    def compose(self):
        yield Static("Generar informe global", classes="titulo-panel")
        yield Static(
            "Combina TCP, Nmap, auditoria web, Nuclei y OWASP ZAP en un unico informe. "
            "Los informes especificos de cada herramienta siguen disponibles en sus "
            "propios paneles/comandos.",
            classes="ast-caja",
        )
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
            msg.update(f"Informe global generado en: {texto_seguro(ruta)}")
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
        yield Static("", id="herr-mensaje", classes="ast-tenue")

    def on_mount(self) -> None:
        self.query_one("#herr-tabla", DataTable).add_columns(
            "Herramienta", "Comando", "Estado", "Version", "Ruta"
        )
        self.refrescar()

    def refrescar(self) -> None:
        """Dispara la deteccion en un worker: comprobar 4 binarios/servicios tarda
        cientos de milisegundos (ver docs/ROADMAP.md), y bloquear aqui congelaria la
        interfaz cada vez que el usuario visita este panel, no solo la primera vez."""
        self.query_one("#herr-mensaje", Static).update("Detectando herramientas...")
        self._detectar()

    @work(thread=True, exclusive=True, group="herr-deteccion", exit_on_error=False)
    def _detectar(self) -> None:
        herramientas = detectar_herramientas()
        self.app.call_from_thread(self._mostrar_herramientas, herramientas)

    def _mostrar_herramientas(self, herramientas: list) -> None:
        tabla = self.query_one("#herr-tabla", DataTable)
        tabla.clear()
        for herramienta in herramientas:
            estado = "Instalada" if herramienta.instalada else "No instalada"
            tabla.add_row(
                herramienta.nombre,
                herramienta.comando,
                estado,
                texto_seguro(herramienta.version) if herramienta.version else "-",
                texto_seguro(herramienta.ruta) if herramienta.ruta else "-",
            )
        self.query_one("#herr-mensaje", Static).update("")

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
