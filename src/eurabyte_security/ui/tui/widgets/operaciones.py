"""Mesa de trabajo compartida para documentar, corregir y verificar casos."""

from sqlite3 import Error as ErrorSQLite

from textual import on, work
from textual.containers import VerticalScroll
from textual.widgets import Button, Input, Select, Static
from textual.worker import get_current_worker

from eurabyte_security.commands.operaciones import contexto, exportar_caso
from eurabyte_security.core.errores import ErrorEST, ErrorValidacion
from eurabyte_security.modules.network.trafico import medir_equipo
from eurabyte_security.storage.operaciones import ACCIONES


class PanelOperaciones(VerticalScroll):
    _proyecto = None
    _worker = None

    def cambiar_proyecto(self, nombre):
        if nombre == self._proyecto:
            return
        self._proyecto = nombre
        if self._worker is not None:
            self._worker.cancel()
        for campo in self.query(Input):
            if campo.id != "ops-umbral":
                campo.value = ""
        for nombre_campo in ("lista", "detalle", "monitor", "mensaje"):
            self.query_one(f"#ops-{nombre_campo}", Static).update("")
        self.query_one("#ops-gravedad", Select).value = "media"
        self.query_one("#ops-accion", Select).value = "asignar"

    def compose(self):
        yield Static("Operaciones Red / Blue Team", classes="titulo-panel")
        yield Static("", id="ops-proyecto", markup=False)
        yield Input(placeholder="Activo (también filtra el historial)", id="ops-activo")
        yield Button("Consultar historial del activo", id="ops-listar")
        yield Static("", id="ops-lista", markup=False)
        yield Static("Red Team · Documentar hallazgo", classes="ast-subtitulo")
        yield Input(placeholder="Título del hallazgo", id="ops-titulo")
        yield Select([(n, n) for n in ("informativa", "baja", "media", "alta", "critica")],
                     value="media", allow_blank=False, id="ops-gravedad")
        yield Input(placeholder="Evidencia inicial e impacto", id="ops-evidencia")
        yield Button("Abrir caso", id="ops-crear")
        yield Static("Caso compartido", classes="ast-subtitulo")
        yield Input(placeholder="Número del caso", id="ops-caso")
        yield Input(placeholder="Resultado de origen, por ejemplo web:12", id="ops-origen")
        yield Button("Vincular resultado", id="ops-vincular")
        yield Static("Blue Team · Respuesta y validación", classes="ast-subtitulo")
        yield Select([(v, k) for k, v in ACCIONES.items()],
                     value="asignar", allow_blank=False, id="ops-accion")
        yield Input(placeholder="Responsable, evidencia o referencia de la alerta", id="ops-nota")
        yield Input(placeholder="Fecha ISO con zona horaria (por defecto ahora)", id="ops-fecha")
        yield Input(placeholder="Evento de ejercicio asociado", id="ops-ejercicio")
        yield Button("Guardar evento", id="ops-registrar")
        yield Button("Ver cronología", id="ops-ver")
        yield Button("Exportar informe JSON", id="ops-informe")
        yield Static("", id="ops-detalle", markup=False)
        yield Static("Blue Team · Monitoreo local", classes="ast-subtitulo")
        yield Input(value="100", placeholder="Umbral por sentido en Mbps", id="ops-umbral")
        yield Button("Iniciar monitoreo", id="ops-vigilar")
        yield Button("Detener monitoreo", id="ops-detener", disabled=True)
        yield Button("Ver mediciones", id="ops-mediciones")
        yield Static("", id="ops-monitor", markup=False)
        yield Static("", id="ops-mensaje", markup=False)

    def _valor(self, nombre):
        return self.query_one(f"#ops-{nombre}", Input).value.strip()

    def refrescar(self):
        try:
            db, p = contexto()
        except (ErrorEST, ErrorSQLite) as exc:
            self.cambiar_proyecto(None)
            self.query_one("#ops-proyecto", Static).update(str(exc))
            self.query_one("#ops-lista", Static).update("")
            self.query_one("#ops-detalle", Static).update("")
            return
        self.cambiar_proyecto(p.nombre)
        self.query_one("#ops-proyecto", Static).update(f"Proyecto activo: {p.nombre}")
        filas = db.listar(p.id, self._valor("activo") or None)
        self.query_one("#ops-lista", Static).update("\n".join(
            f"#{r['id']} · {r['activo']} · {r['titulo']} · {r['estado']} · "
            f"{r['responsable'] or 'Sin asignar'}" for r in filas
        ) or "Sin casos para este filtro.")

    @on(Button.Pressed)
    def _accion(self, evento):
        boton = evento.button.id
        msg = self.query_one("#ops-mensaje", Static)
        try:
            if boton == "ops-detener":
                self._worker.cancel()
                return
            db, p = contexto()
            if p.nombre != self._proyecto:
                self.refrescar()
                msg.update("Cambió el proyecto activo. Revisa el formulario.")
                return
            if boton == "ops-crear":
                caso = db.crear(p.id, self._valor("activo"), self._valor("titulo"),
                                self.query_one("#ops-gravedad", Select).value,
                                self._valor("evidencia"))
                self.query_one("#ops-caso", Input).value = str(caso)
                msg.update(f"Caso #{caso} abierto.")
            elif boton in ("ops-registrar", "ops-vincular", "ops-informe", "ops-ver"):
                caso = int(self._valor("caso"))
                if boton == "ops-registrar":
                    ejercicio = self._valor("ejercicio")
                    db.registrar(p.id, caso, self.query_one("#ops-accion", Select).value,
                                 self._valor("nota"), self._valor("fecha"),
                                 int(ejercicio) if ejercicio else None)
                    msg.update("Evento guardado.")
                if boton == "ops-vincular":
                    fuente, _, origen = self._valor("origen").partition(":")
                    db.vincular(p.id, caso, fuente, int(origen))
                    msg.update("Evidencia vinculada.")
                if boton == "ops-informe":
                    msg.update(f"Informe guardado en {exportar_caso(db, p.id, caso)}")
                caso_actual = db.detalle(p.id, caso)
                lineas = [f"#{caso} · {caso_actual['titulo']} · {caso_actual['estado']}"]
                for e in caso_actual["eventos"]:
                    fuente = f" · {e['fuente']}:{e['id_origen']}" if e["fuente"] else ""
                    demora = e.get("segundos_hasta_deteccion")
                    tiempo = f" · {demora:g} s tras el ejercicio" if demora is not None else ""
                    lineas.append(f"#{e['id']} {e['fecha']} · {e['tipo']}{fuente}{tiempo}"
                                  f"\n{e['detalle']}")
                self.query_one("#ops-detalle", Static).update("\n".join(lineas))
            elif boton == "ops-vigilar":
                umbral = float(self._valor("umbral"))
                if not 0 < umbral <= 1_000_000:
                    raise ErrorValidacion("Introduce un umbral positivo de hasta 1 000 000 Mbps.")
                self.query_one("#ops-vigilar", Button).disabled = True
                self.query_one("#ops-detener", Button).disabled = False
                self._worker = self._vigilar(db, p, umbral)
                msg.update(f"Monitoreando interfaces locales para {p.nombre}.")
            elif boton == "ops-mediciones":
                filas = db.muestras(p.id, 20)
                self.query_one("#ops-monitor", Static).update("\n".join(
                    f"{r['fecha']} · {r['interfaz']} · ↑{r['carga']} B ↓{r['descarga']} B"
                    f" · umbral {r['umbral']:g} Mbps · {'ALERTA' if r['alerta'] else 'normal'}"
                    for r in filas
                ) or "Todavía no hay mediciones.")
            self.refrescar()
        except (ErrorEST, OSError, ErrorSQLite) as exc:
            msg.update(str(exc))
        except ValueError:
            msg.update("Revisa los campos numéricos del formulario.")

    @work(thread=True, group="monitor-defensivo")
    def _vigilar(self, db, proyecto, umbral):
        worker = get_current_worker()
        try:
            while not worker.is_cancelled:
                medicion = medir_equipo(2)
                if worker.is_cancelled:
                    break
                db.guardar_muestra(proyecto.id, medicion, umbral)
        except (ErrorEST, OSError, ErrorSQLite) as exc:
            self.app.call_from_thread(self._error_monitor, proyecto.nombre, str(exc))
        finally:
            if self.is_mounted:
                self.app.call_from_thread(self._detenido)

    def _error_monitor(self, proyecto, mensaje):
        if proyecto == self._proyecto:
            self.query_one("#ops-mensaje", Static).update(mensaje)

    def _detenido(self):
        self._worker = None
        self.query_one("#ops-vigilar", Button).disabled = False
        self.query_one("#ops-detener", Button).disabled = True
