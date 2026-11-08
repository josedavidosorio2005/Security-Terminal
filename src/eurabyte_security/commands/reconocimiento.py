"""Orquestador de reconocimiento automatico: motor compartido por CLI y Textual.

``ejecutar_reconocimiento_automatico`` es la funcion central: recibe un unico
objetivo (IP, dominio o URL), lo interpreta y resuelve una sola vez
(``core/objetivo.py``), y encadena las integraciones ya existentes (Nmap, auditoria
web, Nuclei, OWASP ZAP) reutilizando sus propias funciones de ``commands/*.py`` --
nunca duplica su logica de persistencia, evidencia ni verificacion de alcance. No
depende de Typer, Rich ni de ningun widget de Textual: la interfaz visual podra
importarla y ejecutarla en un worker exactamente igual que ya hace con
``ejecutar_nmap``/``auditar_web``/``ejecutar_nuclei``/``ejecutar_zap_pasivo``.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass

import typer
from rich.table import Table

from eurabyte_security.commands._comun import obtener_base_datos, resolver_proyecto
from eurabyte_security.commands.nmap import ejecutar_nmap
from eurabyte_security.commands.nuclei import ejecutar_nuclei
from eurabyte_security.commands.reporte import generar_reporte
from eurabyte_security.commands.web import auditar_web
from eurabyte_security.commands.zap import ejecutar_zap_pasivo
from eurabyte_security.core.errores import (
    ErrorAuditoriaWeb,
    ErrorEscaneoCancelado,
    ErrorEST,
    ErrorFueraDeAlcance,
    ErrorHerramientaNoDisponible,
    ErrorIntegracion,
    ErrorResolucionDNS,
    ErrorValidacion,
    ErrorZAPNoDisponible,
)
from eurabyte_security.core.objetivo import interpretar_entrada, resolver_y_autorizar
from eurabyte_security.integrations.nmap import AdaptadorNmap
from eurabyte_security.integrations.nuclei import PLANTILLAS_APROBADAS, AdaptadorNuclei
from eurabyte_security.integrations.zap import AdaptadorZAP
from eurabyte_security.storage.database import BaseDatos, Proyecto
from eurabyte_security.ui.consola import consola, texto_seguro

reconocimiento_app = typer.Typer(
    help="Orquesta un reconocimiento automatico: puertos, servicios, web, Nuclei y ZAP.",
    no_args_is_help=True,
)

NOMBRES_ETAPAS: tuple[str, ...] = ("verificacion", "puertos", "web", "nuclei", "zap", "informe")
ESTADOS_ETAPA_VALIDOS = frozenset(
    {"pendiente", "ejecutando", "completada", "omitida", "fallida", "cancelada"}
)
PERFILES_VALIDOS = frozenset({"rapido", "completo", "personalizado"})

# Puertos bien conocidos usados SOLO como ultimo recurso, cuando Nmap no identifico un
# nombre de servicio reconocible: la fuente principal es siempre el nombre de servicio
# que Nmap ya reporta (p. ej. 'http'/'https'/'ssl'), nunca el numero de puerto a solas.
_PUERTOS_HTTP_CONOCIDOS = frozenset({80, 8080, 8000, 8008, 8880})
_PUERTOS_HTTPS_CONOCIDOS = frozenset({443, 8443, 9443})

_ERRORES_NO_FATALES_ETAPA = (
    ErrorHerramientaNoDisponible,
    ErrorIntegracion,
    ErrorFueraDeAlcance,
    ErrorValidacion,
    ErrorAuditoriaWeb,
    ErrorZAPNoDisponible,
)


@dataclass(frozen=True, slots=True)
class EtapaReconocimiento:
    """Estado de una sola etapa del reconocimiento. Nunca lleva un porcentaje de
    avance inventado: solo uno de los estados reales de ``ESTADOS_ETAPA_VALIDOS``."""

    nombre: str
    estado: str
    detalle: str

    def como_dict(self) -> dict[str, str]:
        return {"nombre": self.nombre, "estado": self.estado, "detalle": self.detalle}


@dataclass(frozen=True, slots=True)
class ResultadoReconocimiento:
    """Resultado final de una sesion de reconocimiento automatico completa."""

    sesion_id: int
    objetivo_original: str
    nombre_host: str | None
    ip: str | None
    perfil: str
    estado_general: str
    etapas: tuple[EtapaReconocimiento, ...]
    limitaciones: tuple[str, ...]
    ruta_informe_html: str | None
    ruta_informe_json: str | None


class _Ejecucion:
    """Estado mutable de una sesion en curso: aplica cada cambio de etapa a la base de
    datos de inmediato (para que una consulta concurrente del estado vea progreso
    real) y, si se indico, notifica a ``callback_progreso`` -- pensado para que la
    interfaz visual actualice su barra de estado sin inventar un porcentaje."""

    def __init__(
        self,
        base_datos: BaseDatos,
        sesion_id: int,
        callback_progreso: Callable[[EtapaReconocimiento], None] | None,
    ) -> None:
        self.base_datos = base_datos
        self.sesion_id = sesion_id
        self.callback_progreso = callback_progreso
        self.etapas: dict[str, EtapaReconocimiento] = {
            nombre: EtapaReconocimiento(nombre, "pendiente", "") for nombre in NOMBRES_ETAPAS
        }
        self.limitaciones: list[str] = []

    def emitir(self, nombre: str, estado: str, detalle: str) -> None:
        self.etapas[nombre] = EtapaReconocimiento(nombre, estado, detalle)
        self.base_datos.actualizar_sesion_reconocimiento(
            self.sesion_id,
            etapas=[e.como_dict() for e in self.etapas.values()],
            limitaciones=list(self.limitaciones),
        )
        if self.callback_progreso is not None:
            self.callback_progreso(self.etapas[nombre])

    def limitar(self, mensaje: str) -> None:
        if mensaje not in self.limitaciones:
            self.limitaciones.append(mensaje)

    def finalizar(self, estado_general: str) -> None:
        self.base_datos.actualizar_sesion_reconocimiento(
            self.sesion_id,
            estado_general=estado_general,
            etapas=[e.como_dict() for e in self.etapas.values()],
            limitaciones=list(self.limitaciones),
        )


def _inferir_esquema(puerto) -> str | None:  # noqa: ANN001 - integrations.nmap.PuertoNmap
    servicio = (puerto.servicio or "").lower()
    if "https" in servicio or "ssl" in servicio:
        return "https"
    if "http" in servicio:
        return "http"
    if puerto.puerto in _PUERTOS_HTTPS_CONOCIDOS:
        return "https"
    if puerto.puerto in _PUERTOS_HTTP_CONOCIDOS:
        return "http"
    return None


def ejecutar_reconocimiento_automatico(
    base_datos: BaseDatos,
    proyecto: Proyecto,
    entrada_texto: str,
    *,
    perfil: str = "rapido",
    especificacion_puertos_personalizada: str | None = None,
    tiempo_limite_nmap: float = 120.0,
    tiempo_limite_web: float = 10.0,
    tiempo_limite_nuclei: float = 60.0,
    tiempo_limite_zap: float = 60.0,
    callback_progreso: Callable[[EtapaReconocimiento], None] | None = None,
    debe_cancelar: Callable[[], bool] | None = None,
) -> ResultadoReconocimiento:
    """Ejecuta el flujo completo de reconocimiento automatico para un unico objetivo.

    El usuario escribe el objetivo UNA sola vez: esta funcion lo interpreta y lo
    resuelve (``core/objetivo.py``) y encadena Nmap, deteccion de servicios
    HTTP/HTTPS, auditoria web, Nuclei y OWASP ZAP sin que el llamador tenga que
    repetirlo en cada paso. Cada etapa reutiliza la funcion de ``commands/*.py`` que
    ya existe para esa herramienta (persistencia, evidencia y verificacion de alcance
    incluidas): esta funcion nunca llama a un adaptador externo directamente salvo
    para comprobar si esta instalado/disponible antes de decidir si omitir su etapa.

    **Nunca se vuelve a resolver el dominio**: a partir de la etapa de verificacion,
    todas las llamadas posteriores reciben la IP ya fijada (``resuelto.ip``), nunca el
    nombre de dominio original. Si el objetivo es un dominio, las etapas de auditoria
    web/Nuclei/ZAP se OMITEN explicitamente (ver la etapa "verificacion" y las
    limitaciones del resultado): ninguna herramienta HTTP de AST sabe hoy conservar el
    ``Host``/SNI de un dominio mientras se conecta a una IP fijada por separado, y
    auditar por numero de IP un host virtual podria mostrar contenido distinto al que
    el usuario pidio -- se prefiere omitir y documentarlo a mostrar un resultado que
    podria no corresponder al dominio real.

    ``debe_cancelar`` se comprueba entre etapas y, cuando una herramienta lo admite
    (Nmap, auditoria web, Nuclei, ZAP), tambien durante la ejecucion de esa etapa: una
    cancelacion nunca deja una etapa a medio persistir (cada funcion de
    ``commands/*.py`` ya garantiza su propia atomicidad), pero las etapas YA
    completadas antes de cancelar se conservan tal cual.
    """
    if perfil not in PERFILES_VALIDOS:
        raise ErrorValidacion(
            f"Perfil '{perfil}' no reconocido. Usa uno de: {', '.join(sorted(PERFILES_VALIDOS))}."
        )
    if perfil == "personalizado" and not especificacion_puertos_personalizada:
        raise ErrorValidacion(
            "El perfil 'personalizado' requiere una especificacion de puertos explicita."
        )

    sesion = base_datos.crear_sesion_reconocimiento(proyecto.id, entrada_texto, perfil)
    ejecucion = _Ejecucion(base_datos, sesion.id, callback_progreso)

    def _cancelado_ahora() -> bool:
        return debe_cancelar is not None and debe_cancelar()

    def _cancelar_y_salir(etapa_actual: str) -> None:
        ejecucion.emitir(etapa_actual, "cancelada", "")
        ejecucion.finalizar("cancelada")

    # -- Etapas 1-3: interpretar, resolver DNS y autorizar -----------------------
    ejecucion.emitir("verificacion", "ejecutando", "Interpretando y resolviendo el objetivo...")
    try:
        entrada = interpretar_entrada(entrada_texto)
        redes_autorizadas = [
            ipaddress.IPv4Network(a.red) for a in base_datos.listar_alcance(proyecto.id)
        ]
        resuelto = resolver_y_autorizar(entrada, redes_autorizadas)
    except (ErrorValidacion, ErrorFueraDeAlcance, ErrorResolucionDNS) as exc:
        ejecucion.emitir("verificacion", "fallida", texto_seguro(str(exc)))
        ejecucion.finalizar("fallida")
        raise

    detalle_verificacion = f"Objetivo autorizado: {resuelto.ip}"
    if resuelto.nombre_host:
        otras = ", ".join(str(ip) for ip in resuelto.ips_resueltas)
        detalle_verificacion += f" (dominio '{resuelto.nombre_host}', IPs resueltas: {otras})"
    ejecucion.emitir("verificacion", "completada", detalle_verificacion)
    base_datos.actualizar_sesion_reconocimiento(
        sesion.id, nombre_host=resuelto.nombre_host, ip=str(resuelto.ip)
    )

    objetivo_es_dominio = resuelto.nombre_host is not None
    if objetivo_es_dominio:
        ejecucion.limitar(
            "El objetivo es un dominio: AST no puede fijar la IP conservando el Host/SNI "
            "original con las herramientas HTTP actuales. Se descubren puertos sobre la IP "
            "autorizada, pero las etapas de auditoria web, Nuclei y OWASP ZAP se omiten para "
            "no mostrar resultados de un host virtual que podria no corresponder al dominio "
            "pedido."
        )

    if _cancelado_ahora():
        _cancelar_y_salir("puertos")
        raise ErrorEscaneoCancelado(f"El reconocimiento de '{entrada_texto}' se cancelo.")

    # -- Etapas 4-5: Nmap (puertos + nombres de servicio) ------------------------
    puertos_detectados: list = []
    if not AdaptadorNmap().info().instalada:
        ejecucion.emitir("puertos", "omitida", "Nmap no esta instalado.")
        ejecucion.limitar("Nmap no esta instalado: no se descubrieron puertos ni servicios.")
    else:
        especificacion = (
            especificacion_puertos_personalizada if perfil == "personalizado" else perfil
        )
        ejecucion.emitir("puertos", "ejecutando", f"Ejecutando Nmap (perfil '{perfil}')...")
        try:
            resultado_nmap, _guardados, _ruta_xml = ejecutar_nmap(
                base_datos,
                proyecto,
                str(resuelto.ip),
                especificacion,  # type: ignore[arg-type]
                tiempo_limite=tiempo_limite_nmap,
                debe_cancelar=debe_cancelar,
            )
            puertos_detectados = resultado_nmap.puertos
            abiertos = [p for p in puertos_detectados if p.estado == "open"]
            ejecucion.emitir(
                "puertos",
                "completada",
                f"{len(abiertos)} puerto(s) abierto(s) de {len(puertos_detectados)} "
                "comprobado(s).",
            )
        except ErrorEscaneoCancelado:
            _cancelar_y_salir("puertos")
            raise
        except _ERRORES_NO_FATALES_ETAPA as exc:
            if _cancelado_ahora():
                _cancelar_y_salir("puertos")
                raise ErrorEscaneoCancelado(
                    f"El reconocimiento de '{entrada_texto}' se cancelo."
                ) from exc
            ejecucion.emitir("puertos", "fallida", texto_seguro(str(exc)))
            ejecucion.limitar(f"Nmap fallo: {texto_seguro(str(exc))}")

    # -- Etapas 6-7: deteccion HTTP/HTTPS + auditoria web automatica -------------
    candidatos_web: list[tuple[str, int]] = []
    if not objetivo_es_dominio:
        if entrada.tiene_esquema and entrada.esquema and entrada.puerto:
            candidatos_web.append((entrada.esquema, entrada.puerto))
        for puerto in puertos_detectados:
            if puerto.estado != "open":
                continue
            esquema = _inferir_esquema(puerto)
            if esquema and (esquema, puerto.puerto) not in candidatos_web:
                candidatos_web.append((esquema, puerto.puerto))

    endpoints_verificados: list[tuple[str, int]] = []
    if objetivo_es_dominio:
        ejecucion.emitir("web", "omitida", "El objetivo es un dominio (ver limitaciones).")
    elif not candidatos_web:
        ejecucion.emitir("web", "omitida", "No se detectaron puertos HTTP/HTTPS abiertos.")
    else:
        if _cancelado_ahora():
            _cancelar_y_salir("web")
            raise ErrorEscaneoCancelado(f"El reconocimiento de '{entrada_texto}' se cancelo.")
        ejecucion.emitir(
            "web", "ejecutando", f"Auditando {len(candidatos_web)} endpoint(s) candidato(s)..."
        )
        for esquema, puerto in candidatos_web:
            if _cancelado_ahora():
                break
            url = f"{esquema}://{resuelto.ip}:{puerto}/"
            try:
                auditar_web(
                    base_datos,
                    proyecto,
                    url,
                    "auditar",
                    tiempo_limite=tiempo_limite_web,
                    debe_cancelar=debe_cancelar,
                )
                endpoints_verificados.append((esquema, puerto))
            except ErrorEscaneoCancelado:
                break
            except _ERRORES_NO_FATALES_ETAPA as exc:
                if _cancelado_ahora():
                    break
                ejecucion.limitar(
                    f"{esquema}://{resuelto.ip}:{puerto}/ no respondio como servicio web: "
                    f"{texto_seguro(str(exc))}"
                )
        if _cancelado_ahora():
            _cancelar_y_salir("web")
            raise ErrorEscaneoCancelado(f"El reconocimiento de '{entrada_texto}' se cancelo.")
        if endpoints_verificados:
            ejecucion.emitir(
                "web",
                "completada",
                f"{len(endpoints_verificados)} de {len(candidatos_web)} endpoint(s) "
                "auditado(s) con exito.",
            )
        else:
            ejecucion.emitir(
                "web", "fallida", "Ningun endpoint candidato respondio como servicio web valido."
            )

    # -- Etapa 8: Nuclei (solo plantillas aprobadas) -----------------------------
    _ejecutar_etapa_vulnerabilidad(
        ejecucion,
        "nuclei",
        objetivo_es_dominio=objetivo_es_dominio,
        endpoints=endpoints_verificados,
        herramienta_disponible=AdaptadorNuclei().info().instalada,
        mensaje_no_disponible="Nuclei no esta instalado.",
        entrada_texto=entrada_texto,
        debe_cancelar=debe_cancelar,
        ejecutor=lambda objetivo: ejecutar_nuclei(
            base_datos,
            proyecto,
            objetivo,
            list(PLANTILLAS_APROBADAS.keys()),
            tiempo_limite=tiempo_limite_nuclei,
            debe_cancelar=debe_cancelar,
        )[1],
        construir_objetivo=lambda esquema, ip, puerto: f"{esquema}://{ip}:{puerto}",
        ip=resuelto.ip,
    )

    # -- Etapa 9: OWASP ZAP (solo pasivo) -----------------------------------------
    _ejecutar_etapa_vulnerabilidad(
        ejecucion,
        "zap",
        objetivo_es_dominio=objetivo_es_dominio,
        endpoints=endpoints_verificados,
        herramienta_disponible=AdaptadorZAP().info().disponible,
        mensaje_no_disponible="OWASP ZAP no esta disponible.",
        entrada_texto=entrada_texto,
        debe_cancelar=debe_cancelar,
        ejecutor=lambda objetivo: ejecutar_zap_pasivo(
            base_datos, proyecto, objetivo, tiempo_limite=tiempo_limite_zap,
            debe_cancelar=debe_cancelar,
        )[1],
        construir_objetivo=lambda esquema, ip, puerto: f"{esquema}://{ip}:{puerto}/",
        ip=resuelto.ip,
    )

    # -- Etapas 10-11: consolidar e informe global --------------------------------
    ejecucion.emitir("informe", "ejecutando", "Generando el informe global...")
    try:
        ruta_html = generar_reporte(base_datos, proyecto, "html")
        ruta_json = generar_reporte(base_datos, proyecto, "json")
        ejecucion.emitir("informe", "completada", f"Informe generado en {ruta_html}.")
        base_datos.actualizar_sesion_reconocimiento(
            sesion.id, ruta_informe_html=str(ruta_html), ruta_informe_json=str(ruta_json)
        )
    except ErrorEST as exc:
        ejecucion.emitir("informe", "fallida", texto_seguro(str(exc)))

    estado_final = (
        "completada" if ejecucion.etapas["informe"].estado == "completada" else "fallida"
    )
    ejecucion.finalizar(estado_final)

    sesion_final = base_datos.obtener_sesion_reconocimiento(sesion.id)
    return ResultadoReconocimiento(
        sesion_id=sesion.id,
        objetivo_original=entrada_texto,
        nombre_host=resuelto.nombre_host,
        ip=str(resuelto.ip),
        perfil=perfil,
        estado_general=sesion_final.estado_general,
        etapas=tuple(ejecucion.etapas[n] for n in NOMBRES_ETAPAS),
        limitaciones=tuple(ejecucion.limitaciones),
        ruta_informe_html=sesion_final.ruta_informe_html,
        ruta_informe_json=sesion_final.ruta_informe_json,
    )


def _ejecutar_etapa_vulnerabilidad(
    ejecucion: _Ejecucion,
    nombre_etapa: str,
    *,
    objetivo_es_dominio: bool,
    endpoints: list[tuple[str, int]],
    herramienta_disponible: bool,
    mensaje_no_disponible: str,
    entrada_texto: str,
    debe_cancelar: Callable[[], bool] | None,
    ejecutor: Callable[[str], list],
    construir_objetivo: Callable[[str, object, int], str],
    ip: object,
) -> None:
    """Cuerpo compartido de las etapas Nuclei/ZAP: mismo patron (omitir si falta la
    herramienta o no hay endpoints verificados; si no, ejecutar contra cada endpoint
    que SI respondio en la etapa web, acumulando hallazgos y limitaciones)."""

    def _cancelado_ahora() -> bool:
        return debe_cancelar is not None and debe_cancelar()

    if objetivo_es_dominio:
        ejecucion.emitir(nombre_etapa, "omitida", "El objetivo es un dominio (ver limitaciones).")
        return
    if not endpoints:
        ejecucion.emitir(
            nombre_etapa, "omitida", "No hay endpoints web verificados para analizar."
        )
        return
    if not herramienta_disponible:
        ejecucion.emitir(nombre_etapa, "omitida", mensaje_no_disponible)
        ejecucion.limitar(f"{mensaje_no_disponible} No se ejecuto la etapa '{nombre_etapa}'.")
        return

    ejecucion.emitir(nombre_etapa, "ejecutando", f"Ejecutando '{nombre_etapa}'...")
    total_hallazgos = 0
    fallo_alguno = False
    for esquema, puerto in endpoints:
        if _cancelado_ahora():
            break
        objetivo = construir_objetivo(esquema, ip, puerto)
        try:
            guardados = ejecutor(objetivo)
            total_hallazgos += len(guardados)
        except ErrorEscaneoCancelado:
            break
        except _ERRORES_NO_FATALES_ETAPA as exc:
            if _cancelado_ahora():
                break
            fallo_alguno = True
            ejecucion.limitar(f"{nombre_etapa} fallo en {objetivo}: {texto_seguro(str(exc))}")

    if _cancelado_ahora():
        ejecucion.emitir(nombre_etapa, "cancelada", "")
        ejecucion.finalizar("cancelada")
        raise ErrorEscaneoCancelado(f"El reconocimiento de '{entrada_texto}' se cancelo.")

    if total_hallazgos or not fallo_alguno:
        ejecucion.emitir(
            nombre_etapa, "completada", f"{total_hallazgos} hallazgo(s) guardado(s)."
        )
    else:
        ejecucion.emitir(nombre_etapa, "fallida", f"'{nombre_etapa}' fallo en todos los endpoints.")


_ESTILOS_ESTADO_ETAPA = {
    "completada": "bold green",
    "ejecutando": "bold yellow",
    "pendiente": "grey70",
    "omitida": "grey70",
    "fallida": "bold red",
    "cancelada": "bold red",
}


def _tabla_etapas(resultado: ResultadoReconocimiento, titulo: str) -> Table:
    tabla = Table(title=titulo)
    tabla.add_column("Etapa")
    tabla.add_column("Estado")
    tabla.add_column("Detalle")
    for etapa in resultado.etapas:
        estilo = _ESTILOS_ESTADO_ETAPA.get(etapa.estado, "")
        estado_texto = f"[{estilo}]{etapa.estado}[/{estilo}]" if estilo else etapa.estado
        tabla.add_row(etapa.nombre, estado_texto, texto_seguro(etapa.detalle))
    return tabla


@reconocimiento_app.command("ejecutar")
def ejecutar_cmd(
    objetivo: str = typer.Argument(
        ..., help="Objetivo unico: IPv4, dominio o URL completa (http/https)."
    ),
    perfil: str = typer.Option(
        "rapido", "--perfil", help="Perfil de puertos para Nmap: rapido, completo o personalizado."
    ),
    puertos: str | None = typer.Option(
        None, "--puertos", help="Especificacion de puertos para el perfil 'personalizado'."
    ),
    proyecto: str | None = typer.Option(
        None, "--proyecto", help="Proyecto a usar (por defecto, el activo)."
    ),
    tiempo_limite_nmap: float = typer.Option(
        120.0, "--tiempo-limite-nmap", help="Segundos maximos de espera para Nmap."
    ),
) -> None:
    """Ejecuta el reconocimiento automatico completo contra un unico objetivo."""
    base_datos = obtener_base_datos()
    proyecto_obj = resolver_proyecto(base_datos, proyecto)

    def _mostrar_progreso(etapa: EtapaReconocimiento) -> None:
        estilo = _ESTILOS_ESTADO_ETAPA.get(etapa.estado, "")
        estado_texto = f"[{estilo}]{etapa.estado}[/{estilo}]" if estilo else etapa.estado
        consola.print(
            f"[bold]{etapa.nombre}[/bold]: {estado_texto} - {texto_seguro(etapa.detalle)}"
        )

    resultado = ejecutar_reconocimiento_automatico(
        base_datos,
        proyecto_obj,
        objetivo,
        perfil=perfil,
        especificacion_puertos_personalizada=puertos,
        tiempo_limite_nmap=tiempo_limite_nmap,
        callback_progreso=_mostrar_progreso,
    )
    consola.print(
        _tabla_etapas(resultado, f"Reconocimiento #{resultado.sesion_id} - {objetivo}")
    )
    if resultado.limitaciones:
        consola.print("\n[bold yellow]Limitaciones:[/bold yellow]")
        for limitacion in resultado.limitaciones:
            consola.print(f"- {texto_seguro(limitacion)}")
    if resultado.ruta_informe_html:
        consola.print(f"\nInforme global: {texto_seguro(resultado.ruta_informe_html)}")


@reconocimiento_app.command("sesiones")
def sesiones_cmd(
    proyecto: str | None = typer.Option(
        None, "--proyecto", help="Proyecto a consultar (por defecto, el activo)."
    ),
    limite: int = typer.Option(20, "--limite", help="Numero maximo de sesiones a mostrar."),
) -> None:
    """Lista las sesiones de reconocimiento automatico guardadas de un proyecto."""
    base_datos = obtener_base_datos()
    proyecto_obj = resolver_proyecto(base_datos, proyecto)
    sesiones = base_datos.listar_sesiones_reconocimiento(proyecto_obj.id, limite=limite)

    if not sesiones:
        consola.print(f"El proyecto '{proyecto_obj.nombre}' no tiene sesiones guardadas.")
        return

    tabla = Table(title=f"Sesiones de reconocimiento - {proyecto_obj.nombre}")
    tabla.add_column("Id")
    tabla.add_column("Objetivo")
    tabla.add_column("Perfil")
    tabla.add_column("Estado")
    tabla.add_column("Fecha")
    for sesion in sesiones:
        estilo = _ESTILOS_ESTADO_ETAPA.get(sesion.estado_general, "")
        estado_texto = (
            f"[{estilo}]{sesion.estado_general}[/{estilo}]" if estilo else sesion.estado_general
        )
        tabla.add_row(
            str(sesion.id),
            texto_seguro(sesion.objetivo_original),
            texto_seguro(sesion.perfil),
            estado_texto,
            sesion.creado_en,
        )
    consola.print(tabla)


@reconocimiento_app.command("estado")
def estado_cmd(
    sesion_id: int = typer.Argument(
        ..., help="Id de la sesion (ver 'est reconocimiento sesiones')."
    ),
) -> None:
    """Muestra el detalle de etapas y limitaciones de una sesion guardada."""
    import json

    base_datos = obtener_base_datos()
    sesion = base_datos.obtener_sesion_reconocimiento(sesion_id)
    etapas_datos = json.loads(sesion.etapas_json)
    limitaciones = json.loads(sesion.limitaciones_json)

    resultado = ResultadoReconocimiento(
        sesion_id=sesion.id,
        objetivo_original=sesion.objetivo_original,
        nombre_host=sesion.nombre_host,
        ip=sesion.ip,
        perfil=sesion.perfil,
        estado_general=sesion.estado_general,
        etapas=tuple(EtapaReconocimiento(**e) for e in etapas_datos),
        limitaciones=tuple(limitaciones),
        ruta_informe_html=sesion.ruta_informe_html,
        ruta_informe_json=sesion.ruta_informe_json,
    )
    consola.print(
        _tabla_etapas(resultado, f"Reconocimiento #{sesion.id} - {sesion.objetivo_original}")
    )
    if resultado.limitaciones:
        consola.print("\n[bold yellow]Limitaciones:[/bold yellow]")
        for limitacion in resultado.limitaciones:
            consola.print(f"- {texto_seguro(limitacion)}")
    if resultado.ruta_informe_html:
        consola.print(f"\nInforme global: {texto_seguro(resultado.ruta_informe_html)}")
