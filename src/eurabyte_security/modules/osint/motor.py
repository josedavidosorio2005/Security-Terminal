"""Motor OSINT: orquesta la validacion, la autorizacion y las fuentes para un objetivo.

``ejecutar_investigacion_osint`` es el equivalente, para OSINT, de
``commands/reconocimiento.py:ejecutar_reconocimiento_automatico``: sin dependencias de
Typer, Rich ni Textual, para que la CLI y la futura interfaz visual lo ejecuten igual en
un worker. Cada fuente se consulta de forma independiente -- una fuente ausente,
fallida o no configurada nunca detiene a las demas -- y sus hallazgos se persisten en
un unico lote atomico por fuente inmediatamente despues de que esa fuente termine
(``BaseDatos.agregar_hallazgos_osint``): si la investigacion se cancela, la fuente en
curso en ese momento no persiste nada (ni parcial), pero las fuentes ya completadas se
conservan, igual que hace el orquestador de reconocimiento con sus etapas.
"""

from __future__ import annotations

from collections.abc import Callable

from eurabyte_security.core.errores import (
    ErrorFuenteOSINTError,
    ErrorFuenteOSINTNoDisponible,
    ErrorInvestigacionOSINTCancelada,
    ErrorValidacion,
)
from eurabyte_security.core.osint.validacion import (
    TIPOS_OBJETIVO_OSINT,
    extraer_dominio_de_objetivo,
    validar_correo_osint,
    validar_dominio_osint,
    validar_telefono_osint,
    validar_usuario_osint,
    verificar_autorizacion_datos_personales,
)
from eurabyte_security.integrations.osint.registro import fuentes_para_tipo
from eurabyte_security.modules.osint.modelos import EtapaFuenteOSINT, ResultadoInvestigacionOSINT
from eurabyte_security.storage.database import BaseDatos, Proyecto
from eurabyte_security.ui.consola import texto_seguro

TIEMPO_LIMITE_POR_FUENTE_POR_DEFECTO = 15.0


def _sanear_objetivo(tipo_objetivo: str, objetivo_texto: str, region_telefono: str | None) -> str:
    if tipo_objetivo == "dominio":
        return validar_dominio_osint(objetivo_texto)
    if tipo_objetivo == "correo":
        return validar_correo_osint(objetivo_texto).correo
    if tipo_objetivo == "telefono":
        return validar_telefono_osint(objetivo_texto, region_telefono).e164
    if tipo_objetivo == "usuario":
        return validar_usuario_osint(objetivo_texto)
    raise ErrorValidacion(
        f"Tipo de objetivo OSINT '{tipo_objetivo}' no reconocido. Usa uno de: "
        f"{', '.join(TIPOS_OBJETIVO_OSINT)}."
    )


def _objetivo_para_fuente(tipo_objetivo: str, objetivo_saneado: str) -> str | None:
    """Lo que realmente se le pasa a ``AdaptadorFuenteOSINT.investigar()``.

    Las fuentes de dominio (DNS, RDAP, Certificate Transparency) necesitan el dominio,
    no el correo completo; ``None`` significa "esta fuente no tiene nada que consultar
    para este objetivo" (p. ej. un correo cuyo dominio no se pudo derivar).
    """
    if tipo_objetivo in ("dominio", "correo"):
        return extraer_dominio_de_objetivo(tipo_objetivo, objetivo_saneado)
    return objetivo_saneado


def ejecutar_investigacion_osint(
    base_datos: BaseDatos,
    proyecto: Proyecto,
    tipo_objetivo: str,
    objetivo_texto: str,
    *,
    autorizado_datos_personales: bool = False,
    region_telefono: str | None = None,
    fuentes_seleccionadas: frozenset[str] | None = None,
    tiempo_limite_por_fuente: float = TIEMPO_LIMITE_POR_FUENTE_POR_DEFECTO,
    callback_progreso: Callable[[EtapaFuenteOSINT], None] | None = None,
    debe_cancelar: Callable[[], bool] | None = None,
) -> ResultadoInvestigacionOSINT:
    if tipo_objetivo not in TIPOS_OBJETIVO_OSINT:
        raise ErrorValidacion(
            f"Tipo de objetivo OSINT '{tipo_objetivo}' no reconocido. Usa uno de: "
            f"{', '.join(TIPOS_OBJETIVO_OSINT)}."
        )
    verificar_autorizacion_datos_personales(tipo_objetivo, autorizado_datos_personales)
    objetivo_saneado = _sanear_objetivo(tipo_objetivo, objetivo_texto, region_telefono)

    fuentes_aplicables = fuentes_para_tipo(tipo_objetivo)
    if fuentes_seleccionadas is not None:
        invalidas = fuentes_seleccionadas - set(fuentes_aplicables)
        if invalidas:
            raise ErrorValidacion(
                f"Fuente(s) no aplicable(s) a '{tipo_objetivo}': {', '.join(sorted(invalidas))}."
            )
        fuentes_aplicables = {
            k: v for k, v in fuentes_aplicables.items() if k in fuentes_seleccionadas
        }

    investigacion = base_datos.crear_investigacion_osint(
        proyecto.id,
        tipo_objetivo,
        objetivo_texto,
        objetivo_saneado,
        autorizado_datos_personales,
        sorted(fuentes_aplicables),
    )

    etapas: dict[str, EtapaFuenteOSINT] = {
        id_fuente: EtapaFuenteOSINT(id_fuente, "pendiente", "") for id_fuente in fuentes_aplicables
    }
    limitaciones: list[str] = []
    total_hallazgos = 0

    def _emitir(id_fuente: str, estado: str, detalle: str) -> None:
        etapas[id_fuente] = EtapaFuenteOSINT(id_fuente, estado, detalle)
        base_datos.actualizar_investigacion_osint(
            investigacion.id,
            etapas=[e.como_dict() for e in etapas.values()],
            limitaciones=list(limitaciones),
        )
        if callback_progreso is not None:
            callback_progreso(etapas[id_fuente])

    def _limitar(mensaje: str) -> None:
        if mensaje not in limitaciones:
            limitaciones.append(mensaje)

    def _cancelado() -> bool:
        return debe_cancelar is not None and debe_cancelar()

    for id_fuente, adaptador in fuentes_aplicables.items():
        if _cancelado():
            _emitir(id_fuente, "cancelada", "")
            base_datos.actualizar_investigacion_osint(investigacion.id, estado_general="cancelada")
            raise ErrorInvestigacionOSINTCancelada(
                f"La investigacion OSINT de '{objetivo_texto}' se cancelo."
            )

        # Cada fuente declara si necesita el objetivo tal cual se valido (p. ej. Have
        # I Been Pwned, que consulta por cuenta de correo completa) o el dominio
        # derivado (DNS/RDAP/Certificate Transparency/VirusTotal): calcularlo UNA sola
        # vez fuera de este bucle enviaria el dominio a una fuente que necesita el
        # correo completo, o viceversa (ver integrations/osint/base.py).
        if adaptador.requiere_objetivo_original:
            objetivo_consulta: str | None = objetivo_saneado
        else:
            objetivo_consulta = _objetivo_para_fuente(tipo_objetivo, objetivo_saneado)

        if objetivo_consulta is None:
            _emitir(id_fuente, "omitida", "No hay un dominio que consultar para este objetivo.")
            continue

        if not adaptador.configurada():
            mensaje = adaptador.mensaje_no_configurada()
            _emitir(id_fuente, "omitida", mensaje)
            _limitar(mensaje)
            continue

        _emitir(id_fuente, "ejecutando", f"Consultando {adaptador.nombre}...")
        try:
            hallazgos = adaptador.investigar(
                objetivo_consulta,
                tipo_objetivo=tipo_objetivo,
                tiempo_limite=tiempo_limite_por_fuente,
                debe_cancelar=debe_cancelar,
            )
        except ErrorFuenteOSINTNoDisponible as exc:
            _emitir(id_fuente, "omitida", texto_seguro(str(exc)))
            _limitar(f"{adaptador.nombre}: {texto_seguro(exc)}")
            continue
        except ErrorFuenteOSINTError as exc:
            _emitir(id_fuente, "fallida", texto_seguro(str(exc)))
            _limitar(f"{adaptador.nombre}: {texto_seguro(exc)}")
            continue

        if _cancelado():
            _emitir(id_fuente, "cancelada", "")
            base_datos.actualizar_investigacion_osint(investigacion.id, estado_general="cancelada")
            raise ErrorInvestigacionOSINTCancelada(
                f"La investigacion OSINT de '{objetivo_texto}' se cancelo."
            )

        if hallazgos:
            base_datos.agregar_hallazgos_osint(
                investigacion.id, proyecto.id, id_fuente, [h.como_dict() for h in hallazgos]
            )
        total_hallazgos += len(hallazgos)
        _emitir(id_fuente, "completada", f"{len(hallazgos)} hallazgo(s).")

    base_datos.actualizar_investigacion_osint(investigacion.id, estado_general="completada")
    investigacion_final = base_datos.obtener_investigacion_osint(investigacion.id)

    return ResultadoInvestigacionOSINT(
        investigacion_id=investigacion.id,
        tipo_objetivo=tipo_objetivo,
        objetivo_original=objetivo_texto,
        objetivo_saneado=objetivo_saneado,
        estado_general=investigacion_final.estado_general,
        etapas=tuple(etapas.values()),
        limitaciones=tuple(limitaciones),
        total_hallazgos=total_hallazgos,
    )
