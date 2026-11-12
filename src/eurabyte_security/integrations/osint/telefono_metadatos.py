"""Fuente OSINT: metadatos de numeracion telefonica (biblioteca ``phonenumbers``).

A diferencia de toda otra fuente de ``integrations/osint/``, esta NUNCA hace una
peticion de red: toda la informacion viene de los catalogos de planes de numeracion que
``phonenumbers`` (el mismo motor que usa libphonenumber de Google) distribuye
embebidos en el propio paquete Python -- por eso se ofrece siempre disponible, sin
clave ni configuracion, igual que la validacion de ``core/osint/validacion.py`` que ya
usa la misma biblioteca.

**Lo que esto NO es**: no identifica al titular de la linea, no confirma que el numero
este actualmente activo, y "operador sugerido" es una ESTIMACION basada en el rango
asignado historicamente al bloque numerico (nunca el operador real y vigente, que solo
una consulta a un proveedor como Twilio Lookup -- ``integrations/osint/
twilio_lookup.py`` -- podria aproximar, y tampoco con certeza total). Cada metadato que
pueda confundirse con un dato confirmado sobre el titular se marca explicitamente como
estimacion/no verificado (ver seccion 4 de la especificacion de metadatos telefonicos).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

import phonenumbers
from phonenumbers import PhoneMetadata, PhoneNumberFormat, carrier, geocoder, timezone

from eurabyte_security.core.errores import ErrorFuenteOSINTError
from eurabyte_security.integrations.osint.base import AdaptadorFuenteOSINT
from eurabyte_security.modules.osint.modelos import EvidenciaOSINT, HallazgoOSINT

URL_DOCUMENTACION_PHONENUMBERS = "https://github.com/google/libphonenumber"

# Mismas etiquetas en espanol que ``core/osint/validacion.py`` usa para el tipo de
# numero (duplicado deliberado: ``integrations/`` no debe depender de un nombre privado
# de ``core/``, y es una tabla pequena y estable).
_ETIQUETAS_TIPO_TELEFONO: dict[int, str] = {
    phonenumbers.PhoneNumberType.MOBILE: "movil",
    phonenumbers.PhoneNumberType.FIXED_LINE: "fijo",
    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fijo_o_movil",
    phonenumbers.PhoneNumberType.TOLL_FREE: "gratuito",
    phonenumbers.PhoneNumberType.PREMIUM_RATE: "tarifa_premium",
    phonenumbers.PhoneNumberType.SHARED_COST: "costo_compartido",
    phonenumbers.PhoneNumberType.VOIP: "voip",
    phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "numero_personal",
    phonenumbers.PhoneNumberType.PAGER: "radiomensaje",
    phonenumbers.PhoneNumberType.UAN: "uan",
    phonenumbers.PhoneNumberType.VOICEMAIL: "buzon_de_voz",
    phonenumbers.PhoneNumberType.UNKNOWN: "desconocido",
}


def _ahora() -> str:
    return datetime.now(UTC).isoformat()


def _evidencia(valor: str) -> EvidenciaOSINT:
    return EvidenciaOSINT(
        fuente="telefono_metadatos",
        fecha_consulta=_ahora(),
        referencia=URL_DOCUMENTACION_PHONENUMBERS,
        valor=valor,
    )


class AdaptadorMetadatosTelefono(AdaptadorFuenteOSINT):
    id_fuente = "telefono_metadatos"
    nombre = "Metadatos de numeracion (phonenumbers)"
    tipos_objetivo = frozenset({"telefono"})
    url_documentacion = URL_DOCUMENTACION_PHONENUMBERS

    def investigar(
        self,
        objetivo: str,
        *,
        tipo_objetivo: str,
        tiempo_limite: float,
        debe_cancelar: Callable[[], bool] | None,
    ) -> list[HallazgoOSINT]:
        try:
            numero = phonenumbers.parse(objetivo, None)
        except phonenumbers.NumberParseException as exc:
            raise ErrorFuenteOSINTError(
                f"'{objetivo}' no se pudo interpretar como numero E.164: {exc}"
            ) from exc

        valido = phonenumbers.is_valid_number(numero)
        posible = phonenumbers.is_possible_number(numero)
        region = phonenumbers.region_code_for_number(numero)
        tipo_numero = phonenumbers.number_type(numero)
        tipo_texto = _ETIQUETAS_TIPO_TELEFONO.get(tipo_numero, "desconocido")

        evidencias = [
            _evidencia(f"E.164: {phonenumbers.format_number(numero, PhoneNumberFormat.E164)}"),
            _evidencia(
                "Formato nacional: "
                f"{phonenumbers.format_number(numero, PhoneNumberFormat.NATIONAL)}"
            ),
            _evidencia(
                "Formato internacional: "
                f"{phonenumbers.format_number(numero, PhoneNumberFormat.INTERNATIONAL)}"
            ),
            _evidencia(f"Codigo de pais: +{numero.country_code}"),
            _evidencia(f"Numero posible segun el plan de numeracion: {'si' if posible else 'no'}"),
            _evidencia(f"Numero valido segun el plan de numeracion: {'si' if valido else 'no'}"),
            _evidencia(f"Tipo de linea: {tipo_texto}"),
        ]

        if region:
            evidencias.append(_evidencia(f"Pais o region (ISO): {region}"))
            metadatos_region = PhoneMetadata.metadata_for_region(region)
            if metadatos_region is not None and metadatos_region.national_prefix:
                evidencias.append(
                    _evidencia(f"Prefijo nacional de marcado: {metadatos_region.national_prefix}")
                )

        descripcion_geografica = geocoder.description_for_number(numero, "es")
        if descripcion_geografica:
            evidencias.append(
                _evidencia(f"Descripcion geografica aproximada: {descripcion_geografica}")
            )

        zonas_horarias = timezone.time_zones_for_number(numero)
        if zonas_horarias:
            zonas_texto = ", ".join(zonas_horarias)
            evidencias.append(
                _evidencia(f"Zona(s) horaria(s) del plan de numeracion: {zonas_texto}")
            )

        hallazgos = [
            HallazgoOSINT(
                categoria="telefono",
                titulo="Metadatos de numeracion telefonica",
                descripcion=(
                    "Datos derivados unicamente del plan de numeracion publico "
                    "(libphonenumber), nunca del titular real de la linea ni de su "
                    "estado de actividad actual."
                ),
                nivel_confianza="confirmado",
                indicador_exposicion=None,
                evidencias=tuple(evidencias),
            )
        ]

        # El operador sugerido por el bloque numerico es, por diseno de la propia
        # biblioteca, una aproximacion historica (no una consulta en vivo a ningun
        # operador): se reporta en un hallazgo SEPARADO y marcado 'no_verificado' para
        # que nunca se confunda con el resto de metadatos 'confirmado' de arriba (ver
        # seccion 4: "no afirmes conocer el operador actual basandote solo en el
        # prefijo").
        operador = carrier.name_for_number(numero, "es")
        if operador:
            hallazgos.append(
                HallazgoOSINT(
                    categoria="telefono",
                    titulo="Operador sugerido por el bloque numerico (no verificado)",
                    descripcion=(
                        f"El bloque numerico esta historicamente asignado a '{operador}'. "
                        "Esto NO confirma el operador actual de la linea: los numeros se "
                        "portan entre operadores y esta asignacion puede estar desactualizada."
                    ),
                    nivel_confianza="no_verificado",
                    indicador_exposicion=None,
                    evidencias=(_evidencia(f"Operador (estimado, no verificado): {operador}"),),
                )
            )

        return hallazgos
