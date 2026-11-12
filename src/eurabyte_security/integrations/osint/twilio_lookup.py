"""Fuente OSINT opcional y de pago por consulta: Twilio Lookup v2.

Documentacion oficial: https://www.twilio.com/docs/lookup/v2-api. A diferencia de toda
otra fuente de ``integrations/osint/`` (gratuitas, o con suscripcion FIJA como Have I
Been Pwned/VirusTotal), Twilio Lookup factura POR CONSULTA: por eso
``requiere_seleccion_explicita = True`` (ver ``integrations/osint/base.py``) -- tener
las credenciales configuradas nunca basta para que se ejecute; el usuario debe nombrarla
explicitamente con ``--fuentes twilio_lookup`` en CADA investigacion donde la quiera, y
la CLI (``commands/osint.py``) muestra un aviso de costo potencial antes de llamarla.

Credenciales: ``EST_TWILIO_ACCOUNT_SID`` y ``EST_TWILIO_AUTH_TOKEN`` (autenticacion HTTP
Basic, igual que el resto de la API de Twilio). Solo se piden los "fields" de tipo de
linea y nombre del operador (``line_type_intelligence``): nunca datos del titular de la
cuenta (nombre, direccion...), que Twilio Lookup tambien podria exponer segun el
"field" solicitado pero que estan fuera del alcance autorizado de AST (ver CLAUDE.md y
seccion 4 de la especificacion de metadatos telefonicos: "no identifiques al propietario
privado").
"""

from __future__ import annotations

import base64
import os
from collections.abc import Callable
from datetime import UTC, datetime

from eurabyte_security.core.errores import ErrorFuenteOSINTError, ErrorFuenteOSINTNoDisponible
from eurabyte_security.integrations.osint.base import AdaptadorFuenteOSINT
from eurabyte_security.integrations.osint.cliente_http import peticion_json
from eurabyte_security.modules.osint.modelos import EvidenciaOSINT, HallazgoOSINT

URL_DOCUMENTACION_TWILIO = "https://www.twilio.com/docs/lookup/v2-api"
VARIABLE_ACCOUNT_SID = "EST_TWILIO_ACCOUNT_SID"
VARIABLE_AUTH_TOKEN = "EST_TWILIO_AUTH_TOKEN"

AVISO_COSTO = (
    "Twilio Lookup v2 factura por consulta (ver https://www.twilio.com/docs/lookup/v2-api"
    "#pricing): cada vez que se incluya '--fuentes twilio_lookup' se generara un cargo "
    "en la cuenta de Twilio configurada."
)


def _ahora() -> str:
    return datetime.now(UTC).isoformat()


class AdaptadorTwilioLookup(AdaptadorFuenteOSINT):
    id_fuente = "twilio_lookup"
    nombre = "Twilio Lookup v2"
    tipos_objetivo = frozenset({"telefono"})
    requiere_clave = True
    variable_entorno_clave = VARIABLE_ACCOUNT_SID
    requiere_seleccion_explicita = True
    url_documentacion = URL_DOCUMENTACION_TWILIO

    def configurada(self) -> bool:
        return bool(
            os.environ.get(VARIABLE_ACCOUNT_SID) and os.environ.get(VARIABLE_AUTH_TOKEN)
        )

    def mensaje_no_configurada(self) -> str:
        return (
            f"'{self.nombre}' requiere configurar '{VARIABLE_ACCOUNT_SID}' y "
            f"'{VARIABLE_AUTH_TOKEN}'. {AVISO_COSTO}"
        )

    def investigar(
        self,
        objetivo: str,
        *,
        tipo_objetivo: str,
        tiempo_limite: float,
        debe_cancelar: Callable[[], bool] | None,
    ) -> list[HallazgoOSINT]:
        account_sid = os.environ.get(VARIABLE_ACCOUNT_SID)
        auth_token = os.environ.get(VARIABLE_AUTH_TOKEN)
        if not account_sid or not auth_token:
            raise ErrorFuenteOSINTNoDisponible(self.mensaje_no_configurada())

        credenciales = base64.b64encode(f"{account_sid}:{auth_token}".encode()).decode("ascii")
        url = (
            f"https://lookups.twilio.com/v2/PhoneNumbers/{objetivo}"
            "?Fields=line_type_intelligence"
        )
        try:
            datos = peticion_json(
                url,
                cabeceras={"Authorization": f"Basic {credenciales}"},
                tiempo_limite=tiempo_limite,
                debe_cancelar=debe_cancelar,
            )
        except ErrorFuenteOSINTError as exc:
            # Codigo HTTP estructurado, nunca una subcadena del mensaje ya formateado
            # (mismo principio que el resto de fuentes opcionales, ver revision de
            # seguridad de PR B del modulo OSINT).
            if exc.codigo_http == 404:
                raise ErrorFuenteOSINTNoDisponible(
                    f"Twilio Lookup no tiene informacion para '{objetivo}' (404)."
                ) from exc
            if exc.codigo_http == 401:
                raise ErrorFuenteOSINTNoDisponible(
                    f"Twilio rechazo las credenciales configuradas en "
                    f"'{VARIABLE_ACCOUNT_SID}'/'{VARIABLE_AUTH_TOKEN}' (401)."
                ) from exc
            if exc.codigo_http == 429:
                raise ErrorFuenteOSINTNoDisponible(
                    "Twilio Lookup respondio con limite de tasa agotado (429)."
                ) from exc
            raise
        if not isinstance(datos, dict):
            raise ErrorFuenteOSINTError(
                f"'{self.nombre}' devolvio una respuesta con formato inesperado."
            )

        fecha = _ahora()
        valido = datos.get("valid")
        evidencias = [
            EvidenciaOSINT(
                fuente="twilio_lookup",
                fecha_consulta=fecha,
                referencia=URL_DOCUMENTACION_TWILIO,
                valor=f"Numero valido segun Twilio: {'si' if valido else 'no'}",
            )
        ]
        pais = datos.get("country_code")
        if pais:
            evidencias.append(
                EvidenciaOSINT(
                    fuente="twilio_lookup",
                    fecha_consulta=fecha,
                    referencia=URL_DOCUMENTACION_TWILIO,
                    valor=f"Pais (ISO): {pais}",
                )
            )

        intel = datos.get("line_type_intelligence") or {}
        tipo_linea = intel.get("type")
        operador = intel.get("carrier_name")
        if tipo_linea:
            evidencias.append(
                EvidenciaOSINT(
                    fuente="twilio_lookup",
                    fecha_consulta=fecha,
                    referencia=URL_DOCUMENTACION_TWILIO,
                    valor=f"Tipo de linea (Twilio): {tipo_linea}",
                )
            )

        hallazgos = [
            HallazgoOSINT(
                categoria="telefono",
                titulo="Validacion de Twilio Lookup v2",
                descripcion=(
                    "Numero validado contra la base de Twilio Lookup (consulta de pago). "
                    "No identifica al titular de la linea."
                ),
                nivel_confianza="confirmado" if valido else "no_verificado",
                indicador_exposicion=None,
                evidencias=tuple(evidencias),
            )
        ]

        if operador:
            hallazgos.append(
                HallazgoOSINT(
                    categoria="telefono",
                    titulo="Operador reportado por Twilio (no verificado)",
                    descripcion=(
                        f"Twilio reporta el operador '{operador}' segun su propia base de "
                        "portabilidad numerica. Un numero portado recientemente puede no "
                        "reflejarse todavia; no se trata como un dato confirmado al 100%."
                    ),
                    nivel_confianza="no_verificado",
                    indicador_exposicion=None,
                    evidencias=(
                        EvidenciaOSINT(
                            fuente="twilio_lookup",
                            fecha_consulta=fecha,
                            referencia=URL_DOCUMENTACION_TWILIO,
                            valor=f"Operador (Twilio, no verificado): {operador}",
                        ),
                    ),
                )
            )

        return hallazgos
