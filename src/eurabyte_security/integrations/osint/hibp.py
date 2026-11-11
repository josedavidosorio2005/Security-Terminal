"""Fuente OSINT opcional: Have I Been Pwned (API v3) -- brechas conocidas de un correo.

Documentacion oficial: https://haveibeenpwned.com/API/v3. Requiere una clave de
suscripcion (no hay nivel gratuito para esta consulta): se lee de
``EST_HIBP_API_KEY`` y nunca se muestra, se registra ni se persiste.

**Minimizacion deliberada**: de cada brecha solo se guarda su nombre, fecha publicada
y las CATEGORIAS de datos que se reportaron expuestas (``DataClasses``, p. ej.
"Email addresses", "Passwords" -- son etiquetas de categoria, nunca el dato real que se
filtro). Nunca se solicita, almacena ni muestra una contrasena, hash, cookie, token ni
el contenido de la brecha en si (ver CLAUDE.md y seccion 3 de la especificacion del
modulo).
"""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import UTC, datetime
from urllib.parse import quote

from eurabyte_security.core.errores import ErrorFuenteOSINTError, ErrorFuenteOSINTNoDisponible
from eurabyte_security.integrations.osint import cache
from eurabyte_security.integrations.osint.base import AdaptadorFuenteOSINT
from eurabyte_security.integrations.osint.cliente_http import peticion_json
from eurabyte_security.integrations.osint.limitador import limitador_para_fuente
from eurabyte_security.modules.osint.modelos import EvidenciaOSINT, HallazgoOSINT

URL_DOCUMENTACION_HIBP = "https://haveibeenpwned.com/API/v3"
VARIABLE_CLAVE_HIBP = "EST_HIBP_API_KEY"

# HIBP exige un minimo de tiempo entre peticiones segun el nivel de suscripcion; 1.6s
# es un valor conservador razonable para el nivel de entrada, documentado como punto
# de partida (ver docs/OSINT.md): quien tenga un nivel superior puede ajustarlo si en
# el futuro se expone como configuracion.
_INTERVALO_MINIMO_SEGUNDOS = 1.6
_TTL_CACHE_SEGUNDOS = 3600.0


def _ahora() -> str:
    return datetime.now(UTC).isoformat()


class AdaptadorHIBP(AdaptadorFuenteOSINT):
    id_fuente = "hibp"
    nombre = "Have I Been Pwned"
    tipos_objetivo = frozenset({"correo"})
    requiere_clave = True
    variable_entorno_clave = VARIABLE_CLAVE_HIBP
    # Consulta por CUENTA DE CORREO completa (breachedaccount/{correo}), nunca por
    # dominio: a diferencia del resto de fuentes de 'correo', necesita el objetivo
    # original completo, no el dominio derivado (ver integrations/osint/base.py).
    requiere_objetivo_original = True
    url_documentacion = URL_DOCUMENTACION_HIBP

    def investigar(
        self,
        objetivo: str,
        *,
        tipo_objetivo: str,
        tiempo_limite: float,
        debe_cancelar: Callable[[], bool] | None,
    ) -> list[HallazgoOSINT]:
        clave_api = (
            os.environ.get(self.variable_entorno_clave) if self.variable_entorno_clave else None
        )
        if not clave_api:
            raise ErrorFuenteOSINTNoDisponible(self.mensaje_no_configurada())

        clave_cache = f"hibp:{objetivo.lower()}"
        datos = cache.obtener(clave_cache)
        if datos is None:
            limitador_para_fuente(self.id_fuente, _INTERVALO_MINIMO_SEGUNDOS).esperar_si_necesario(
                debe_cancelar
            )
            url = (
                "https://haveibeenpwned.com/api/v3/breachedaccount/"
                f"{quote(objetivo, safe='')}?truncateResponse=false"
            )
            try:
                datos = peticion_json(
                    url,
                    cabeceras={"hibp-api-key": clave_api},
                    tiempo_limite=tiempo_limite,
                    debe_cancelar=debe_cancelar,
                )
            except ErrorFuenteOSINTError as exc:
                # Comparacion por codigo HTTP ESTRUCTURADO (entero), nunca por
                # subcadena del mensaje ya formateado: evita que un fallo real se
                # confunda con "sin brechas" por una coincidencia de texto (ver
                # revision de seguridad de esta misma PR).
                if exc.codigo_http == 404:
                    datos = []  # documentado por HIBP: cuenta no encontrada = sin brechas
                elif exc.codigo_http == 401:
                    raise ErrorFuenteOSINTNoDisponible(
                        f"'{self.nombre}' rechazo la clave configurada en "
                        f"'{self.variable_entorno_clave}' (401). Verifica que sea valida."
                    ) from exc
                else:
                    raise
            cache.guardar(clave_cache, datos, _TTL_CACHE_SEGUNDOS)

        if not isinstance(datos, list):
            raise ErrorFuenteOSINTError(
                f"'{self.nombre}' devolvio una respuesta con formato inesperado."
            )

        if not datos:
            return [
                HallazgoOSINT(
                    categoria="exposicion",
                    titulo="Sin brechas conocidas",
                    descripcion=(
                        f"{self.nombre} no reporta ninguna brecha conocida para este correo."
                    ),
                    nivel_confianza="confirmado",
                    indicador_exposicion=None,
                    evidencias=(),
                )
            ]

        fecha = _ahora()
        hallazgos: list[HallazgoOSINT] = []
        for brecha in datos:
            nombre_brecha = str(brecha.get("Name", "desconocida"))
            titulo_brecha = str(brecha.get("Title", nombre_brecha))
            fecha_brecha = str(brecha.get("BreachDate", "fecha desconocida"))
            categorias_datos = [str(c) for c in brecha.get("DataClasses", [])]
            hallazgos.append(
                HallazgoOSINT(
                    categoria="exposicion",
                    titulo=f"Brecha conocida: {titulo_brecha}",
                    descripcion=(
                        f"Reportada el {fecha_brecha}. Categorias de datos expuestas: "
                        f"{', '.join(categorias_datos) or 'no especificadas'}."
                    ),
                    nivel_confianza="confirmado",
                    indicador_exposicion=(
                        f"El correo aparece en la brecha '{titulo_brecha}' ({fecha_brecha})."
                    ),
                    evidencias=(
                        EvidenciaOSINT(
                            fuente="hibp",
                            fecha_consulta=fecha,
                            referencia="https://haveibeenpwned.com/",
                            valor=nombre_brecha,
                        ),
                    ),
                )
            )
        return hallazgos
