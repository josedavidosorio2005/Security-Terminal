"""Fuente OSINT opcional: VirusTotal -- reputacion/indicadores de un dominio.

Documentacion oficial: https://docs.virustotal.com/reference/domain-info. Requiere una
clave de API (nivel gratuito disponible en virustotal.com, con limite de tasa bajo):
se lee de ``EST_VIRUSTOTAL_API_KEY`` y nunca se muestra, se registra ni se persiste.

Solo se consulta el endpoint de informacion de dominio (solo lectura): nunca se sube
ni se envia ningun archivo/URL para analizar.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import UTC, datetime

from eurabyte_security.core.errores import ErrorFuenteOSINTError, ErrorFuenteOSINTNoDisponible
from eurabyte_security.integrations.osint import cache
from eurabyte_security.integrations.osint.base import AdaptadorFuenteOSINT
from eurabyte_security.integrations.osint.cliente_http import peticion_json
from eurabyte_security.integrations.osint.limitador import limitador_para_fuente
from eurabyte_security.modules.osint.modelos import EvidenciaOSINT, HallazgoOSINT

URL_DOCUMENTACION_VT = "https://docs.virustotal.com/reference/domain-info"
VARIABLE_CLAVE_VT = "EST_VIRUSTOTAL_API_KEY"

# Nivel publico/gratuito de VirusTotal: 4 peticiones por minuto documentadas -- 15s de
# intervalo minimo es el valor conservador correspondiente.
_INTERVALO_MINIMO_SEGUNDOS = 15.0
_TTL_CACHE_SEGUNDOS = 3600.0


def _ahora() -> str:
    return datetime.now(UTC).isoformat()


class AdaptadorVirusTotal(AdaptadorFuenteOSINT):
    id_fuente = "virustotal"
    nombre = "VirusTotal"
    tipos_objetivo = frozenset({"dominio", "correo"})
    requiere_clave = True
    variable_entorno_clave = VARIABLE_CLAVE_VT
    url_documentacion = URL_DOCUMENTACION_VT

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

        clave_cache = f"virustotal:{objetivo.lower()}"
        datos = cache.obtener(clave_cache)
        if datos is None:
            limitador_para_fuente(self.id_fuente, _INTERVALO_MINIMO_SEGUNDOS).esperar_si_necesario(
                debe_cancelar
            )
            url = f"https://www.virustotal.com/api/v3/domains/{objetivo}"
            try:
                datos = peticion_json(
                    url,
                    cabeceras={"x-apikey": clave_api},
                    tiempo_limite=tiempo_limite,
                    debe_cancelar=debe_cancelar,
                )
            except ErrorFuenteOSINTError as exc:
                mensaje = str(exc)
                if "404" in mensaje:
                    raise ErrorFuenteOSINTNoDisponible(
                        f"'{self.nombre}' no tiene informacion registrada para '{objetivo}'."
                    ) from exc
                if "401" in mensaje or "403" in mensaje:
                    raise ErrorFuenteOSINTNoDisponible(
                        f"'{self.nombre}' rechazo la clave configurada en "
                        f"'{self.variable_entorno_clave}'. Verifica que sea valida."
                    ) from exc
                raise
            cache.guardar(clave_cache, datos, _TTL_CACHE_SEGUNDOS)

        if not isinstance(datos, dict):
            raise ErrorFuenteOSINTError(
                f"'{self.nombre}' devolvio una respuesta con formato inesperado."
            )

        atributos = datos.get("data", {}).get("attributes", {})
        estadisticas = atributos.get("last_analysis_stats", {})
        maliciosos = int(estadisticas.get("malicious", 0))
        sospechosos = int(estadisticas.get("suspicious", 0))
        reputacion = atributos.get("reputation")

        descripcion = (
            f"Analisis de motores: {maliciosos} malicioso(s), {sospechosos} sospechoso(s). "
            f"Reputacion: {reputacion if reputacion is not None else 'sin dato'}."
        )
        indicador = None
        if maliciosos > 0 or sospechosos > 0:
            indicador = (
                f"{maliciosos} motor(es) marcan este dominio como malicioso y "
                f"{sospechosos} como sospechoso, segun VirusTotal."
            )

        return [
            HallazgoOSINT(
                categoria="exposicion",
                titulo="Reputacion en VirusTotal",
                descripcion=descripcion,
                nivel_confianza="confirmado",
                indicador_exposicion=indicador,
                evidencias=(
                    EvidenciaOSINT(
                        fuente="virustotal",
                        fecha_consulta=_ahora(),
                        referencia=f"https://www.virustotal.com/gui/domain/{objetivo}",
                        valor=f"maliciosos={maliciosos}, sospechosos={sospechosos}",
                    ),
                ),
            )
        ]
