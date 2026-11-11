"""Fuente OSINT: busqueda publica de urlscan.io -- historial de escaneos de un dominio.

Documentacion oficial: https://docs.urlscan.io/. La busqueda (``/api/v1/search/``) es
publica y no requiere clave de API (a diferencia de enviar una URL nueva a analizar,
que esta fuera del alcance de AST): por eso esta fuente se ofrece sin configuracion,
igual que DNS/RDAP/Certificate Transparency.

Pasivo por diseno: solo lee escaneos que YA existen en urlscan.io, nunca envia el
dominio a analizar. Cada hallazgo se marca como 'probable' (evidencia historica, no
confirma el estado actual del sitio).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from urllib.parse import quote

from eurabyte_security.core.errores import ErrorFuenteOSINTError
from eurabyte_security.integrations.osint.base import AdaptadorFuenteOSINT
from eurabyte_security.integrations.osint.cliente_http import peticion_json
from eurabyte_security.modules.osint.modelos import EvidenciaOSINT, HallazgoOSINT

URL_DOCUMENTACION_URLSCAN = "https://docs.urlscan.io/"
MAXIMO_RESULTADOS = 10


def _ahora() -> str:
    return datetime.now(UTC).isoformat()


class AdaptadorUrlscan(AdaptadorFuenteOSINT):
    id_fuente = "urlscan_historial"
    nombre = "Historial de escaneos (urlscan.io)"
    tipos_objetivo = frozenset({"dominio", "correo"})
    url_documentacion = URL_DOCUMENTACION_URLSCAN

    def investigar(
        self,
        objetivo: str,
        *,
        tipo_objetivo: str,
        tiempo_limite: float,
        debe_cancelar: Callable[[], bool] | None,
    ) -> list[HallazgoOSINT]:
        consulta = quote(f"domain:{objetivo}", safe="")
        url = f"https://urlscan.io/api/v1/search/?q={consulta}&size={MAXIMO_RESULTADOS}"
        datos = peticion_json(url, tiempo_limite=tiempo_limite, debe_cancelar=debe_cancelar)
        if not isinstance(datos, dict):
            raise ErrorFuenteOSINTError(
                f"'{self.nombre}' devolvio una respuesta con formato inesperado."
            )

        resultados = datos.get("results", [])
        if not resultados:
            return []

        fecha = _ahora()
        evidencias = []
        for resultado in resultados[:MAXIMO_RESULTADOS]:
            pagina_url = resultado.get("page", {}).get("url", "(sin URL)")
            marca_tiempo = resultado.get("task", {}).get("time", "fecha desconocida")
            enlace_resultado = resultado.get("result") or "https://urlscan.io/"
            evidencias.append(
                EvidenciaOSINT(
                    fuente="urlscan_historial",
                    fecha_consulta=fecha,
                    referencia=enlace_resultado,
                    valor=f"{pagina_url} ({marca_tiempo})",
                )
            )

        return [
            HallazgoOSINT(
                categoria="historial_escaneos",
                titulo=f"{len(evidencias)} escaneo(s) historico(s) en urlscan.io",
                descripcion=(
                    "Escaneos publicos ya existentes de este dominio (no se envio ningun "
                    "escaneo nuevo). No confirma el estado actual del sitio."
                ),
                nivel_confianza="probable",
                indicador_exposicion=None,
                evidencias=tuple(evidencias),
            )
        ]
