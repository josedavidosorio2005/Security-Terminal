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
# Por pagina (parametro 'size' de la API de busqueda) y numero maximo de paginas: una
# sola fuente pasiva no debe convertir una investigacion en decenas de peticiones. Con
# el tope por defecto (100 x 3 = 300) se cubre con holgura el historial tipico de un
# dominio sin arriesgar una investigacion que tarde demasiado o golpee limites de tasa.
RESULTADOS_POR_PAGINA = 100
MAXIMO_PAGINAS = 3


def _ahora() -> str:
    return datetime.now(UTC).isoformat()


def _cancelado(debe_cancelar: Callable[[], bool] | None) -> bool:
    return debe_cancelar is not None and debe_cancelar()


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
        resultados: list[dict] = []
        total_reportado: int | None = None
        cursor: str | None = None

        for _pagina in range(MAXIMO_PAGINAS):
            if _cancelado(debe_cancelar):
                break
            url = (
                f"https://urlscan.io/api/v1/search/?q={consulta}&size={RESULTADOS_POR_PAGINA}"
            )
            if cursor:
                url += f"&search_after={cursor}"
            datos = peticion_json(url, tiempo_limite=tiempo_limite, debe_cancelar=debe_cancelar)
            if not isinstance(datos, dict):
                raise ErrorFuenteOSINTError(
                    f"'{self.nombre}' devolvio una respuesta con formato inesperado."
                )
            if total_reportado is None:
                total_reportado = datos.get("total")

            pagina_resultados = datos.get("results", [])
            if not isinstance(pagina_resultados, list) or not pagina_resultados:
                break
            resultados.extend(pagina_resultados)

            if len(pagina_resultados) < RESULTADOS_POR_PAGINA:
                break  # ultima pagina: la fuente devolvio menos de lo pedido
            ultimo = pagina_resultados[-1].get("sort")
            if not isinstance(ultimo, list) or len(ultimo) != 2:
                break  # sin cursor de paginacion valido: no se puede seguir avanzando
            cursor = ",".join(str(v) for v in ultimo)

        if not resultados:
            return []

        fecha = _ahora()
        # Deduplicacion defensiva por (URL, fecha de escaneo): urlscan puede repetir una
        # entrada entre paginas si hay nuevos escaneos mientras se recorre el cursor.
        vistos: set[tuple[str, str]] = set()
        evidencias: list[EvidenciaOSINT] = []
        for resultado in resultados:
            pagina_url = resultado.get("page", {}).get("url") or "(sin URL)"
            marca_tiempo = resultado.get("task", {}).get("time") or "fecha desconocida"
            if (pagina_url, marca_tiempo) in vistos:
                continue
            vistos.add((pagina_url, marca_tiempo))
            enlace_resultado = resultado.get("result") or "https://urlscan.io/"
            evidencias.append(
                EvidenciaOSINT(
                    fuente="urlscan_historial",
                    fecha_consulta=fecha,
                    referencia=enlace_resultado,
                    valor=pagina_url,
                    fecha_observada=marca_tiempo,
                )
            )

        descripcion = (
            "Escaneos publicos ya existentes de este dominio (no se envio ningun "
            "escaneo nuevo). No confirma el estado actual del sitio."
        )
        if isinstance(total_reportado, int) and total_reportado > len(evidencias):
            descripcion += (
                f" Mostrando {len(evidencias)} de {total_reportado} escaneos reportados "
                f"en total por urlscan.io (limite de {MAXIMO_PAGINAS} pagina(s) de "
                f"{RESULTADOS_POR_PAGINA})."
            )

        return [
            HallazgoOSINT(
                categoria="historial_escaneos",
                titulo=f"{len(evidencias)} escaneo(s) historico(s) en urlscan.io",
                descripcion=descripcion,
                nivel_confianza="probable",
                indicador_exposicion=None,
                evidencias=tuple(evidencias),
            )
        ]
