"""Fuente OSINT: Certificate Transparency (subdominios observados pasivamente).

Usa la API publica y gratuita de ``crt.sh`` (https://crt.sh, respaldada por Sectigo):
busca certificados TLS emitidos para el dominio y sus subdominios en los logs publicos
de Certificate Transparency (ct.cloudflare.com, Google Argon/Xenon...). Es
deliberadamente PASIVO: no conecta con ningun subdominio descubierto, solo lee que
alguien, en algun momento, pidio un certificado para ese nombre -- por eso cada hallazgo
se marca con nivel de confianza 'probable', nunca 'confirmado': un nombre en un
certificado no garantiza que el subdominio siga activo hoy (ver seccion 2.A de la
especificacion del modulo, "separar observaciones historicas de informacion confirmada").
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from eurabyte_security.core.errores import ErrorFuenteOSINTError
from eurabyte_security.integrations.osint.base import AdaptadorFuenteOSINT
from eurabyte_security.integrations.osint.cliente_http import peticion_json
from eurabyte_security.modules.osint.modelos import EvidenciaOSINT, HallazgoOSINT

URL_DOCUMENTACION_CT = "https://crt.sh/"
# crt.sh devuelve TODAS las coincidencias en una sola respuesta (no pagina): este tope
# es solo para no construir un hallazgo con miles de evidencias en un dominio con
# certificados wildcard muy reemitidos. Si se supera, el hallazgo lo dice explicitamente
# (nunca se oculta el recorte, ver seccion 2 de la especificacion de evidencia completa).
MAXIMO_SUBDOMINIOS = 500


class AdaptadorCertificateTransparency(AdaptadorFuenteOSINT):
    id_fuente = "certificados"
    nombre = "Certificate Transparency (crt.sh)"
    tipos_objetivo = frozenset({"dominio", "correo"})
    url_documentacion = URL_DOCUMENTACION_CT

    def investigar(
        self,
        objetivo: str,
        *,
        tipo_objetivo: str,
        tiempo_limite: float,
        debe_cancelar: Callable[[], bool] | None,
    ) -> list[HallazgoOSINT]:
        url = f"https://crt.sh/?q=%25.{objetivo}&output=json"
        datos = peticion_json(url, tiempo_limite=tiempo_limite, debe_cancelar=debe_cancelar)
        if not isinstance(datos, list):
            raise ErrorFuenteOSINTError("crt.sh devolvio una respuesta con formato inesperado.")

        fecha = _ahora()
        objetivo_bajo = objetivo.lower()
        # Por subdominio: el certificado MAS RECIENTE visto (segun 'entry_timestamp',
        # cuando crt.sh lo reporta) para poder enlazar una referencia real y una fecha
        # de observacion historica concreta, en vez de un enlace generico de busqueda.
        mas_reciente: dict[str, tuple[str, str | None]] = {}
        for entrada in datos:
            nombres = str(entrada.get("name_value", ""))
            id_certificado = entrada.get("id")
            marca_tiempo = entrada.get("entry_timestamp") or entrada.get("not_before")
            marca_tiempo = str(marca_tiempo) if marca_tiempo else None
            referencia_cert = f"https://crt.sh/?id={id_certificado}" if id_certificado else None
            for nombre in nombres.splitlines():
                # Solo quita UN prefijo de comodin literal ('*.'), nunca cualquier
                # combinacion de '*'/'.' (lstrip() recortaria tambien puntos legitimos
                # al inicio de un nombre sin comodin).
                nombre = nombre.strip().lower().removeprefix("*.")
                # Comprobacion por LIMITE DE ETIQUETA, no un simple 'endswith': sin el
                # punto exigido antes del sufijo, 'malicioso-ejemplo.com' coincidiria
                # con el objetivo 'ejemplo.com' por ser un sufijo de cadena, aunque no
                # sea en absoluto un subdominio real (ver revision de seguridad). El
                # propio dominio (sin subdominio) se excluye a proposito: esto busca
                # SUBdominios, no vuelve a reportar el objetivo que el usuario ya dio.
                es_subdominio = (
                    nombre and nombre != objetivo_bajo and nombre.endswith(f".{objetivo_bajo}")
                )
                if not es_subdominio:
                    continue
                anterior = mas_reciente.get(nombre)
                if anterior is None or (marca_tiempo and (anterior[1] or "") < marca_tiempo):
                    mas_reciente[nombre] = (referencia_cert or url, marca_tiempo)

        if not mas_reciente:
            return []

        total_observados = len(mas_reciente)
        nombres_ordenados = sorted(mas_reciente)[:MAXIMO_SUBDOMINIOS]
        recortado = total_observados > len(nombres_ordenados)
        descripcion = (
            "Nombres observados en certificados TLS emitidos para el dominio (deduplicados). "
            "No implica que el subdominio este actualmente activo ni accesible."
        )
        if recortado:
            descripcion += (
                f" Mostrando {len(nombres_ordenados)} de {total_observados} subdominios "
                "observados en total (limite de evidencias por hallazgo); crt.sh no "
                "pagina su respuesta, por lo que el resto no se recupero en esta consulta."
            )
        return [
            HallazgoOSINT(
                categoria="certificados",
                titulo=(
                    f"{len(nombres_ordenados)} subdominio(s) observado(s) en "
                    "Certificate Transparency"
                ),
                descripcion=descripcion,
                nivel_confianza="probable",
                indicador_exposicion=(
                    "Revisa si alguno de estos subdominios expone un servicio que no deberia "
                    "ser publico."
                ),
                evidencias=tuple(
                    EvidenciaOSINT(
                        fuente="certificados",
                        fecha_consulta=fecha,
                        referencia=mas_reciente[nombre][0],
                        valor=nombre,
                        fecha_observada=mas_reciente[nombre][1],
                    )
                    for nombre in nombres_ordenados
                ),
            )
        ]


def _ahora() -> str:
    return datetime.now(UTC).isoformat()
