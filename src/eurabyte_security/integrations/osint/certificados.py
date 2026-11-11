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
MAXIMO_SUBDOMINIOS = 50


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
        subdominios: set[str] = set()
        for entrada in datos:
            nombres = str(entrada.get("name_value", ""))
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
                if nombre and nombre != objetivo_bajo and nombre.endswith(f".{objetivo_bajo}"):
                    subdominios.add(nombre)

        if not subdominios:
            return []

        ordenados = sorted(subdominios)[:MAXIMO_SUBDOMINIOS]
        return [
            HallazgoOSINT(
                categoria="certificados",
                titulo=f"{len(ordenados)} subdominio(s) observado(s) en Certificate Transparency",
                descripcion=(
                    "Nombres observados en certificados TLS emitidos para el dominio. No "
                    "implica que el subdominio este actualmente activo ni accesible."
                ),
                nivel_confianza="probable",
                indicador_exposicion=(
                    "Revisa si alguno de estos subdominios expone un servicio que no deberia "
                    "ser publico."
                ),
                evidencias=tuple(
                    EvidenciaOSINT(
                        fuente="certificados", fecha_consulta=fecha, referencia=url, valor=s
                    )
                    for s in ordenados
                ),
            )
        ]


def _ahora() -> str:
    return datetime.now(UTC).isoformat()
