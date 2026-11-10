"""Fuente OSINT: registros DNS publicos de un dominio (A, AAAA, MX, NS, TXT, CNAME) y
comprobaciones relacionadas con correo (SPF, DMARC).

Usa ``dnspython`` (ya dependencia transitiva del proyecto, ver pyproject.toml) en vez de
``socket.getaddrinfo`` (que ``core/objetivo.py`` ya usa para A/AAAA, pero no sabe
consultar MX/NS/TXT/CNAME): a diferencia de ese modulo, esta fuente nunca autoriza nada
contra un alcance de red, solo lee informacion ya publica.

``_crear_resolver()`` es el punto de extension que las pruebas sustituyen
(``monkeypatch.setattr(dns_publico, "_crear_resolver", doble)``) para nunca resolver un
dominio real durante las pruebas automatizadas (ver CLAUDE.md, regla 5).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

import dns.exception
import dns.resolver

from eurabyte_security.core.errores import ErrorFuenteOSINTError
from eurabyte_security.integrations.osint.base import AdaptadorFuenteOSINT
from eurabyte_security.modules.osint.modelos import EvidenciaOSINT, HallazgoOSINT

_TIPOS_REGISTRO: tuple[str, ...] = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")

URL_DOCUMENTACION_DNS = "https://www.rfc-editor.org/rfc/rfc1035"


def _crear_resolver(tiempo_limite: float) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = tiempo_limite
    resolver.lifetime = tiempo_limite
    return resolver


def _ahora() -> str:
    return datetime.now(UTC).isoformat()


def _consultar(
    resolver: dns.resolver.Resolver, dominio: str, tipo: str
) -> list[str] | None:
    """Devuelve los valores del registro, ``[]`` si no hay ninguno, o ``None`` si el
    dominio no existe en absoluto (NXDOMAIN) -- distincion que el llamador necesita para
    no repetir la misma consulta fallida cinco veces."""
    try:
        respuesta = resolver.resolve(dominio, tipo)
    except dns.resolver.NXDOMAIN:
        return None
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout as exc:
        raise ErrorFuenteOSINTError(
            f"La consulta DNS de tipo {tipo} para '{dominio}' no respondio a tiempo."
        ) from exc
    return [registro.to_text().strip('"') for registro in respuesta]


def _analizar_spf(valores_txt: list[str]) -> HallazgoOSINT:
    spf = next((v for v in valores_txt if v.lower().startswith("v=spf1")), None)
    if spf is None:
        return HallazgoOSINT(
            categoria="correo",
            titulo="SPF no configurado",
            descripcion="El dominio no publica un registro SPF (TXT 'v=spf1...').",
            nivel_confianza="confirmado",
            indicador_exposicion=(
                "Sin SPF, cualquier servidor puede falsificar el remitente del dominio."
            ),
            evidencias=(),
        )
    return HallazgoOSINT(
        categoria="correo",
        titulo="SPF configurado",
        descripcion=f"Registro SPF: {spf}",
        nivel_confianza="confirmado",
        indicador_exposicion=None,
        evidencias=(
            EvidenciaOSINT(fuente="dns", fecha_consulta=_ahora(), referencia=None, valor=spf),
        ),
    )


def _analizar_dmarc(valores_txt: list[str] | None) -> HallazgoOSINT:
    dmarc = next((v for v in (valores_txt or []) if v.lower().startswith("v=dmarc1")), None)
    if dmarc is None:
        return HallazgoOSINT(
            categoria="correo",
            titulo="DMARC no configurado",
            descripcion="El dominio no publica un registro DMARC ('_dmarc.<dominio>' TXT).",
            nivel_confianza="confirmado",
            indicador_exposicion=(
                "Sin DMARC, no hay politica que indique a otros servidores que hacer con "
                "un correo que falle SPF/DKIM para este dominio."
            ),
            evidencias=(),
        )
    return HallazgoOSINT(
        categoria="correo",
        titulo="DMARC configurado",
        descripcion=f"Registro DMARC: {dmarc}",
        nivel_confianza="confirmado",
        indicador_exposicion=(
            "Politica DMARC en modo 'none' (solo monitorizacion, sin rechazo)."
            if "p=none" in dmarc.lower()
            else None
        ),
        evidencias=(
            EvidenciaOSINT(fuente="dns", fecha_consulta=_ahora(), referencia=None, valor=dmarc),
        ),
    )


class AdaptadorDNSPublico(AdaptadorFuenteOSINT):
    id_fuente = "dns"
    nombre = "DNS publico"
    tipos_objetivo = frozenset({"dominio", "correo"})
    url_documentacion = URL_DOCUMENTACION_DNS

    def investigar(
        self,
        objetivo: str,
        *,
        tipo_objetivo: str,
        tiempo_limite: float,
        debe_cancelar: Callable[[], bool] | None,
    ) -> list[HallazgoOSINT]:
        resolver = _crear_resolver(tiempo_limite)
        hallazgos: list[HallazgoOSINT] = []
        fecha = _ahora()

        valores_por_tipo: dict[str, list[str] | None] = {}
        for tipo in _TIPOS_REGISTRO:
            if debe_cancelar is not None and debe_cancelar():
                return hallazgos
            valores_por_tipo[tipo] = _consultar(resolver, objetivo, tipo)

        # NXDOMAIN es una propiedad del propio nombre, no del tipo de registro: si la
        # consulta A ya lo confirma, el dominio no existe y no hace falta repetir la
        # misma conclusion para AAAA/MX/NS/TXT/CNAME.
        if valores_por_tipo.get("A") is None:
            return [
                HallazgoOSINT(
                    categoria="dns",
                    titulo="El dominio no existe",
                    descripcion=f"'{objetivo}' no tiene ningun registro DNS (NXDOMAIN).",
                    nivel_confianza="confirmado",
                    indicador_exposicion=None,
                    evidencias=(),
                )
            ]

        for tipo, valores in valores_por_tipo.items():
            if not valores:
                continue
            hallazgos.append(
                HallazgoOSINT(
                    categoria="dns",
                    titulo=f"Registros {tipo}",
                    descripcion=", ".join(valores),
                    nivel_confianza="confirmado",
                    indicador_exposicion=None,
                    evidencias=tuple(
                        EvidenciaOSINT(fuente="dns", fecha_consulta=fecha, referencia=None, valor=v)
                        for v in valores
                    ),
                )
            )

        hallazgos.append(_analizar_spf(valores_por_tipo.get("TXT") or []))
        if debe_cancelar is None or not debe_cancelar():
            valores_dmarc = _consultar(resolver, f"_dmarc.{objetivo}", "TXT")
            hallazgos.append(_analizar_dmarc(valores_dmarc))

        return hallazgos
