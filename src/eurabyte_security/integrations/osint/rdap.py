"""Fuentes OSINT basadas en RDAP (Registration Data Access Protocol, RFC 9082/9083).

RDAP es el sucesor documentado por ICANN del protocolo WHOIS clasico
(https://www.icann.org/rdap): a diferencia de WHOIS, devuelve JSON estructurado y tiene
un servicio de redireccion ("bootstrap") unico (``rdap.org``, operado por la propia
comunidad RDAP) que reenvia la consulta al registro oficial correspondiente segun el
TLD o el rango de IP, sin que AST tenga que mantener su propia tabla de servidores RDAP
por registro.

**Minimizacion deliberada**: muchos registros RDAP incluyen datos de contacto del
registrante cuando el dominio no usa un servicio de privacidad. Estos adaptadores
extraen unicamente el nombre de la ORGANIZACION de cada entidad (campo ``org`` de su
``vcardArray``), nunca nombre de persona, correo ni telefono de un WHOIS/RDAP de
terceros: ese dato personal no esta dentro del alcance autorizado de esta investigacion
(ver CLAUDE.md y la seccion 3 de la especificacion del modulo).
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from datetime import UTC, datetime

import dns.exception
import dns.resolver

from eurabyte_security.core.errores import ErrorFuenteOSINTError, ErrorFuenteOSINTNoDisponible
from eurabyte_security.integrations.osint.base import AdaptadorFuenteOSINT
from eurabyte_security.integrations.osint.cliente_http import peticion_json
from eurabyte_security.modules.osint.modelos import EvidenciaOSINT, HallazgoOSINT

URL_DOCUMENTACION_RDAP = "https://www.icann.org/rdap"
URL_DOCUMENTACION_CYMRU = "https://team-cymru.com/community-services/ip-asn-mapping/"
_BASE_RDAP = "https://rdap.org"


def _consultar_asn_por_ip(ip: str, tiempo_limite: float) -> dict[str, str] | None:
    """Resuelve el ASN y la organizacion de una IPv4 via el servicio DNS publico y
    pasivo de Team Cymru (``origin.asn.cymru.com``): NUNCA se conecta a la IP en si,
    solo lee la tabla de rutas BGP que Cymru publica por DNS, el mismo mecanismo
    documentado que usan herramientas como 'whois -h whois.cymru.com'. Devuelve
    ``None`` (nunca lanza) si el ASN no se pudo resolver: es informacion adicional, no
    critica para el resto del hallazgo de infraestructura."""
    try:
        octetos = str(ipaddress.IPv4Address(ip)).split(".")
    except ValueError:
        return None

    resolver = dns.resolver.Resolver()
    resolver.timeout = tiempo_limite
    resolver.lifetime = tiempo_limite
    consulta_origen = f"{'.'.join(reversed(octetos))}.origin.asn.cymru.com"
    try:
        respuesta = resolver.resolve(consulta_origen, "TXT")
    except (dns.exception.DNSException, OSError):
        return None

    registro = next(iter(respuesta), None)
    if registro is None:
        return None
    partes = [p.strip() for p in registro.to_text().strip('"').split("|")]
    if len(partes) < 4:
        return None
    asn = partes[0].split()[0]  # puede listar varios ASN separados por espacio
    resultado = {"asn": asn, "prefijo_bgp": partes[1], "pais": partes[2], "registro": partes[3]}

    try:
        respuesta_nombre = resolver.resolve(f"AS{asn}.asn.cymru.com", "TXT")
        registro_nombre = next(iter(respuesta_nombre), None)
        if registro_nombre is not None:
            partes_nombre = [p.strip() for p in registro_nombre.to_text().strip('"').split("|")]
            if len(partes_nombre) >= 5 and partes_nombre[4]:
                resultado["organizacion"] = partes_nombre[4]
    except (dns.exception.DNSException, OSError):
        pass  # el ASN numerico ya es util sin el nombre de la organizacion

    return resultado


def _ahora() -> str:
    return datetime.now(UTC).isoformat()


def _organizacion_desde_entidades(entidades: list[dict]) -> str | None:
    for entidad in entidades or []:
        vcard = entidad.get("vcardArray")
        if not (isinstance(vcard, list) and len(vcard) == 2):
            continue
        for campo in vcard[1]:
            if isinstance(campo, list) and len(campo) >= 4 and campo[0] == "org":
                valor = campo[3]
                if isinstance(valor, str) and valor.strip():
                    return valor.strip()
    return None


def _eventos_resumen(eventos: list[dict]) -> dict[str, str]:
    resumen: dict[str, str] = {}
    for evento in eventos or []:
        accion = evento.get("eventAction")
        fecha = evento.get("eventDate")
        if accion and fecha:
            resumen[str(accion)] = str(fecha)
    return resumen


class AdaptadorRDAPDominio(AdaptadorFuenteOSINT):
    id_fuente = "rdap_dominio"
    nombre = "RDAP (registro del dominio)"
    tipos_objetivo = frozenset({"dominio", "correo"})
    url_documentacion = URL_DOCUMENTACION_RDAP

    def investigar(
        self,
        objetivo: str,
        *,
        tipo_objetivo: str,
        tiempo_limite: float,
        debe_cancelar: Callable[[], bool] | None,
    ) -> list[HallazgoOSINT]:
        url = f"{_BASE_RDAP}/domain/{objetivo}"
        try:
            datos = peticion_json(url, tiempo_limite=tiempo_limite, debe_cancelar=debe_cancelar)
        except ErrorFuenteOSINTError as exc:
            # Codigo HTTP estructurado, nunca una subcadena del mensaje (ver revision
            # de seguridad de esta PR).
            if exc.codigo_http == 404:
                raise ErrorFuenteOSINTNoDisponible(
                    f"RDAP no tiene un registro publico para '{objetivo}' (404)."
                ) from exc
            raise
        if not isinstance(datos, dict):
            raise ErrorFuenteOSINTError("RDAP devolvio una respuesta con formato inesperado.")

        fecha = _ahora()
        hallazgos: list[HallazgoOSINT] = []

        eventos = _eventos_resumen(datos.get("events", []))
        estados = ", ".join(datos.get("status", [])) or "sin estado publicado"
        descripcion = f"Estado: {estados}."
        if eventos:
            partes_eventos = (f"{accion}: {fecha_evt}" for accion, fecha_evt in eventos.items())
            descripcion += " " + "; ".join(partes_eventos)
        hallazgos.append(
            HallazgoOSINT(
                categoria="rdap",
                titulo="Registro RDAP del dominio",
                descripcion=descripcion,
                nivel_confianza="confirmado",
                indicador_exposicion=None,
                evidencias=(
                    EvidenciaOSINT(
                        fuente="rdap_dominio", fecha_consulta=fecha, referencia=url, valor=estados
                    ),
                ),
            )
        )

        organizacion = _organizacion_desde_entidades(datos.get("entities", []))
        if organizacion:
            hallazgos.append(
                HallazgoOSINT(
                    categoria="rdap",
                    titulo="Organizacion registrante (RDAP)",
                    descripcion=(
                        f"Organizacion publicada por el registro: {organizacion}. Puede "
                        "corresponder a un servicio de privacidad del registrador, no "
                        "necesariamente al titular final."
                    ),
                    nivel_confianza="probable",
                    indicador_exposicion=None,
                    evidencias=(
                        EvidenciaOSINT(
                            fuente="rdap_dominio",
                            fecha_consulta=fecha,
                            referencia=url,
                            valor=organizacion,
                        ),
                    ),
                )
            )
        return hallazgos


class AdaptadorInfraestructuraIP(AdaptadorFuenteOSINT):
    """Infraestructura (ASN/red/organizacion) de la primera IP publicada por el dominio."""

    id_fuente = "infraestructura_ip"
    nombre = "RDAP (infraestructura IP)"
    tipos_objetivo = frozenset({"dominio", "correo"})
    url_documentacion = URL_DOCUMENTACION_RDAP

    def investigar(
        self,
        objetivo: str,
        *,
        tipo_objetivo: str,
        tiempo_limite: float,
        debe_cancelar: Callable[[], bool] | None,
    ) -> list[HallazgoOSINT]:
        try:
            resultados = socket.getaddrinfo(objetivo, None, family=socket.AF_INET)
        except OSError as exc:
            raise ErrorFuenteOSINTNoDisponible(
                f"'{objetivo}' no se pudo resolver a una IPv4 para consultar su "
                f"infraestructura: {exc}"
            ) from exc
        ip = str(ipaddress.IPv4Address(resultados[0][4][0]))

        url = f"{_BASE_RDAP}/ip/{ip}"
        datos = peticion_json(url, tiempo_limite=tiempo_limite, debe_cancelar=debe_cancelar)
        if not isinstance(datos, dict):
            raise ErrorFuenteOSINTError("RDAP devolvio una respuesta con formato inesperado.")

        fecha = _ahora()
        nombre_red = datos.get("name") or "(sin nombre)"
        pais = datos.get("country") or "desconocido"
        rango = f"{datos.get('startAddress', '?')} - {datos.get('endAddress', '?')}"
        organizacion = _organizacion_desde_entidades(datos.get("entities", []))

        descripcion = f"Red: {nombre_red} ({rango}). Pais: {pais}."
        if organizacion:
            descripcion += f" Organizacion: {organizacion}."

        evidencias = [
            EvidenciaOSINT(
                fuente="infraestructura_ip", fecha_consulta=fecha, referencia=url, valor=ip
            )
        ]

        # El ASN es informacion ADICIONAL: si Cymru no responde (red, timeout...) el
        # hallazgo de infraestructura RDAP sigue siendo valido sin el (ver
        # '_consultar_asn_por_ip', que nunca lanza).
        if debe_cancelar is None or not debe_cancelar():
            asn_info = _consultar_asn_por_ip(ip, tiempo_limite)
            if asn_info is not None:
                asn = asn_info["asn"]
                descripcion += f" ASN: AS{asn}"
                if asn_info.get("organizacion"):
                    descripcion += f" ({asn_info['organizacion']})"
                descripcion += "."
                organizacion_asn = asn_info.get("organizacion", "sin nombre publicado")
                valor_asn = (
                    f"ASN: AS{asn} ({organizacion_asn}) - prefijo BGP "
                    f"{asn_info['prefijo_bgp']} - registro {asn_info['registro']}"
                )
                evidencias.append(
                    EvidenciaOSINT(
                        fuente="infraestructura_ip",
                        fecha_consulta=fecha,
                        referencia=URL_DOCUMENTACION_CYMRU,
                        valor=valor_asn,
                    )
                )

        return [
            HallazgoOSINT(
                categoria="infraestructura",
                titulo=f"Infraestructura de {ip}",
                descripcion=descripcion,
                nivel_confianza="confirmado",
                indicador_exposicion=None,
                evidencias=tuple(evidencias),
            )
        ]
