"""Auditoria HTTPS/TLS: version negociada, suite de cifrado y certificado.

``obtener_info_tls`` nunca desactiva la validacion TLS para fingir un resultado
satisfactorio. Primero intenta una conexion completamente verificada (cadena de
confianza + nombre de host); si eso falla, abre una segunda conexion *solo para
leer los bytes reales del certificado* (necesarios para mostrar fecha de
vencimiento, emisor, etc.), pero el resultado deja explicito que la cadena de
confianza no se pudo verificar y por que. Los metadatos extraidos por esa via
siempre vienen del certificado real presentado por el servidor, nunca se
inventan ni se asumen.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from eurabyte_security.core.errores import ErrorAuditoriaWeb
from eurabyte_security.modules.web.modelos import Hallazgo, Severidad

TIEMPO_LIMITE_MINIMO = 1.0
TIEMPO_LIMITE_MAXIMO = 30.0

# TLS 1.0/1.1 y cualquier version de SSL se consideran obsoletos: aunque Python/OpenSSL
# ya no suelen negociarlos salvo configuracion explicita, se evaluan si aparecen.
_PROTOCOLOS_OBSOLETOS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


@dataclass(frozen=True, slots=True)
class InfoCertificado:
    sujeto: str | None
    emisor: str | None
    no_antes: datetime | None
    no_despues: datetime | None
    nombres_alternativos: tuple[str, ...]
    coincide_con_host: bool | None
    confiable: bool
    error_confianza: str | None


@dataclass(frozen=True, slots=True)
class InfoTLS:
    version_protocolo: str | None
    suite_cifrado: str | None
    certificado: InfoCertificado | None


def _nombre_x509(nombre: x509.Name | None) -> str | None:
    if nombre is None:
        return None
    try:
        atributos = nombre.get_attributes_for_oid(NameOID.COMMON_NAME)
        if atributos:
            return str(atributos[0].value)
    except Exception:  # noqa: BLE001 - lectura de metadatos, nunca debe romper la auditoria
        pass
    return nombre.rfc4514_string()


def _analizar_certificado_der(
    der: bytes, host: ipaddress.IPv4Address, *, confiable: bool, error_confianza: str | None
) -> InfoCertificado:
    try:
        certificado = x509.load_der_x509_certificate(der, backend=default_backend())
    except Exception as exc:  # noqa: BLE001 - certificado ilegible, se reporta como tal
        return InfoCertificado(
            sujeto=None,
            emisor=None,
            no_antes=None,
            no_despues=None,
            nombres_alternativos=(),
            coincide_con_host=None,
            confiable=False,
            error_confianza=error_confianza or f"No se pudo interpretar el certificado: {exc}",
        )

    nombres_alternativos: tuple[str, ...] = ()
    try:
        extension = certificado.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        ips = [str(v) for v in extension.value.get_values_for_type(x509.IPAddress)]
        dns = list(extension.value.get_values_for_type(x509.DNSName))
        nombres_alternativos = tuple(ips + dns)
    except x509.ExtensionNotFound:
        nombres_alternativos = ()

    if confiable:
        # La verificacion con check_hostname ya confirmo la coincidencia.
        coincide_con_host: bool | None = True
    elif nombres_alternativos:
        coincide_con_host = str(host) in nombres_alternativos
    else:
        coincide_con_host = None

    return InfoCertificado(
        sujeto=_nombre_x509(certificado.subject),
        emisor=_nombre_x509(certificado.issuer),
        no_antes=certificado.not_valid_before_utc,
        no_despues=certificado.not_valid_after_utc,
        nombres_alternativos=nombres_alternativos,
        coincide_con_host=coincide_con_host,
        confiable=confiable,
        error_confianza=error_confianza,
    )


def obtener_info_tls(
    host: ipaddress.IPv4Address, puerto: int, *, tiempo_limite: float
) -> InfoTLS:
    """Negocia TLS contra ``host``:``puerto`` y devuelve version, cifrado y certificado."""
    host_texto = str(host)
    version_protocolo: str | None = None
    suite_cifrado: str | None = None
    cert_der: bytes | None = None
    confiable = True
    error_confianza: str | None = None

    contexto_verificado = ssl.create_default_context()
    try:
        with socket.create_connection((host_texto, puerto), timeout=tiempo_limite) as sock:
            with contexto_verificado.wrap_socket(sock, server_hostname=host_texto) as tls_sock:
                version_protocolo = tls_sock.version()
                cifrado = tls_sock.cipher()
                suite_cifrado = cifrado[0] if cifrado else None
                cert_der = tls_sock.getpeercert(binary_form=True)
    except ssl.SSLCertVerificationError as exc:
        confiable = False
        error_confianza = f"La cadena de confianza o el nombre de host no son validos: {exc}"
    except ssl.SSLError as exc:
        confiable = False
        error_confianza = f"Error TLS: {exc}"
    except (TimeoutError, OSError) as exc:
        raise ErrorAuditoriaWeb(
            f"No se pudo establecer una conexion TLS con {host_texto}:{puerto}: {exc}"
        ) from exc

    if cert_der is None:
        # La conexion verificada fallo por la confianza/el nombre, no por la red: se
        # repite SOLO para leer los bytes del certificado y poder mostrar sus metadatos
        # (fecha de vencimiento, emisor...). El resultado sigue marcado como no confiable.
        contexto_diagnostico = ssl.create_default_context()
        contexto_diagnostico.check_hostname = False
        contexto_diagnostico.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host_texto, puerto), timeout=tiempo_limite) as sock:
                with contexto_diagnostico.wrap_socket(
                    sock, server_hostname=host_texto
                ) as tls_sock:
                    version_protocolo = version_protocolo or tls_sock.version()
                    cifrado = tls_sock.cipher()
                    suite_cifrado = suite_cifrado or (cifrado[0] if cifrado else None)
                    cert_der = tls_sock.getpeercert(binary_form=True)
        except (TimeoutError, ssl.SSLError, OSError) as exc:
            if error_confianza is None:
                error_confianza = f"No se pudo leer el certificado: {exc}"

    certificado = None
    if cert_der is not None:
        certificado = _analizar_certificado_der(
            cert_der, host, confiable=confiable, error_confianza=error_confianza
        )
    elif error_confianza is not None:
        certificado = InfoCertificado(
            sujeto=None,
            emisor=None,
            no_antes=None,
            no_despues=None,
            nombres_alternativos=(),
            coincide_con_host=None,
            confiable=False,
            error_confianza=error_confianza,
        )

    return InfoTLS(
        version_protocolo=version_protocolo, suite_cifrado=suite_cifrado, certificado=certificado
    )


def evaluar_tls(info: InfoTLS | None, *, esquema: str) -> list[Hallazgo]:
    """Convierte ``InfoTLS`` en hallazgos explicados en espanol, con severidad justificada."""
    if esquema != "https":
        return [
            Hallazgo(
                categoria="tls",
                id_="tls-no-aplica",
                nombre="Cifrado en transito (TLS)",
                significado="TLS cifra el trafico entre el cliente y el servidor.",
                proposito="Evitar que un tercero en la red pueda leer o alterar la comunicacion.",
                valor_detectado="El objetivo se audito por HTTP, sin TLS.",
                severidad="media",
                estado="No aplica",
                riesgo=(
                    "El trafico HTTP viaja en texto claro: cualquiera con acceso a la red "
                    "puede leerlo o modificarlo."
                ),
                recomendacion=(
                    "Si este servicio maneja datos sensibles, ofrece tambien HTTPS y "
                    "considera redirigir HTTP a HTTPS."
                ),
                referencia="https://developer.mozilla.org/docs/Web/Security/Transport_Layer_Security",
            )
        ]

    if info is None:
        return [
            Hallazgo(
                categoria="tls",
                id_="tls-sin-datos",
                nombre="Cifrado en transito (TLS)",
                significado="TLS cifra el trafico entre el cliente y el servidor.",
                proposito="Evitar que un tercero en la red pueda leer o alterar la comunicacion.",
                valor_detectado=None,
                severidad="media",
                estado="Sin datos",
                riesgo="No se pudo completar el analisis TLS del objetivo.",
                recomendacion="Repite el analisis; si persiste, revisa la conectividad de red.",
                referencia="https://developer.mozilla.org/docs/Web/Security/Transport_Layer_Security",
            )
        ]

    hallazgos: list[Hallazgo] = []

    protocolo = info.version_protocolo
    severidad_protocolo: Severidad = (
        "alta" if protocolo in _PROTOCOLOS_OBSOLETOS else "info"
    )
    hallazgos.append(
        Hallazgo(
            categoria="tls",
            id_="tls-protocolo",
            nombre="Version de TLS negociada",
            significado="La version del protocolo TLS que el servidor acepto usar.",
            proposito="Las versiones antiguas (TLS 1.0/1.1, SSLv3) tienen debilidades conocidas.",
            valor_detectado=protocolo or "desconocida",
            severidad=severidad_protocolo,
            estado="Obsoleta" if severidad_protocolo == "alta" else "Vigente",
            riesgo=(
                "Las versiones antiguas de TLS son vulnerables a ataques conocidos "
                "(p. ej. POODLE, BEAST) y deberian desactivarse."
                if severidad_protocolo == "alta"
                else "Ninguno: la version negociada es una de las recomendadas actualmente."
            ),
            recomendacion=(
                "Desactiva TLS 1.0/1.1 y SSLv3 en el servidor; exige TLS 1.2 como minimo "
                "(TLS 1.3 preferido)."
                if severidad_protocolo == "alta"
                else "Ninguna accion necesaria."
            ),
            referencia="https://ssl-config.mozilla.org/",
        )
    )

    hallazgos.append(
        Hallazgo(
            categoria="tls",
            id_="tls-cifrado",
            nombre="Suite de cifrado negociada",
            significado="El conjunto de algoritmos de cifrado/autenticacion usado en la sesion.",
            proposito="Suites debiles reducen la proteccion real que ofrece TLS.",
            valor_detectado=info.suite_cifrado or "desconocida",
            severidad="info",
            estado="Informativo",
            riesgo=(
                "No evaluado automaticamente; revisa la suite contra las recomendaciones "
                "vigentes de Mozilla/OWASP si el objetivo es sensible."
            ),
            recomendacion="Preferir suites AEAD (AES-GCM, ChaCha20-Poly1305) con PFS.",
            referencia="https://ssl-config.mozilla.org/",
        )
    )

    cert = info.certificado
    if cert is None:
        return hallazgos

    ahora = datetime.now(UTC)
    if not cert.confiable:
        hallazgos.append(
            Hallazgo(
                categoria="tls",
                id_="tls-confianza",
                nombre="Confianza del certificado",
                significado=(
                    "Si el certificado presentado es verificable mediante una cadena de "
                    "confianza reconocida y el nombre de host coincide."
                ),
                proposito="Evitar ataques de intermediario (MITM) con certificados falsos.",
                valor_detectado=cert.error_confianza or "No se pudo verificar la confianza.",
                severidad="alta",
                estado="No confiable",
                riesgo=(
                    "Un cliente que no valide TLS (o que el usuario fuerce a ignorar la "
                    "advertencia) queda expuesto a interceptacion del trafico."
                ),
                recomendacion=(
                    "Usa un certificado emitido por una autoridad de confianza publica (o "
                    "por la CA interna de la organizacion, distribuida a los clientes) y "
                    "verifica que el nombre coincida con el objetivo real."
                ),
                referencia="https://developer.mozilla.org/docs/Web/Security/Certificate_Transparency",
            )
        )
    else:
        hallazgos.append(
            Hallazgo(
                categoria="tls",
                id_="tls-confianza",
                nombre="Confianza del certificado",
                significado=(
                    "Si el certificado presentado es verificable mediante una cadena de "
                    "confianza reconocida y el nombre de host coincide."
                ),
                proposito="Evitar ataques de intermediario (MITM) con certificados falsos.",
                valor_detectado="Cadena de confianza y nombre de host verificados.",
                severidad="info",
                estado="Confiable",
                riesgo="Ninguno detectado.",
                recomendacion="Ninguna accion necesaria.",
                referencia="https://developer.mozilla.org/docs/Web/Security/Certificate_Transparency",
            )
        )

    if cert.no_despues is not None:
        dias_restantes = (cert.no_despues - ahora).days
        if dias_restantes < 0:
            severidad_vencimiento: Severidad = "alta"
            estado_vencimiento = "Vencido"
        elif dias_restantes <= 15:
            severidad_vencimiento = "alta"
            estado_vencimiento = "Por vencer"
        elif dias_restantes <= 30:
            severidad_vencimiento = "media"
            estado_vencimiento = "Por vencer"
        else:
            severidad_vencimiento = "info"
            estado_vencimiento = "Vigente"
        hallazgos.append(
            Hallazgo(
                categoria="tls",
                id_="tls-vencimiento",
                nombre="Vencimiento del certificado",
                significado="La fecha hasta la que el certificado es valido.",
                proposito="Un certificado vencido rompe la confianza del cliente en el servicio.",
                valor_detectado=(
                    f"Vence el {cert.no_despues.date().isoformat()} "
                    f"({dias_restantes} dias desde hoy)"
                ),
                severidad=severidad_vencimiento,
                estado=estado_vencimiento,
                riesgo=(
                    "Un certificado vencido provoca errores de confianza en los clientes y "
                    "puede interrumpir el servicio o incentivar a los usuarios a ignorar "
                    "advertencias de seguridad legitimas."
                    if severidad_vencimiento != "info"
                    else "Ninguno detectado."
                ),
                recomendacion=(
                    "Renueva el certificado antes de la fecha de vencimiento (idealmente con "
                    "renovacion automatica)."
                    if severidad_vencimiento != "info"
                    else "Ninguna accion necesaria."
                ),
                referencia="https://developer.mozilla.org/docs/Web/Security/Transport_Layer_Security",
            )
        )

    if cert.coincide_con_host is False:
        hallazgos.append(
            Hallazgo(
                categoria="tls",
                id_="tls-nombre-host",
                nombre="Coincidencia del nombre de host",
                significado=(
                    "Si la direccion IP auditada aparece en el certificado (como nombre "
                    "alternativo de tipo IP)."
                ),
                proposito="Evitar que un certificado valido para otro host se acepte aqui.",
                valor_detectado=(
                    f"Nombres alternativos del certificado: "
                    f"{', '.join(cert.nombres_alternativos) or '(ninguno)'}"
                ),
                severidad="alta",
                estado="No coincide",
                riesgo="El certificado no corresponde al objetivo auditado.",
                recomendacion=(
                    "Emite o configura un certificado que incluya esta direccion IP en sus "
                    "nombres alternativos (SAN), o audita el nombre de host correcto."
                ),
                referencia="https://developer.mozilla.org/docs/Web/Security/Certificate_Transparency",
            )
        )

    if cert.sujeto or cert.emisor:
        hallazgos.append(
            Hallazgo(
                categoria="tls",
                id_="tls-identidad",
                nombre="Identidad del certificado",
                significado="Sujeto y emisor declarados en el certificado.",
                proposito="Confirmar que el certificado fue emitido para el servicio esperado.",
                valor_detectado=f"Sujeto: {cert.sujeto or '-'} | Emisor: {cert.emisor or '-'}",
                severidad="info",
                estado=(
                    "Metadatos confirmados"
                    if cert.confiable
                    else "Metadatos leidos sin verificar la cadena de confianza"
                ),
                riesgo="Ninguno: informativo.",
                recomendacion="Ninguna accion necesaria.",
                referencia="https://developer.mozilla.org/docs/Web/Security/Certificate_Transparency",
            )
        )

    return hallazgos
