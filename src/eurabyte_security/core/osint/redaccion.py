"""Minimizacion de datos personales en exportaciones/vistas OSINT.

Distinto de ``core/redaccion.py`` (oculta SECRETOS -- tokens, contrasenas, claves --
en URLs y texto libre de herramientas externas): este modulo oculta PARCIALMENTE un
identificador personal (correo, telefono) que el propio usuario introdujo como
objetivo, para que una exportacion o vista con "minimizacion" activada no muestre el
dato completo en claro, sin dejar de ser reconocible para quien ya conoce el objetivo
original. Nunca se aplica a los hallazgos en si (esos conservan su contenido real para
quien tiene acceso al proyecto): es una opcion explicita para quien exporta/comparte un
informe con un publico mas amplio (ver seccion 7 de la especificacion del modulo).
"""

from __future__ import annotations

VALOR_OCULTO = "***"


def enmascarar_correo(correo: str) -> str:
    """'usuario@ejemplo.com' -> 'u***o@ejemplo.com'. Conserva el dominio completo."""
    local, _, dominio = correo.partition("@")
    if not dominio:
        return VALOR_OCULTO
    if len(local) <= 2:
        local_enmascarado = VALOR_OCULTO
    else:
        local_enmascarado = f"{local[0]}{VALOR_OCULTO}{local[-1]}"
    return f"{local_enmascarado}@{dominio}"


def enmascarar_telefono(e164: str) -> str:
    """'+573001234567' -> '+57********67'. Conserva el prefijo de pais y los 2 ultimos digitos."""
    if not e164.startswith("+") or len(e164) < 6:
        return VALOR_OCULTO
    # Prefijo de pais: hasta 3 digitos tras el '+' (E.164 admite codigos de 1 a 3
    # digitos); se usan los primeros 3 como aproximacion visible, sin pretender
    # identificar el codigo real de pais (eso exigiria la tabla completa de
    # prefijos, que 'phonenumbers' ya resuelve en core/osint/validacion.py).
    prefijo = e164[:3]
    sufijo = e164[-2:]
    relleno = "*" * max(0, len(e164) - len(prefijo) - len(sufijo))
    return f"{prefijo}{relleno}{sufijo}"


def enmascarar_usuario(usuario: str) -> str:
    if len(usuario) <= 2:
        return VALOR_OCULTO
    return f"{usuario[0]}{VALOR_OCULTO}{usuario[-1]}"


_ENMASCARADORES = {
    "correo": enmascarar_correo,
    "telefono": enmascarar_telefono,
    "usuario": enmascarar_usuario,
}


def minimizar_objetivo(tipo_objetivo: str, objetivo: str) -> str:
    """Aplica el enmascarado correspondiente al tipo de objetivo; 'dominio' no se oculta
    (se trata como informacion corporativa, no personal, ver core/osint/validacion.py)."""
    enmascarador = _ENMASCARADORES.get(tipo_objetivo)
    return enmascarador(objetivo) if enmascarador else objetivo
