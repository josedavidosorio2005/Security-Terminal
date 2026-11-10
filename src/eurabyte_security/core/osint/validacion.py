"""Validacion de objetivos OSINT y autorizacion sobre datos personales.

Punto de control de seguridad/privacidad del modulo OSINT: ningun objetivo mal formado
llega a una fuente externa, y ninguna investigacion sobre un correo, telefono o nombre
de usuario (datos potencialmente personales) se ejecuta sin una confirmacion explicita
de autorizacion (``verificar_autorizacion_datos_personales``). Un dominio/empresa no
pasa por esta segunda comprobacion: se trata como informacion corporativa, no personal,
igual que el resto de AST trata el alcance autorizado de un proyecto.

Este modulo es deliberadamente independiente de ``core/validation.py`` y
``core/objetivo.py`` (que validan IPv4/URLs de un objetivo de red ya autorizado en el
alcance de un proyecto): un dominio OSINT no implica ningun trafico de red activo
contra el, solo contra fuentes publicas de terceros (DNS, RDAP, Certificate
Transparency...), por lo que no tiene sentido reutilizar esas validaciones ni su
nocion de alcance.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import phonenumbers
from phonenumbers import NumberParseException, PhoneNumberFormat, PhoneNumberType

from eurabyte_security.core.errores import ErrorAutorizacionOSINTRequerida, ErrorValidacion

TIPOS_OBJETIVO_OSINT: tuple[str, ...] = ("dominio", "correo", "telefono", "usuario")

# Dominio/empresa se trata como informacion corporativa (como el alcance autorizado de
# un proyecto); correo, telefono y usuario pueden identificar a una persona concreta y
# exigen la confirmacion explicita de autorizacion antes de consultar nada (ver
# ``verificar_autorizacion_datos_personales``).
TIPOS_CON_DATOS_PERSONALES: frozenset[str] = frozenset({"correo", "telefono", "usuario"})

LONGITUD_MAXIMA_CORREO = 254
LONGITUD_MAXIMA_LOCAL_CORREO = 64

# Nombre de dominio: etiquetas alfanumericas (guiones internos, nunca al borde), 1-63
# caracteres cada una, dominio completo hasta 253 -- misma forma que exige la RFC
# 1035/1123. Definicion propia (no se importa de ``core/objetivo.py``, que la mantiene
# privada): ``core/osint`` no depende de otros submodulos de validacion de red.
_RE_DOMINIO = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)

# Parte local de un correo (antes de la '@'): caracteres permitidos por RFC 5321 sin los
# casos especiales de cadena entre comillas (poco usados y con alto riesgo de inyeccion
# si se interpolan sin cuidado en una URL o un nombre de archivo de evidencia).
_RE_LOCAL_CORREO = re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$"
)

# Nombre de usuario: letras, numeros, puntos, guiones y guiones bajos -- cubre los
# formatos de GitHub/GitLab/la mayoria de redes sociales sin ser mas permisivo de lo
# necesario (ver ``integrations/osint/perfiles_publicos.py``).
_RE_USUARIO = re.compile(r"^[A-Za-z0-9_.-]{1,39}$")

_ETIQUETAS_TIPO_TELEFONO: dict[int, str] = {
    PhoneNumberType.MOBILE: "movil",
    PhoneNumberType.FIXED_LINE: "fijo",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "fijo_o_movil",
    PhoneNumberType.TOLL_FREE: "gratuito",
    PhoneNumberType.PREMIUM_RATE: "tarifa_premium",
    PhoneNumberType.SHARED_COST: "costo_compartido",
    PhoneNumberType.VOIP: "voip",
    PhoneNumberType.PERSONAL_NUMBER: "numero_personal",
    PhoneNumberType.PAGER: "radiomensaje",
    PhoneNumberType.UNKNOWN: "desconocido",
}


def requiere_autorizacion_datos_personales(tipo_objetivo: str) -> bool:
    return tipo_objetivo in TIPOS_CON_DATOS_PERSONALES


def verificar_autorizacion_datos_personales(tipo_objetivo: str, autorizado: bool) -> None:
    """Exige la confirmacion explicita del usuario antes de investigar datos personales.

    No sustituye a la autorizacion de alcance de un escaneo de red (``ErrorFueraDeAlcance``):
    es una confirmacion distinta, sobre si el objetivo (una cuenta, un telefono, un nombre
    de usuario) es propio o su revision esta autorizada, independiente de cualquier
    proyecto o alcance de red.
    """
    if requiere_autorizacion_datos_personales(tipo_objetivo) and not autorizado:
        raise ErrorAutorizacionOSINTRequerida(
            f"La investigacion de tipo '{tipo_objetivo}' puede exponer datos personales: "
            "confirma explicitamente que el objetivo es propio o que su revision esta "
            "autorizada antes de continuar (--autorizo en la CLI, o la casilla de "
            "autorizacion en la interfaz visual)."
        )


def validar_dominio_osint(texto: str) -> str:
    """Valida un nombre de dominio para OSINT (sin esquema, sin ruta)."""
    texto = texto.strip().rstrip(".")
    if not texto:
        raise ErrorValidacion("El dominio no puede estar vacio.")
    if "://" in texto:
        raise ErrorValidacion(
            f"'{texto}' incluye un esquema; indica solo el dominio (ej. 'ejemplo.com')."
        )
    if "/" in texto or "@" in texto:
        raise ErrorValidacion(f"'{texto}' no es un dominio valido (sin rutas ni '@').")
    if not _RE_DOMINIO.match(texto):
        raise ErrorValidacion(f"'{texto}' no es un nombre de dominio valido.")
    return texto.lower()


@dataclass(frozen=True, slots=True)
class CorreoOSINT:
    correo: str
    local: str
    dominio: str


def validar_correo_osint(texto: str) -> CorreoOSINT:
    """Valida la sintaxis de un correo y el dominio de su parte derecha."""
    texto = texto.strip()
    if not texto:
        raise ErrorValidacion("El correo no puede estar vacio.")
    if len(texto) > LONGITUD_MAXIMA_CORREO:
        raise ErrorValidacion(
            f"El correo no puede superar los {LONGITUD_MAXIMA_CORREO} caracteres."
        )
    if texto.count("@") != 1:
        raise ErrorValidacion(f"'{texto}' no es un correo valido: debe contener un unico '@'.")

    local, _, dominio = texto.partition("@")
    if not local or len(local) > LONGITUD_MAXIMA_LOCAL_CORREO or not _RE_LOCAL_CORREO.match(local):
        raise ErrorValidacion(f"'{texto}' no es un correo valido: la parte local no es valida.")

    dominio_validado = validar_dominio_osint(dominio)
    return CorreoOSINT(correo=f"{local}@{dominio_validado}", local=local, dominio=dominio_validado)


@dataclass(frozen=True, slots=True)
class TelefonoOSINT:
    e164: str
    region: str | None
    tipo_numero: str


def validar_telefono_osint(texto: str, region_por_defecto: str | None = None) -> TelefonoOSINT:
    """Normaliza un numero de telefono a E.164 y describe su region/tipo.

    Si ``texto`` no empieza por '+' (formato internacional explicito), hace falta
    ``region_por_defecto`` (codigo ISO de 2 letras, ej. 'CO') para interpretar un numero
    en formato nacional; sin ninguna de las dos cosas se rechaza en vez de adivinar.
    Nunca afirma que el prefijo identifica con certeza al operador actual: solo expone
    region/tipo de numero segun los metadatos publicos de numeracion (``phonenumbers``,
    el mismo catalogo que usa libphonenumber), nunca el titular real de la linea.
    """
    texto = texto.strip()
    if not texto:
        raise ErrorValidacion("El numero de telefono no puede estar vacio.")
    if not texto.startswith("+") and not region_por_defecto:
        raise ErrorValidacion(
            f"'{texto}' no esta en formato internacional (debe empezar por '+'). "
            "Indica el numero en formato internacional o especifica una region por defecto."
        )

    try:
        numero = phonenumbers.parse(texto, region_por_defecto)
    except NumberParseException as exc:
        raise ErrorValidacion(f"'{texto}' no es un numero de telefono valido: {exc}") from exc

    if not phonenumbers.is_valid_number(numero):
        raise ErrorValidacion(f"'{texto}' no es un numero de telefono valido.")

    e164 = phonenumbers.format_number(numero, PhoneNumberFormat.E164)
    region = phonenumbers.region_code_for_number(numero)
    tipo = _ETIQUETAS_TIPO_TELEFONO.get(phonenumbers.number_type(numero), "desconocido")
    return TelefonoOSINT(e164=e164, region=region, tipo_numero=tipo)


def validar_usuario_osint(texto: str) -> str:
    """Valida un nombre de usuario (sin red social especifica asociada todavia)."""
    texto = texto.strip()
    if not texto:
        raise ErrorValidacion("El nombre de usuario no puede estar vacio.")
    if not _RE_USUARIO.match(texto):
        raise ErrorValidacion(
            f"'{texto}' no es un nombre de usuario valido (letras, numeros, puntos, "
            "guiones y guiones bajos; maximo 39 caracteres)."
        )
    return texto


def extraer_dominio_de_objetivo(tipo_objetivo: str, objetivo: str) -> str | None:
    """Deriva el dominio relevante de un objetivo ya validado, si aplica.

    Usado por las fuentes que solo saben consultar un dominio (DNS, RDAP, Certificate
    Transparency): para un objetivo de tipo 'correo' devuelve la parte del dominio; para
    'dominio' devuelve el propio objetivo; para 'telefono'/'usuario' no hay ningun
    dominio que derivar y devuelve ``None`` (esas fuentes se omiten para ese objetivo,
    ver ``integrations/osint/registro.py``).
    """
    if tipo_objetivo == "dominio":
        return objetivo
    if tipo_objetivo == "correo" and "@" in objetivo:
        return objetivo.rsplit("@", 1)[1]
    return None
