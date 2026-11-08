"""Adaptador de Nuclei (Fase 3, Paso 4): plantillas HTTP aprobadas de bajo impacto.

A diferencia de Nmap, Nuclei puede ejecutar practicamente cualquier cosa segun la
plantilla que se le indique (plantillas de la comunidad incluyen protocolos de red,
DNS, ejecucion de codigo, fuzzing, pruebas OAST/Interactsh contra un servidor de
terceros...). AST **nunca** acepta una ruta de plantilla arbitraria: solo permite
elegir, por identificador, entre un catalogo reducido de plantillas que la propia
AURABYTE escribio, reviso y distribuye junto con el paquete (``plantillas_nuclei/``).

Cada plantilla del catalogo, ademas, se vuelve a validar estructuralmente en tiempo de
ejecucion (``validar_plantilla_estructura``) antes de usarla, con una politica de
**lista blanca estricta** (no solo "lista negra" de lo prohibido): solo se acepta la
forma exacta que las 5 plantillas aprobadas ya tienen (campos de nivel superior
conocidos, un unico bloque ``http`` con metodo GET, rutas exclusivamente relativas a
``{{BaseURL}}``, matchers de tipos conocidos); cualquier campo que AST no reconozca se
rechaza, aunque no este en ninguna lista negra concreta. Ademas, cada plantilla
aprobada tiene fijado un hash SHA-256 revisado (``InfoPlantillaNuclei.sha256``): si el
archivo en disco no coincide con ese hash, la ejecucion se rechaza. Actualizar ese hash
exige revisar de nuevo todo el contenido de la plantilla a mano -- no es un valor que
se recalcule automaticamente. Una plantilla no se considera segura solo por venir con
este paquete o por estar "firmada": si cualquiera de estas comprobaciones falla, la
ejecucion se rechaza con un error claro en vez de asumir que sigue siendo segura.

Para evitar una ventana entre "se valido este archivo" y "se le paso a Nuclei"
(TOCTOU), AST nunca entrega a Nuclei la ruta original del catalogo: lee el contenido
una sola vez, lo valida y escribe una copia nueva en un directorio temporal exclusivo
de esta ejecucion, y es esa copia (no el archivo instalado) la que se pasa con ``-t``.

Aun con todo esto, Nuclei es un binario externo independiente: AST no puede garantizar
en tiempo de ejecucion que una plantilla aprobada hoy nunca abra una conexion fuera del
objetivo autorizado (solo que, al escribirla, no se le dio ningun motivo para hacerlo).
Por eso el catalogo se mantiene deliberadamente pequeno y cada plantilla hace como
maximo un puñado de peticiones GET de solo lectura contra ``{{BaseURL}}`` del objetivo.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import yaml

from eurabyte_security.core.errores import (
    ErrorEscaneoCancelado,
    ErrorIntegracion,
    ErrorParametrosIntegracion,
)
from eurabyte_security.core.validation import ObjetivoNuclei, validar_objetivo_nuclei
from eurabyte_security.integrations.base import AdaptadorExterno

TIEMPO_LIMITE_MINIMO = 5.0
TIEMPO_LIMITE_MAXIMO = 120.0
TIEMPO_LIMITE_POR_DEFECTO = 60.0

# Tiempo de espera por peticion HTTP individual que Nuclei hace internamente (su propio
# -timeout): acotado y fijo, no configurable desde fuera, para mantener el riesgo bajo.
_TIMEOUT_POR_PETICION_NUCLEI = 10
# Limite de peticiones por segundo que Nuclei puede hacer contra el objetivo. Deliberadamente
# bajo: el catalogo tiene muy pocas plantillas, no hace falta velocidad.
_LIMITE_PETICIONES_POR_SEGUNDO = 10

_DIRECTORIO_PLANTILLAS = Path(__file__).parent / "plantillas_nuclei"

# --- Validacion estructural de plantillas: lista blanca + lista negra de refuerzo ---

# Bloques de protocolo que una plantilla de AST nunca puede declarar: cualquiera de estos
# abre la puerta a algo que no es "una peticion GET de solo lectura contra el objetivo"
# (red/DNS/archivos locales/ejecucion de codigo/navegador headless/encadenado de pasos).
# En el formato de plantilla de Nuclei, el protocolo es siempre una clave de nivel
# superior (hermana de "id"/"info"), asi que esta lista queda ademas cubierta por
# _CLAVES_NIVEL_SUPERIOR_PERMITIDAS; se mantiene por separado solo para dar un mensaje
# de error mas especifico cuando el problema es, en concreto, un protocolo no HTTP.
_CLAVES_PROTOCOLO_PROHIBIDAS = frozenset(
    {"dns", "file", "network", "headless", "code", "ssl", "workflows", "javascript"}
)
# Fragmentos que, si aparecen en el YAML serializado de la plantilla, indican que podria
# alcanzar un destino distinto del propio objetivo o cambiar el comportamiento esperado.
# Defensa en profundidad adicional a la lista blanca de campos: cubre, por ejemplo, un
# valor inesperado dentro de un campo que si esta permitido.
_FRAGMENTOS_PROHIBIDOS = (
    "interactsh",
    "oast",
    "redirects: true",
    "follow-redirects: true",
    "unsafe: true",
    "req-condition: true",
)

# Lista blanca estricta: solo se acepta exactamente esta forma (la que ya tienen las 5
# plantillas aprobadas). Cualquier campo fuera de estos conjuntos se rechaza, aunque no
# aparezca en ninguna lista negra: "si no se reconoce, no se ejecuta".
_CLAVES_NIVEL_SUPERIOR_PERMITIDAS = frozenset({"id", "info", "http"})
_CLAVES_INFO_PERMITIDAS = frozenset({"name", "author", "severity", "description", "tags"})
_CLAVES_BLOQUE_HTTP_PERMITIDAS = frozenset({"method", "path", "matchers-condition", "matchers"})
_CLAVES_MATCHER_PERMITIDAS = frozenset(
    {"type", "part", "status", "words", "word", "regex", "condition"}
)
_TIPOS_MATCHER_PERMITIDOS = frozenset({"status", "word", "regex"})
_CONDICIONES_MATCHERS_PERMITIDAS = frozenset({"and", "or"})
# Como mucho un bloque HTTP (las 5 plantillas aprobadas tienen exactamente uno) y como
# mucho un puñado de rutas (peticiones) dentro de ese bloque.
_MAXIMO_BLOQUES_HTTP = 1
_MAXIMO_RUTAS_POR_PLANTILLA = 4
# Una ruta solo puede referirse al propio objetivo: empieza exactamente por
# "{{BaseURL}}" seguido de un segmento relativo con un conjunto reducido de caracteres
# seguros. Nunca una URL absoluta a otro host (nada de "http://", "https://" ni "@" de
# credenciales) ni ninguna otra variable de plantilla.
_RUTA_RELATIVA_RE = re.compile(r"^\{\{BaseURL\}\}(/[A-Za-z0-9_\-./]*)?$")

# --- Limites defensivos sobre la salida JSONL (es, en ultima instancia, la salida de
# --- un binario externo: nunca se trata como si fuera de total confianza). ---
_TAMANO_MAXIMO_JSONL_BYTES = 10 * 1024 * 1024  # 10 MiB
_LONGITUD_MAXIMA_LINEA_JSONL = 200_000
_LONGITUD_MAXIMA_CAMPO_CORTO = 200
_LONGITUD_MAXIMA_CAMPO_LARGO = 300

# --- Opciones de la linea de comandos de Nuclei ---

# Requeridas: si 'nuclei -h' no las reconoce, no se intenta ejecutar nada (version
# demasiado antigua o distinta de lo esperado).
_OPCIONES_REQUERIDAS: tuple[str, ...] = (
    "-target",
    "-t",
    "-jsonl",
    "-timeout",
    "-rate-limit",
    "-duc",
    "-ni",
    "-silent",
    "-nc",
)
# Opcionales de aislamiento: refuerzan que Nuclei no cargue una configuracion, perfil,
# proxy o cabeceras adicionales que el usuario ya tuviera guardados en su sistema, ni
# siga redirecciones. Nunca se asume que una version de Nuclei las reconoce: solo se
# agregan al comando si 'nuclei -h' confirma que existen en la version instalada. Si
# ninguna esta disponible, el analisis sigue adelante igual (son defensa en
# profundidad adicional, no la unica proteccion: el aislamiento real tambien viene del
# entorno de proceso propio, ver '_variables_entorno_aisladas', y de que AST solo pasa
# rutas de plantilla explicitas con '-t', nunca el directorio de plantillas por
# defecto de Nuclei).
_OPCION_CONFIG = "-config"
_OPCIONES_SIN_REDIRECCION = ("-dr", "-disable-redirects")
_OPCION_SIN_CABECERAS_EXTRA = "-nh"
_OPCION_SIN_STDIN = "-no-stdin"

_VARIABLES_PROXY_A_LIMPIAR = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
)


@dataclass(frozen=True, slots=True)
class InfoPlantillaNuclei:
    """Una plantilla aprobada del catalogo de AST (nunca una ruta arbitraria).

    ``version`` es propia de AST (no de Nuclei, cuyo formato de plantilla no tiene un
    campo de version oficial): identifica la revision de ESTA plantilla dentro del
    catalogo, para poder saber con que version se genero un hallazgo ya guardado si la
    plantilla cambia mas adelante. Se incrementa a mano cada vez que se edita el .yaml.

    ``sha256`` es el hash del contenido exacto del archivo en el momento en que se
    reviso y aprobo: si el archivo instalado no coincide, ``validar_plantilla_estructura``
    rechaza la ejecucion aunque el YAML siga siendo estructuralmente valido. Cambiar
    este valor es, en si mismo, una decision que exige volver a revisar todo el
    contenido de la plantilla -- no es algo que deba recalcularse sin mirar el diff.
    """

    id_: str
    nombre: str
    descripcion: str
    severidad_esperada: str
    etiquetas: tuple[str, ...]
    archivo: str
    recomendacion: str
    sha256: str
    version: str = "1"


# Catalogo de plantillas aprobadas. El id_ es lo unico que el usuario puede indicar
# (`--plantillas id1,id2`); la ruta real al archivo vive solo aqui, nunca en la entrada
# del usuario. Ver cada .yaml en plantillas_nuclei/ para el detalle de la comprobacion.
PLANTILLAS_APROBADAS: dict[str, InfoPlantillaNuclei] = {
    "exposed-env-file": InfoPlantillaNuclei(
        id_="exposed-env-file",
        nombre="Archivo .env expuesto",
        descripcion=(
            "Comprueba si el archivo .env (variables de entorno, habitualmente con "
            "credenciales) es accesible publicamente en la raiz del sitio."
        ),
        severidad_esperada="alta",
        etiquetas=("exposure", "config"),
        archivo="exposed-env-file.yaml",
        recomendacion=(
            "Mueve el archivo .env fuera del directorio publico del servidor web (o "
            "bloquea su acceso explicitamente en la configuracion del servidor) y rota "
            "cualquier credencial que haya podido quedar expuesta."
        ),
        sha256="b2b138a4c05532ad84adeb585e1e2e6f56c4d0b52011a6011dcdd82d612fdb75",
    ),
    "exposed-git-config": InfoPlantillaNuclei(
        id_="exposed-git-config",
        nombre="Archivo .git/config expuesto",
        descripcion=(
            "Comprueba si el archivo de configuracion de un repositorio Git "
            "(.git/config) es accesible publicamente."
        ),
        severidad_esperada="alta",
        etiquetas=("exposure", "config"),
        archivo="exposed-git-config.yaml",
        recomendacion=(
            "Bloquea el acceso publico al directorio .git (regla del servidor web) o, "
            "mejor aun, no despliegues el directorio .git en el servidor de produccion."
        ),
        sha256="fd847d7afddeaa37648b2ce38fe3507aa197fe57b2a8a39e984ff65e8ff1c4a4",
    ),
    "directory-listing": InfoPlantillaNuclei(
        id_="directory-listing",
        nombre="Listado de directorio habilitado",
        descripcion="Comprueba si el servidor devuelve un listado de archivos en la raiz.",
        severidad_esperada="baja",
        etiquetas=("misconfig",),
        archivo="directory-listing.yaml",
        recomendacion=(
            "Desactiva el listado de directorios en la configuracion del servidor web "
            "(p. ej. 'Options -Indexes' en Apache) salvo que sea explicitamente necesario."
        ),
        sha256="bf450c526c705607ed0acdc362b1b2b9b6ad1c87eee794194b17bc8f8c4f24ce",
    ),
    "server-version-disclosure": InfoPlantillaNuclei(
        id_="server-version-disclosure",
        nombre="Divulgacion de version del servidor",
        descripcion=(
            "Comprueba si la cabecera 'Server' incluye un numero de version especifico "
            "(nginx, Apache, IIS)."
        ),
        severidad_esperada="info",
        etiquetas=("exposure",),
        archivo="server-version-disclosure.yaml",
        recomendacion=(
            "Configura el servidor para ocultar o genericizar la cabecera 'Server' "
            "(p. ej. 'ServerTokens Prod' en Apache, 'server_tokens off' en nginx)."
        ),
        sha256="3dba8e20281d82199874e340d1f4bb60e7b14b60ca2b9a2c33a969dab115a26b",
    ),
    "exposed-phpinfo": InfoPlantillaNuclei(
        id_="exposed-phpinfo",
        nombre="phpinfo() expuesto",
        descripcion="Comprueba si un script de diagnostico phpinfo() es accesible publicamente.",
        severidad_esperada="media",
        etiquetas=("exposure", "config"),
        archivo="exposed-phpinfo.yaml",
        recomendacion=(
            "Elimina el script de diagnostico del entorno de produccion, o restringe "
            "su acceso a direcciones IP de administracion conocidas."
        ),
        sha256="d6b859f0759f9b3f6707929c80d40fe8e305d497e4225e5047b92735ddd09cab",
    ),
}


@dataclass(frozen=True, slots=True)
class HallazgoNuclei:
    plantilla_id: str
    plantilla_nombre: str
    severidad: str
    descripcion: str
    evidencia: str


@dataclass(frozen=True, slots=True)
class ResultadoNuclei:
    objetivo: str
    hallazgos: list[HallazgoNuclei]
    plantillas_ejecutadas: tuple[str, ...]
    lineas_jsonl_descartadas: int


def ruta_plantilla(plantilla_id: str) -> Path:
    info = PLANTILLAS_APROBADAS.get(plantilla_id)
    if info is None:
        raise ErrorParametrosIntegracion(
            f"'{plantilla_id}' no es una plantilla aprobada. Usa 'est nuclei plantillas' "
            "para ver el catalogo disponible."
        )
    return _DIRECTORIO_PLANTILLAS / info.archivo


def _validar_estructura_texto(
    texto: str, *, nombre_archivo: str, plantilla_id_esperado: str | None
) -> None:
    try:
        datos = yaml.safe_load(texto)
    except yaml.YAMLError as exc:
        raise ErrorIntegracion(
            f"La plantilla '{nombre_archivo}' no es un YAML valido: {exc}"
        ) from exc

    if not isinstance(datos, dict):
        raise ErrorIntegracion(f"La plantilla '{nombre_archivo}' no tiene la forma esperada.")

    claves = set(datos.keys())

    protocolos_prohibidos = claves & _CLAVES_PROTOCOLO_PROHIBIDAS
    if protocolos_prohibidos:
        raise ErrorIntegracion(
            f"La plantilla '{nombre_archivo}' declara un protocolo no permitido "
            f"({', '.join(sorted(protocolos_prohibidos))}); solo se permiten "
            "plantillas HTTP simples."
        )

    claves_desconocidas = claves - _CLAVES_NIVEL_SUPERIOR_PERMITIDAS
    if claves_desconocidas:
        raise ErrorIntegracion(
            f"La plantilla '{nombre_archivo}' declara campos de nivel superior que AST "
            f"no reconoce ({', '.join(sorted(claves_desconocidas))}): podrian alterar su "
            "ejecucion de una forma que no se puede validar, asi que se rechaza."
        )

    if "http" not in claves:
        raise ErrorIntegracion(
            f"La plantilla '{nombre_archivo}' no declara un bloque 'http': no hay nada seguro "
            "que ejecutar en ella."
        )

    if plantilla_id_esperado is not None:
        id_declarado = datos.get("id")
        if id_declarado != plantilla_id_esperado:
            raise ErrorIntegracion(
                f"La plantilla '{nombre_archivo}' declara el id '{id_declarado}', pero el "
                f"catalogo de AST esperaba '{plantilla_id_esperado}': el archivo y el "
                "catalogo ya no coinciden, se rechaza la ejecucion."
            )

    info = datos.get("info")
    if isinstance(info, dict):
        claves_info_desconocidas = set(info.keys()) - _CLAVES_INFO_PERMITIDAS
        if claves_info_desconocidas:
            raise ErrorIntegracion(
                f"La plantilla '{nombre_archivo}' declara campos de 'info' que AST no "
                f"reconoce ({', '.join(sorted(claves_info_desconocidas))})."
            )

    texto_bajo = texto.lower()
    fragmentos_encontrados = [f for f in _FRAGMENTOS_PROHIBIDOS if f in texto_bajo]
    if fragmentos_encontrados:
        raise ErrorIntegracion(
            f"La plantilla '{nombre_archivo}' contiene elementos no permitidos "
            f"({', '.join(fragmentos_encontrados)}): podria seguir redirecciones, "
            "contactar un servidor externo (OAST) o comportarse de forma insegura."
        )

    bloques_http = datos.get("http")
    if not isinstance(bloques_http, list) or not bloques_http:
        raise ErrorIntegracion(f"La plantilla '{nombre_archivo}' no define ninguna peticion HTTP.")
    if len(bloques_http) > _MAXIMO_BLOQUES_HTTP:
        raise ErrorIntegracion(
            f"La plantilla '{nombre_archivo}' declara {len(bloques_http)} bloques HTTP; "
            f"el catalogo aprobado de AST permite como maximo {_MAXIMO_BLOQUES_HTTP}."
        )

    total_rutas = 0
    for bloque in bloques_http:
        if not isinstance(bloque, dict):
            raise ErrorIntegracion(
                f"La plantilla '{nombre_archivo}' tiene un bloque HTTP con una forma inesperada."
            )

        claves_bloque_desconocidas = set(bloque.keys()) - _CLAVES_BLOQUE_HTTP_PERMITIDAS
        if claves_bloque_desconocidas:
            raise ErrorIntegracion(
                f"La plantilla '{nombre_archivo}' declara campos que AST no reconoce en su "
                f"bloque HTTP ({', '.join(sorted(claves_bloque_desconocidas))}): el catalogo "
                "aprobado solo admite peticiones GET simples contra {{BaseURL}}."
            )

        metodo = str(bloque.get("method", "GET")).upper()
        if metodo != "GET":
            raise ErrorIntegracion(
                f"La plantilla '{nombre_archivo}' usa el metodo '{metodo}'; AST solo permite "
                "peticiones GET de solo lectura en su catalogo aprobado."
            )

        rutas = bloque.get("path")
        if isinstance(rutas, str):
            rutas = [rutas]
        if not isinstance(rutas, list) or not rutas:
            raise ErrorIntegracion(
                f"La plantilla '{nombre_archivo}' no declara ninguna ruta en su bloque HTTP."
            )
        total_rutas += len(rutas)
        for ruta_valor in rutas:
            if not isinstance(ruta_valor, str) or not _RUTA_RELATIVA_RE.match(ruta_valor):
                raise ErrorIntegracion(
                    f"La plantilla '{nombre_archivo}' declara una ruta no permitida "
                    f"('{ruta_valor}'): solo se permiten rutas relativas que empiecen "
                    "exactamente por '{{BaseURL}}', sin URLs absolutas a otro servidor ni "
                    "ninguna otra variable de plantilla."
                )

        condicion = bloque.get("matchers-condition")
        if condicion is not None and condicion not in _CONDICIONES_MATCHERS_PERMITIDAS:
            raise ErrorIntegracion(
                f"La plantilla '{nombre_archivo}' declara una condicion de matchers no "
                f"permitida ('{condicion}')."
            )

        matchers = bloque.get("matchers")
        if matchers is not None:
            if not isinstance(matchers, list):
                raise ErrorIntegracion(
                    f"La plantilla '{nombre_archivo}' declara 'matchers' con una forma inesperada."
                )
            for matcher in matchers:
                if not isinstance(matcher, dict):
                    raise ErrorIntegracion(
                        f"La plantilla '{nombre_archivo}' declara un matcher con una forma "
                        "inesperada."
                    )
                claves_matcher_desconocidas = set(matcher.keys()) - _CLAVES_MATCHER_PERMITIDAS
                if claves_matcher_desconocidas:
                    raise ErrorIntegracion(
                        f"La plantilla '{nombre_archivo}' declara campos que AST no reconoce "
                        f"en un matcher ({', '.join(sorted(claves_matcher_desconocidas))})."
                    )
                tipo_matcher = matcher.get("type")
                if tipo_matcher not in _TIPOS_MATCHER_PERMITIDOS:
                    raise ErrorIntegracion(
                        f"La plantilla '{nombre_archivo}' usa un tipo de matcher no permitido "
                        f"('{tipo_matcher}'); solo se admiten "
                        f"{', '.join(sorted(_TIPOS_MATCHER_PERMITIDOS))}."
                    )

    if total_rutas > _MAXIMO_RUTAS_POR_PLANTILLA:
        raise ErrorIntegracion(
            f"La plantilla '{nombre_archivo}' declara {total_rutas} rutas (peticiones); el "
            f"catalogo aprobado de AST permite como maximo {_MAXIMO_RUTAS_POR_PLANTILLA}."
        )


def validar_plantilla_estructura(ruta: Path, plantilla_id_esperado: str | None = None) -> None:
    """Vuelve a comprobar, leyendo el archivo, que una plantilla es segura de ejecutar.

    No basta con que una plantilla este en ``PLANTILLAS_APROBADAS``: si alguien edito el
    archivo despues de instalar AST (por error o a proposito), esta comprobacion lo
    detecta y rechaza la ejecucion en vez de asumir que sigue siendo la misma plantilla
    de bajo impacto que se reviso originalmente. Si se indica ``plantilla_id_esperado``,
    tambien se comprueba que el campo ``id:`` del archivo coincida exactamente con el
    identificador del catalogo (ver ``_cargar_y_validar_plantilla``, que ademas verifica
    el hash SHA-256 aprobado antes de llegar aqui).
    """
    try:
        texto = ruta.read_text(encoding="utf-8")
    except OSError as exc:
        raise ErrorIntegracion(f"No se pudo leer la plantilla '{ruta.name}': {exc}") from exc
    _validar_estructura_texto(
        texto, nombre_archivo=ruta.name, plantilla_id_esperado=plantilla_id_esperado
    )


def _verificar_hash_plantilla(plantilla_id: str, texto: str, *, nombre_archivo: str) -> None:
    info = PLANTILLAS_APROBADAS[plantilla_id]
    hash_real = hashlib.sha256(texto.encode("utf-8")).hexdigest()
    if hash_real != info.sha256:
        raise ErrorIntegracion(
            f"La plantilla '{nombre_archivo}' no coincide con el hash SHA-256 revisado y "
            f"aprobado para '{plantilla_id}' (el archivo pudo haber sido modificado despues "
            "de instalar AST). Actualizar este hash exige revisar de nuevo todo el contenido "
            "de la plantilla; mientras tanto, se rechaza la ejecucion."
        )


def _cargar_y_validar_plantilla(plantilla_id: str) -> str:
    """Lee, verifica el hash aprobado y vuelve a validar estructuralmente una plantilla.

    Devuelve el TEXTO ya validado, no una ruta: quien lo ejecute debe escribir ese mismo
    texto en una copia nueva (ver ``AdaptadorNuclei.ejecutar``) antes de pasarsela a
    Nuclei, para no dejar una ventana entre "se valido este archivo" y "se ejecuto este
    archivo" (TOCTOU) en la que alguien pudiera sustituirlo en disco.
    """
    ruta = ruta_plantilla(plantilla_id)
    try:
        texto = ruta.read_text(encoding="utf-8")
    except OSError as exc:
        raise ErrorIntegracion(f"No se pudo leer la plantilla '{ruta.name}': {exc}") from exc
    _verificar_hash_plantilla(plantilla_id, texto, nombre_archivo=ruta.name)
    _validar_estructura_texto(texto, nombre_archivo=ruta.name, plantilla_id_esperado=plantilla_id)
    return texto


def _opciones_aislamiento_disponibles(ayuda: str, *, ruta_config_aislada: Path) -> list[str]:
    """Agrega opciones de aislamiento SOLO si 'nuclei -h' confirma que existen.

    Nunca se asume que una opcion esta disponible: si la version instalada no la
    reconoce, simplemente no se agrega (no es un error -- son opciones de refuerzo,
    la proteccion real viene del entorno de proceso aislado y de la validacion de
    plantillas, no de estas opciones).
    """
    extra: list[str] = []
    if _OPCION_CONFIG in ayuda:
        extra += [_OPCION_CONFIG, str(ruta_config_aislada)]
    for opcion in _OPCIONES_SIN_REDIRECCION:
        if opcion in ayuda:
            extra.append(opcion)
            break
    if _OPCION_SIN_CABECERAS_EXTRA in ayuda:
        extra.append(_OPCION_SIN_CABECERAS_EXTRA)
    if _OPCION_SIN_STDIN in ayuda:
        extra.append(_OPCION_SIN_STDIN)
    return extra


def _variables_entorno_aisladas(directorio_aislado: Path) -> dict[str, str]:
    """Construye el entorno con el que se invoca a Nuclei, aislado del perfil del usuario.

    Nuclei busca su configuracion y cache de plantillas en un directorio de
    configuracion del sistema operativo (HOME/.config en Linux/macOS, %AppData% en
    Windows) y respeta variables de proxy del entorno. AST nunca quiere que una
    configuracion, proxy o perfil que el usuario ya tenga guardado en su sistema (por
    ejemplo, cabeceras por defecto o un proxy corporativo) se aplique silenciosamente a
    un analisis que se supone controlado: se redirigen esas rutas a un directorio
    vacio, nuevo, dentro del directorio temporal de esta misma ejecucion, y se eliminan
    las variables de proxy del entorno con el que se lanza el proceso.
    """
    directorio_aislado.mkdir(parents=True, exist_ok=True)
    entorno = dict(os.environ)
    for variable in _VARIABLES_PROXY_A_LIMPIAR:
        entorno.pop(variable, None)
    for variable in list(entorno):
        if variable.upper().startswith("NUCLEI_"):
            entorno.pop(variable, None)
    ruta_texto = str(directorio_aislado)
    entorno["HOME"] = ruta_texto
    entorno["XDG_CONFIG_HOME"] = ruta_texto
    entorno["APPDATA"] = ruta_texto
    entorno["USERPROFILE"] = ruta_texto
    return entorno


class AdaptadorNuclei(AdaptadorExterno):
    """Ejecuta Nuclei contra un unico objetivo, solo con plantillas del catalogo aprobado."""

    nombre = "Nuclei"
    comando = "nuclei"
    argumentos_version = ("-version",)

    def verificar_opciones_compatibles(self) -> str:
        """Comprueba (via ``nuclei -h``) que la version instalada admite las opciones

        que AST necesita pasarle. Evita construir un comando con una opcion que una
        version muy antigua (o muy distinta) de Nuclei no reconozca. Devuelve el texto
        de ayuda completo para que ``ejecutar`` pueda decidir, con la misma consulta,
        que opciones de aislamiento opcionales tambien estan disponibles.
        """
        resultado = self._ejecutar_binario(["-h"], tiempo_limite=10.0)
        ayuda = (resultado.stdout or "") + (resultado.stderr or "")
        faltantes = [opcion for opcion in _OPCIONES_REQUERIDAS if opcion not in ayuda]
        if faltantes:
            raise ErrorIntegracion(
                "La version instalada de Nuclei no reconoce las siguientes opciones "
                f"requeridas: {', '.join(faltantes)}. Actualiza Nuclei e intenta de nuevo."
            )
        return ayuda

    def validar_parametros(
        self,
        *,
        objetivo: str,
        plantillas_ids: list[str],
        tiempo_limite: float = TIEMPO_LIMITE_POR_DEFECTO,
        **_kwargs: object,
    ) -> tuple[ObjetivoNuclei, list[str]]:
        componentes = validar_objetivo_nuclei(objetivo)
        if not plantillas_ids:
            raise ErrorParametrosIntegracion(
                "Debes indicar al menos una plantilla aprobada con --plantillas."
            )
        ids_unicos: list[str] = []
        for plantilla_id in plantillas_ids:
            if plantilla_id not in PLANTILLAS_APROBADAS:
                raise ErrorParametrosIntegracion(
                    f"'{plantilla_id}' no es una plantilla aprobada. Usa "
                    "'est nuclei plantillas' para ver el catalogo disponible."
                )
            if plantilla_id not in ids_unicos:
                ids_unicos.append(plantilla_id)
        if not (TIEMPO_LIMITE_MINIMO <= tiempo_limite <= TIEMPO_LIMITE_MAXIMO):
            raise ErrorParametrosIntegracion(
                f"El tiempo limite de Nuclei debe estar entre {TIEMPO_LIMITE_MINIMO:g} y "
                f"{TIEMPO_LIMITE_MAXIMO:g} segundos."
            )
        return componentes, ids_unicos

    def ejecutar(
        self,
        *,
        objetivo: str,
        plantillas_ids: list[str],
        tiempo_limite: float = TIEMPO_LIMITE_POR_DEFECTO,
        debe_cancelar: Callable[[], bool] | None = None,
    ) -> ResultadoNuclei:
        """Ejecuta Nuclei contra ``objetivo`` usando solo plantillas del catalogo aprobado.

        Nunca sigue redirecciones (no se pasa ``-fr``/``-fhr``, que por defecto estan
        desactivados en Nuclei) y desactiva explicitamente Interactsh/OAST (``-ni``) y la
        comprobacion de actualizaciones (``-duc``): AST nunca instala ni actualiza Nuclei
        ni sus plantillas automaticamente. El proceso se invoca con un entorno aislado
        (``_variables_entorno_aisladas``) y, cuando la version instalada lo permite, con
        opciones adicionales de aislamiento (``-config``, sin redirecciones, etc.). Un
        codigo de salida distinto de cero se trata siempre como un fallo real: nunca se
        interpreta como "analisis exitoso sin hallazgos".
        """
        self.requerir_instalada()
        ayuda = self.verificar_opciones_compatibles()
        componentes, ids_unicos = self.validar_parametros(
            objetivo=objetivo, plantillas_ids=plantillas_ids, tiempo_limite=tiempo_limite
        )
        objetivo_nuclei = f"{componentes.esquema}://{componentes.host}:{componentes.puerto}"

        # Lee y valida (hash + estructura) cada plantilla UNA vez, antes de tocar disco
        # de nuevo: el texto ya validado es lo unico que se usara para construir la
        # copia que realmente se le pasa a Nuclei (ver mas abajo, evita TOCTOU).
        textos_plantillas: dict[str, str] = {
            plantilla_id: _cargar_y_validar_plantilla(plantilla_id) for plantilla_id in ids_unicos
        }

        with tempfile.TemporaryDirectory(prefix="ast-nuclei-") as directorio_temporal:
            directorio = Path(directorio_temporal)
            ruta_jsonl = directorio / "resultado.jsonl"

            rutas_plantillas: list[Path] = []
            for indice, (plantilla_id, texto) in enumerate(textos_plantillas.items()):
                copia = directorio / f"plantilla-{indice}-{plantilla_id}.yaml"
                copia.write_text(texto, encoding="utf-8")
                rutas_plantillas.append(copia)

            directorio_aislado = directorio / "entorno-aislado"
            ruta_config_aislada = directorio_aislado / "config-nuclei-aislada.yaml"
            variables_entorno = _variables_entorno_aisladas(directorio_aislado)
            ruta_config_aislada.write_text("", encoding="utf-8")

            argumentos = ["-target", objetivo_nuclei]
            for ruta in rutas_plantillas:
                argumentos += ["-t", str(ruta)]
            argumentos += [
                "-jsonl",
                "-o", str(ruta_jsonl),
                "-timeout", str(_TIMEOUT_POR_PETICION_NUCLEI),
                "-rate-limit", str(_LIMITE_PETICIONES_POR_SEGUNDO),
                "-duc",
                "-ni",
                "-silent",
                "-nc",
            ]
            argumentos += _opciones_aislamiento_disponibles(
                ayuda, ruta_config_aislada=ruta_config_aislada
            )

            resultado_proceso = self._ejecutar_binario(
                argumentos,
                tiempo_limite=tiempo_limite,
                debe_cancelar=debe_cancelar,
                variables_entorno=variables_entorno,
            )

            if resultado_proceso.cancelado:
                raise ErrorEscaneoCancelado(
                    f"El analisis de Nuclei contra '{objetivo}' se cancelo antes de "
                    "completarse. No se guardo ningun resultado."
                )
            if resultado_proceso.agotado_por_tiempo:
                raise ErrorIntegracion(
                    f"Nuclei no termino en {tiempo_limite:g} segundos contra '{objetivo}'. "
                    "Reduce la cantidad de plantillas o aumenta el limite de tiempo."
                )
            if resultado_proceso.codigo_salida != 0:
                detalle = _texto_corto(
                    (resultado_proceso.stderr or resultado_proceso.stdout or "").strip(), 500
                )
                raise ErrorIntegracion(
                    "Nuclei termino con un error (codigo de salida "
                    f"{resultado_proceso.codigo_salida}) contra '{objetivo}'; no se guarda "
                    f"ningun resultado parcial. Detalle: {detalle or '(sin salida)'}"
                )

            lineas_jsonl = ""
            if ruta_jsonl.exists():
                tamano = ruta_jsonl.stat().st_size
                if tamano > _TAMANO_MAXIMO_JSONL_BYTES:
                    raise ErrorIntegracion(
                        f"La salida de Nuclei contra '{objetivo}' ocupa {tamano} bytes, por "
                        f"encima del maximo admitido ({_TAMANO_MAXIMO_JSONL_BYTES} bytes). Se "
                        "rechaza por seguridad; no se guarda ningun resultado."
                    )
                lineas_jsonl = ruta_jsonl.read_text(encoding="utf-8")

        hallazgos, descartadas = _analizar_jsonl_nuclei(
            lineas_jsonl, ids_ejecutados=frozenset(ids_unicos)
        )
        return ResultadoNuclei(
            objetivo=objetivo_nuclei,
            hallazgos=hallazgos,
            plantillas_ejecutadas=tuple(ids_unicos),
            lineas_jsonl_descartadas=descartadas,
        )


def _texto_corto(valor: object, longitud_maxima: int = 300) -> str:
    texto = str(valor) if valor is not None else ""
    return texto if len(texto) <= longitud_maxima else texto[: longitud_maxima - 3] + "..."


def _analizar_jsonl_nuclei(
    contenido: str, *, ids_ejecutados: frozenset[str]
) -> tuple[list[HallazgoNuclei], int]:
    """Interpreta la salida JSONL de Nuclei, una linea = un hallazgo.

    Toda la salida se trata como NO confiable (es la salida de un binario externo, no
    datos generados por AST): se descarta sin interrumpir el analisis cualquier linea
    que no sea JSON valido, le falten los campos minimos, supere los limites de tamano
    definidos, o reporte un ``template-id`` que no sea exactamente uno de los que AST le
    pidio ejecutar en esta misma invocacion (``ids_ejecutados``) -- Nuclei nunca deberia
    reportar un identificador distinto, y si lo hiciera (salida corrupta o manipulada) no
    se usa. Nunca se persisten los campos ``request``/``response``/``curl-command`` que
    Nuclei incluye en cada linea (podrian contener cabeceras de autenticacion, cookies de
    sesion o el cuerpo completo de la respuesta): la evidencia que AST guarda es un
    resumen propio, corto y con longitud acotada, construido solo con el host/ruta
    igualados y el nombre del matcher.
    """
    hallazgos: list[HallazgoNuclei] = []
    descartadas = 0
    for linea in contenido.splitlines():
        linea = linea.strip()
        if not linea:
            continue
        if len(linea) > _LONGITUD_MAXIMA_LINEA_JSONL:
            descartadas += 1
            continue
        try:
            datos = json.loads(linea)
        except json.JSONDecodeError:
            descartadas += 1
            continue
        if not isinstance(datos, dict):
            descartadas += 1
            continue

        info = datos.get("info")
        if not isinstance(info, dict):
            descartadas += 1
            continue

        plantilla_id_bruto = datos.get("template-id") or datos.get("template_id")
        nombre = info.get("name")
        if not plantilla_id_bruto or not nombre:
            descartadas += 1
            continue
        plantilla_id = str(plantilla_id_bruto)
        if plantilla_id not in ids_ejecutados:
            descartadas += 1
            continue

        severidad = _texto_corto(info.get("severity") or "unknown", _LONGITUD_MAXIMA_CAMPO_CORTO)
        descripcion = _texto_corto(info.get("description") or "", _LONGITUD_MAXIMA_CAMPO_LARGO)
        matched_at = _texto_corto(
            datos.get("matched-at") or datos.get("host") or "", _LONGITUD_MAXIMA_CAMPO_LARGO
        )
        matcher_nombre = _texto_corto(
            datos.get("matcher-name") or datos.get("matcher_name") or "",
            _LONGITUD_MAXIMA_CAMPO_CORTO,
        )
        evidencia = f"{matched_at} (matcher: {matcher_nombre})" if matcher_nombre else matched_at

        hallazgos.append(
            HallazgoNuclei(
                plantilla_id=plantilla_id,
                plantilla_nombre=_texto_corto(nombre, _LONGITUD_MAXIMA_CAMPO_CORTO),
                severidad=severidad,
                descripcion=descripcion,
                evidencia=evidencia,
            )
        )
    return hallazgos, descartadas
