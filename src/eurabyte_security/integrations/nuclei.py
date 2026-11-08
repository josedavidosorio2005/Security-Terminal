"""Adaptador de Nuclei (Fase 3, Paso 4): plantillas HTTP aprobadas de bajo impacto.

A diferencia de Nmap, Nuclei puede ejecutar practicamente cualquier cosa segun la
plantilla que se le indique (plantillas de la comunidad incluyen protocolos de red,
DNS, ejecucion de codigo, fuzzing, pruebas OAST/Interactsh contra un servidor de
terceros...). AST **nunca** acepta una ruta de plantilla arbitraria: solo permite
elegir, por identificador, entre un catalogo reducido de plantillas que la propia
AURABYTE escribio, reviso y distribuye junto con el paquete (``plantillas_nuclei/``).

Cada plantilla del catalogo, ademas, se vuelve a validar estructuralmente en tiempo de
ejecucion (``validar_plantilla_estructura``) antes de usarla: que sea un unico bloque
``http``, sin otros protocolos (``dns``, ``file``, ``network``, ``headless``, ``code``,
``ssl``, ``workflows``), sin seguir redirecciones y sin ninguna referencia a
Interactsh/OAST. Una plantilla no se considera segura solo por venir con este paquete o
por estar "firmada": si la validacion estructural falla (por ejemplo, alguien edito el
archivo despues de instalar AST), la ejecucion se rechaza con un error claro en vez de
asumir que sigue siendo segura.

Aun con todo esto, Nuclei es un binario externo independiente: AST no puede garantizar
en tiempo de ejecucion que una plantilla aprobada hoy nunca abra una conexion fuera del
objetivo autorizado (solo que, al escribirla, no se le dio ningun motivo para hacerlo).
Por eso el catalogo se mantiene deliberadamente pequeno y cada plantilla hace como
maximo un puñado de peticiones GET de solo lectura contra ``{{BaseURL}}`` del objetivo.
"""

from __future__ import annotations

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

# Bloques de protocolo que una plantilla de AST nunca puede declarar: cualquiera de estos
# abre la puerta a algo que no es "una peticion GET de solo lectura contra el objetivo"
# (red/DNS/archivos locales/ejecucion de codigo/navegador headless/encadenado de pasos).
_CLAVES_PROTOCOLO_PROHIBIDAS = frozenset(
    {"dns", "file", "network", "headless", "code", "ssl", "workflows", "javascript"}
)
# Fragmentos que, si aparecen en el YAML serializado de la plantilla, indican que podria
# alcanzar un destino distinto del propio objetivo o cambiar el comportamiento esperado.
_FRAGMENTOS_PROHIBIDOS = (
    "interactsh",
    "oast",
    "redirects: true",
    "follow-redirects: true",
    "unsafe: true",
    "req-condition: true",
)


@dataclass(frozen=True, slots=True)
class InfoPlantillaNuclei:
    """Una plantilla aprobada del catalogo de AST (nunca una ruta arbitraria).

    ``version`` es propia de AST (no de Nuclei, cuyo formato de plantilla no tiene un
    campo de version oficial): identifica la revision de ESTA plantilla dentro del
    catalogo, para poder saber con que version se genero un hallazgo ya guardado si la
    plantilla cambia mas adelante. Se incrementa a mano cada vez que se edita el .yaml.
    """

    id_: str
    nombre: str
    descripcion: str
    severidad_esperada: str
    etiquetas: tuple[str, ...]
    archivo: str
    recomendacion: str
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


def validar_plantilla_estructura(ruta: Path) -> None:
    """Vuelve a comprobar, leyendo el archivo, que una plantilla es segura de ejecutar.

    No basta con que una plantilla este en ``PLANTILLAS_APROBADAS``: si alguien edito el
    archivo despues de instalar AST (por error o a proposito), esta comprobacion lo
    detecta y rechaza la ejecucion en vez de asumir que sigue siendo la misma plantilla
    de bajo impacto que se reviso originalmente.
    """
    try:
        texto = ruta.read_text(encoding="utf-8")
    except OSError as exc:
        raise ErrorIntegracion(f"No se pudo leer la plantilla '{ruta.name}': {exc}") from exc

    try:
        datos = yaml.safe_load(texto)
    except yaml.YAMLError as exc:
        raise ErrorIntegracion(f"La plantilla '{ruta.name}' no es un YAML valido: {exc}") from exc

    if not isinstance(datos, dict):
        raise ErrorIntegracion(f"La plantilla '{ruta.name}' no tiene la forma esperada.")

    claves = set(datos.keys())
    protocolos_prohibidos = claves & _CLAVES_PROTOCOLO_PROHIBIDAS
    if protocolos_prohibidos:
        raise ErrorIntegracion(
            f"La plantilla '{ruta.name}' declara un protocolo no permitido "
            f"({', '.join(sorted(protocolos_prohibidos))}); solo se permiten "
            "plantillas HTTP simples."
        )
    if "http" not in claves:
        raise ErrorIntegracion(
            f"La plantilla '{ruta.name}' no declara un bloque 'http': no hay nada seguro "
            "que ejecutar en ella."
        )

    texto_bajo = texto.lower()
    fragmentos_encontrados = [f for f in _FRAGMENTOS_PROHIBIDOS if f in texto_bajo]
    if fragmentos_encontrados:
        raise ErrorIntegracion(
            f"La plantilla '{ruta.name}' contiene elementos no permitidos "
            f"({', '.join(fragmentos_encontrados)}): podria seguir redirecciones, "
            "contactar un servidor externo (OAST) o comportarse de forma insegura."
        )

    bloques_http = datos.get("http")
    if not isinstance(bloques_http, list) or not bloques_http:
        raise ErrorIntegracion(f"La plantilla '{ruta.name}' no define ninguna peticion HTTP.")
    for bloque in bloques_http:
        if not isinstance(bloque, dict):
            continue
        metodo = str(bloque.get("method", "GET")).upper()
        if metodo != "GET":
            raise ErrorIntegracion(
                f"La plantilla '{ruta.name}' usa el metodo '{metodo}'; AST solo permite "
                "peticiones GET de solo lectura en su catalogo aprobado."
            )


def _opciones_requeridas() -> tuple[str, ...]:
    return (
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


class AdaptadorNuclei(AdaptadorExterno):
    """Ejecuta Nuclei contra un unico objetivo, solo con plantillas del catalogo aprobado."""

    nombre = "Nuclei"
    comando = "nuclei"
    argumentos_version = ("-version",)

    def verificar_opciones_compatibles(self) -> None:
        """Comprueba (via ``nuclei -h``) que la version instalada admite las opciones

        que AST necesita pasarle. Evita construir un comando con una opcion que una
        version muy antigua (o muy distinta) de Nuclei no reconozca.
        """
        resultado = self._ejecutar_binario(["-h"], tiempo_limite=10.0)
        ayuda = (resultado.stdout or "") + (resultado.stderr or "")
        faltantes = [opcion for opcion in _opciones_requeridas() if opcion not in ayuda]
        if faltantes:
            raise ErrorIntegracion(
                "La version instalada de Nuclei no reconoce las siguientes opciones "
                f"requeridas: {', '.join(faltantes)}. Actualiza Nuclei e intenta de nuevo."
            )

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
        ni sus plantillas automaticamente.
        """
        self.requerir_instalada()
        self.verificar_opciones_compatibles()
        componentes, ids_unicos = self.validar_parametros(
            objetivo=objetivo, plantillas_ids=plantillas_ids, tiempo_limite=tiempo_limite
        )
        objetivo_nuclei = f"{componentes.esquema}://{componentes.host}:{componentes.puerto}"

        rutas_plantillas: list[Path] = []
        for plantilla_id in ids_unicos:
            ruta = ruta_plantilla(plantilla_id)
            validar_plantilla_estructura(ruta)
            rutas_plantillas.append(ruta)

        with tempfile.TemporaryDirectory(prefix="ast-nuclei-") as directorio_temporal:
            ruta_jsonl = Path(directorio_temporal) / "resultado.jsonl"

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

            resultado_proceso = self._ejecutar_binario(
                argumentos, tiempo_limite=tiempo_limite, debe_cancelar=debe_cancelar
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

            lineas_jsonl = ruta_jsonl.read_text(encoding="utf-8") if ruta_jsonl.exists() else ""

        hallazgos, descartadas = _analizar_jsonl_nuclei(lineas_jsonl)
        return ResultadoNuclei(
            objetivo=objetivo_nuclei,
            hallazgos=hallazgos,
            plantillas_ejecutadas=tuple(ids_unicos),
            lineas_jsonl_descartadas=descartadas,
        )


def _texto_corto(valor: object, longitud_maxima: int = 300) -> str:
    texto = str(valor) if valor is not None else ""
    return texto if len(texto) <= longitud_maxima else texto[: longitud_maxima - 3] + "..."


def _analizar_jsonl_nuclei(contenido: str) -> tuple[list[HallazgoNuclei], int]:
    """Interpreta la salida JSONL de Nuclei, una linea = un hallazgo.

    Nunca persiste los campos ``request``/``response``/``curl-command`` que Nuclei
    incluye en cada linea (podrian contener cabeceras de autenticacion, cookies de
    sesion o el cuerpo completo de la respuesta): la evidencia que AST guarda es un
    resumen propio, corto, construido solo con el host/ruta igualados y el nombre del
    matcher. Una linea que no es JSON valido (o le faltan los campos minimos) se
    descarta sin interrumpir el analisis del resto.
    """
    import json

    hallazgos: list[HallazgoNuclei] = []
    descartadas = 0
    for linea in contenido.splitlines():
        linea = linea.strip()
        if not linea:
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

        plantilla_id = datos.get("template-id") or datos.get("template_id")
        nombre = info.get("name")
        if not plantilla_id or not nombre:
            descartadas += 1
            continue

        severidad = str(info.get("severity") or "unknown")
        descripcion = _texto_corto(info.get("description") or "")
        matched_at = _texto_corto(datos.get("matched-at") or datos.get("host") or "")
        matcher_nombre = datos.get("matcher-name") or datos.get("matcher_name") or ""
        evidencia = f"{matched_at} (matcher: {matcher_nombre})" if matcher_nombre else matched_at

        hallazgos.append(
            HallazgoNuclei(
                plantilla_id=str(plantilla_id),
                plantilla_nombre=str(nombre),
                severidad=severidad,
                descripcion=descripcion,
                evidencia=evidencia,
            )
        )
    return hallazgos, descartadas
