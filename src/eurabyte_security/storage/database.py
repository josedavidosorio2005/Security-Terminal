"""Repositorio SQLite para proyectos, alcances y resultados de EST."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from eurabyte_security.core.config import ruta_base_datos
from eurabyte_security.core.errores import (
    ErrorInvestigacionOSINTNoEncontrada,
    ErrorProyectoDuplicado,
    ErrorProyectoNoEncontrado,
    ErrorSesionReconocimientoNoEncontrada,
)

ESQUEMA = """
CREATE TABLE IF NOT EXISTS proyectos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT UNIQUE NOT NULL,
    creado_en TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alcances (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proyecto_id INTEGER NOT NULL REFERENCES proyectos(id) ON DELETE CASCADE,
    red TEXT NOT NULL,
    creado_en TEXT NOT NULL,
    UNIQUE(proyecto_id, red)
);

CREATE TABLE IF NOT EXISTS resultados (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proyecto_id INTEGER NOT NULL REFERENCES proyectos(id) ON DELETE CASCADE,
    objetivo TEXT NOT NULL,
    puerto INTEGER NOT NULL,
    estado TEXT NOT NULL,
    creado_en TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS resultados_nmap (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proyecto_id INTEGER NOT NULL REFERENCES proyectos(id) ON DELETE CASCADE,
    objetivo TEXT NOT NULL,
    puerto INTEGER NOT NULL,
    protocolo TEXT NOT NULL,
    estado TEXT NOT NULL,
    servicio TEXT,
    version TEXT,
    creado_en TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS resultados_web (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proyecto_id INTEGER NOT NULL REFERENCES proyectos(id) ON DELETE CASCADE,
    objetivo TEXT NOT NULL,
    tipo_analisis TEXT NOT NULL,
    categoria TEXT NOT NULL,
    nombre_hallazgo TEXT NOT NULL,
    severidad TEXT NOT NULL,
    estado TEXT NOT NULL,
    valor_detectado TEXT,
    riesgo TEXT NOT NULL,
    recomendacion TEXT NOT NULL,
    referencia TEXT NOT NULL,
    creado_en TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS resultados_nuclei (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proyecto_id INTEGER NOT NULL REFERENCES proyectos(id) ON DELETE CASCADE,
    objetivo TEXT NOT NULL,
    plantilla_id TEXT NOT NULL,
    plantilla_version TEXT NOT NULL,
    nombre_hallazgo TEXT NOT NULL,
    severidad TEXT NOT NULL,
    descripcion TEXT NOT NULL,
    evidencia TEXT,
    estado_revision TEXT NOT NULL,
    creado_en TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS resultados_zap (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proyecto_id INTEGER NOT NULL REFERENCES proyectos(id) ON DELETE CASCADE,
    objetivo TEXT NOT NULL,
    plugin_id TEXT NOT NULL,
    nombre_hallazgo TEXT NOT NULL,
    riesgo TEXT NOT NULL,
    confianza TEXT NOT NULL,
    descripcion TEXT NOT NULL,
    evidencia TEXT,
    solucion TEXT NOT NULL,
    referencia TEXT,
    estado_revision TEXT NOT NULL,
    creado_en TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS investigaciones_osint (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proyecto_id INTEGER NOT NULL REFERENCES proyectos(id) ON DELETE CASCADE,
    tipo_objetivo TEXT NOT NULL,
    objetivo_original TEXT NOT NULL,
    objetivo_saneado TEXT NOT NULL,
    autorizado_datos_personales INTEGER NOT NULL,
    fuentes_json TEXT NOT NULL,
    estado_general TEXT NOT NULL,
    etapas_json TEXT NOT NULL,
    limitaciones_json TEXT NOT NULL,
    ruta_informe_html TEXT,
    ruta_informe_json TEXT,
    creado_en TEXT NOT NULL,
    actualizado_en TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hallazgos_osint (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigacion_id INTEGER NOT NULL REFERENCES investigaciones_osint(id) ON DELETE CASCADE,
    proyecto_id INTEGER NOT NULL REFERENCES proyectos(id) ON DELETE CASCADE,
    fuente TEXT NOT NULL,
    categoria TEXT NOT NULL,
    titulo TEXT NOT NULL,
    descripcion TEXT NOT NULL,
    nivel_confianza TEXT NOT NULL,
    indicador_exposicion TEXT,
    evidencias_json TEXT NOT NULL,
    creado_en TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sesiones_reconocimiento (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proyecto_id INTEGER NOT NULL REFERENCES proyectos(id) ON DELETE CASCADE,
    objetivo_original TEXT NOT NULL,
    nombre_host TEXT,
    ip TEXT,
    perfil TEXT NOT NULL,
    estado_general TEXT NOT NULL,
    etapas_json TEXT NOT NULL,
    limitaciones_json TEXT NOT NULL,
    ruta_informe_html TEXT,
    ruta_informe_json TEXT,
    creado_en TEXT NOT NULL,
    actualizado_en TEXT NOT NULL
);
"""


def _ahora() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True, slots=True)
class Proyecto:
    id: int
    nombre: str
    creado_en: str


@dataclass(frozen=True, slots=True)
class Alcance:
    id: int
    proyecto_id: int
    red: str
    creado_en: str


@dataclass(frozen=True, slots=True)
class Resultado:
    id: int
    proyecto_id: int
    objetivo: str
    puerto: int
    estado: str
    creado_en: str


@dataclass(frozen=True, slots=True)
class ResultadoNmap:
    id: int
    proyecto_id: int
    objetivo: str
    puerto: int
    protocolo: str
    estado: str
    servicio: str | None
    version: str | None
    creado_en: str


@dataclass(frozen=True, slots=True)
class ResultadoWeb:
    id: int
    proyecto_id: int
    objetivo: str
    tipo_analisis: str
    categoria: str
    nombre_hallazgo: str
    severidad: str
    estado: str
    valor_detectado: str | None
    riesgo: str
    recomendacion: str
    referencia: str
    creado_en: str


@dataclass(frozen=True, slots=True)
class ResultadoNuclei:
    id: int
    proyecto_id: int
    objetivo: str
    plantilla_id: str
    plantilla_version: str
    nombre_hallazgo: str
    severidad: str
    descripcion: str
    evidencia: str | None
    estado_revision: str
    creado_en: str


@dataclass(frozen=True, slots=True)
class ResultadoZAP:
    id: int
    proyecto_id: int
    objetivo: str
    plugin_id: str
    nombre_hallazgo: str
    riesgo: str
    confianza: str
    descripcion: str
    evidencia: str | None
    solucion: str
    referencia: str | None
    estado_revision: str
    creado_en: str


# Identificadores estables de las cinco fuentes de resultados existentes. Se usan tanto
# para filtrar la vista unificada (``BaseDatos.listar_resultados_unificados``) como para
# que otras capas (CLI, informes) sepan que valores de '--fuente' son validos, sin tener
# que repetir esta lista en cada modulo.
FUENTES_RESULTADOS: tuple[str, ...] = ("tcp", "nmap", "web", "nuclei", "zap")

# Agrupa severidades equivalentes de distintas herramientas SOLO para poder filtrar y
# ordenar la vista unificada (p. ej. comparar 'alta' de la auditoria web con 'high' de
# Nuclei o 'critical' de ZAP). Nunca se usa para reescribir el valor guardado en el
# registro original de ninguna tabla: cada fuente conserva su propia escala tal cual la
# reporto la herramienta.
_GRUPOS_SEVERIDAD: dict[str, frozenset[str]] = {
    "info": frozenset({"info", "informational"}),
    "baja": frozenset({"baja", "low"}),
    "media": frozenset({"media", "medium"}),
    "alta": frozenset({"alta", "high", "critical"}),
}


def agrupar_severidad(valor: str | None) -> str | None:
    """Normaliza una severidad/riesgo propio de una herramienta a un grupo comun.

    Devuelve ``None`` sin tocarlo (una severidad ausente sigue ausente: nunca se inventa
    una). Un valor que no coincide con ningun grupo conocido se devuelve en minusculas,
    tal cual, para que todavia se pueda comparar por igualdad.
    """
    if valor is None:
        return None
    valor_bajo = valor.lower()
    for grupo, miembros in _GRUPOS_SEVERIDAD.items():
        if valor_bajo in miembros:
            return grupo
    return valor_bajo


@dataclass(frozen=True, slots=True)
class ResultadoUnificado:
    """Vista normalizada de un resultado/hallazgo, cualquiera sea su herramienta de origen.

    No sustituye a las tablas por herramienta (``resultados``, ``resultados_nmap``,
    ``resultados_web``, ``resultados_nuclei``, ``resultados_zap``): es una proyeccion de
    solo lectura construida a partir de ellas (ver
    ``BaseDatos.listar_resultados_unificados``), que conserva ``fuente`` + ``id_origen``
    para poder rastrear cada fila hasta su registro original.

    ``severidad`` es intencionalmente ``None`` para 'tcp' y 'nmap': un puerto abierto o
    cerrado es informacion de conectividad/reconocimiento, no una vulnerabilidad, y AST
    nunca le asigna una severidad ficticia. ``estado`` (abierto/cerrado/error para
    tcp/nmap, o el estado de un hallazgo de auditoria web) y ``estado_revision``
    (nuevo/confirmado/falso_positivo, solo presente en Nuclei y ZAP) son conceptos
    distintos que nunca se mezclan en un unico campo.
    """

    fuente: str
    id_origen: int
    proyecto_id: int
    objetivo: str
    tipo: str
    nombre: str
    descripcion: str | None
    severidad: str | None
    estado: str | None
    estado_revision: str | None
    evidencia: str | None
    recomendacion: str | None
    referencia: str | None
    creado_en: str


def _normalizar_tcp(r: Resultado) -> ResultadoUnificado:
    return ResultadoUnificado(
        fuente="tcp", id_origen=r.id, proyecto_id=r.proyecto_id, objetivo=r.objetivo,
        tipo="puerto", nombre=f"Puerto {r.puerto}", descripcion=None,
        severidad=None, estado=r.estado, estado_revision=None,
        evidencia=None, recomendacion=None, referencia=None, creado_en=r.creado_en,
    )


def _normalizar_nmap(r: ResultadoNmap) -> ResultadoUnificado:
    detalle = " ".join(parte for parte in (r.servicio, r.version) if parte) or None
    return ResultadoUnificado(
        fuente="nmap", id_origen=r.id, proyecto_id=r.proyecto_id, objetivo=r.objetivo,
        tipo="puerto", nombre=f"Puerto {r.puerto}/{r.protocolo}", descripcion=detalle,
        severidad=None, estado=r.estado, estado_revision=None,
        evidencia=None, recomendacion=None, referencia=None, creado_en=r.creado_en,
    )


def _normalizar_web(r: ResultadoWeb) -> ResultadoUnificado:
    return ResultadoUnificado(
        fuente="web", id_origen=r.id, proyecto_id=r.proyecto_id, objetivo=r.objetivo,
        tipo=r.categoria, nombre=r.nombre_hallazgo, descripcion=None,
        severidad=r.severidad, estado=r.estado, estado_revision=None,
        evidencia=r.valor_detectado, recomendacion=r.recomendacion, referencia=r.referencia,
        creado_en=r.creado_en,
    )


def _normalizar_nuclei(r: ResultadoNuclei) -> ResultadoUnificado:
    return ResultadoUnificado(
        fuente="nuclei", id_origen=r.id, proyecto_id=r.proyecto_id, objetivo=r.objetivo,
        tipo=f"plantilla:{r.plantilla_id}", nombre=r.nombre_hallazgo, descripcion=r.descripcion,
        severidad=r.severidad, estado=None, estado_revision=r.estado_revision,
        evidencia=r.evidencia, recomendacion=None, referencia=None, creado_en=r.creado_en,
    )


def _normalizar_zap(r: ResultadoZAP) -> ResultadoUnificado:
    return ResultadoUnificado(
        fuente="zap", id_origen=r.id, proyecto_id=r.proyecto_id, objetivo=r.objetivo,
        tipo=f"regla:{r.plugin_id}", nombre=r.nombre_hallazgo, descripcion=r.descripcion,
        severidad=r.riesgo, estado=None, estado_revision=r.estado_revision,
        evidencia=r.evidencia, recomendacion=r.solucion, referencia=r.referencia,
        creado_en=r.creado_en,
    )


@dataclass(frozen=True, slots=True)
class SesionReconocimiento:
    """Sesion de reconocimiento automatico (ver ``modules/reconocimiento/orquestador.py``).

    ``etapas_json`` y ``limitaciones_json`` guardan listas de diccionarios/strings ya
    serializadas (JSON): esta capa de almacenamiento no conoce ``EtapaReconocimiento``
    ni ninguna otra clase de ``modules/`` -- ``storage/`` nunca depende de ``modules/``,
    solo al reves -- por lo que recibe y devuelve datos primitivos ya serializados, y es
    responsabilidad de quien llama (el orquestador) convertirlos desde/hacia sus propias
    dataclasses.
    """

    id: int
    proyecto_id: int
    objetivo_original: str
    nombre_host: str | None
    ip: str | None
    perfil: str
    estado_general: str
    etapas_json: str
    limitaciones_json: str
    ruta_informe_html: str | None
    ruta_informe_json: str | None
    creado_en: str
    actualizado_en: str


@dataclass(frozen=True, slots=True)
class InvestigacionOSINT:
    """Investigacion OSINT guardada (ver ``modules/osint/motor.py``).

    ``fuentes_json``/``etapas_json``/``limitaciones_json`` son listas ya serializadas a
    JSON, con la misma logica que ``SesionReconocimiento``: esta capa no conoce
    ``EtapaFuenteOSINT`` ni ningun otro tipo de ``modules/``, solo datos primitivos.
    """

    id: int
    proyecto_id: int
    tipo_objetivo: str
    objetivo_original: str
    objetivo_saneado: str
    autorizado_datos_personales: bool
    fuentes_json: str
    estado_general: str
    etapas_json: str
    limitaciones_json: str
    ruta_informe_html: str | None
    ruta_informe_json: str | None
    creado_en: str
    actualizado_en: str


@dataclass(frozen=True, slots=True)
class HallazgoOSINTGuardado:
    """Un hallazgo OSINT ya persistido. ``evidencias_json`` es una lista de
    ``EvidenciaOSINT.como_dict()`` ya serializada (ver ``modules/osint/modelos.py``)."""

    id: int
    investigacion_id: int
    proyecto_id: int
    fuente: str
    categoria: str
    titulo: str
    descripcion: str
    nivel_confianza: str
    indicador_exposicion: str | None
    evidencias_json: str
    creado_en: str


class BaseDatos:
    """Repositorio de acceso a los datos persistentes de EST."""

    def __init__(self, ruta: Path | None = None) -> None:
        self._ruta = ruta or ruta_base_datos()
        with self._conectar() as conexion:
            conexion.executescript(ESQUEMA)

    @contextmanager
    def _conectar(self) -> Generator[sqlite3.Connection, None, None]:
        conexion = sqlite3.connect(self._ruta)
        conexion.row_factory = sqlite3.Row
        try:
            yield conexion
            conexion.commit()
        finally:
            conexion.close()

    # -- Proyectos ---------------------------------------------------
    def crear_proyecto(self, nombre: str) -> Proyecto:
        try:
            with self._conectar() as conexion:
                cursor = conexion.execute(
                    "INSERT INTO proyectos (nombre, creado_en) VALUES (?, ?)",
                    (nombre, _ahora()),
                )
                nuevo_id = cursor.lastrowid
        except sqlite3.IntegrityError as exc:
            raise ErrorProyectoDuplicado(
                f"Ya existe un proyecto llamado '{nombre}'."
            ) from exc
        return self.obtener_proyecto_por_id(nuevo_id)  # type: ignore[arg-type]

    def obtener_proyecto_por_id(self, id_: int) -> Proyecto:
        with self._conectar() as conexion:
            fila = conexion.execute(
                "SELECT id, nombre, creado_en FROM proyectos WHERE id = ?", (id_,)
            ).fetchone()
        if fila is None:
            raise ErrorProyectoNoEncontrado(f"No existe un proyecto con id {id_}.")
        return Proyecto(**fila)

    def obtener_proyecto_por_nombre(self, nombre: str) -> Proyecto:
        with self._conectar() as conexion:
            fila = conexion.execute(
                "SELECT id, nombre, creado_en FROM proyectos WHERE nombre = ?", (nombre,)
            ).fetchone()
        if fila is None:
            raise ErrorProyectoNoEncontrado(f"No existe un proyecto llamado '{nombre}'.")
        return Proyecto(**fila)

    def listar_proyectos(self) -> list[Proyecto]:
        with self._conectar() as conexion:
            filas = conexion.execute(
                "SELECT id, nombre, creado_en FROM proyectos ORDER BY nombre"
            ).fetchall()
        return [Proyecto(**fila) for fila in filas]

    # -- Alcances ------------------------------------------------------
    def agregar_alcance(self, proyecto_id: int, red: str) -> Alcance:
        with self._conectar() as conexion:
            try:
                cursor = conexion.execute(
                    "INSERT INTO alcances (proyecto_id, red, creado_en) VALUES (?, ?, ?)",
                    (proyecto_id, red, _ahora()),
                )
            except sqlite3.IntegrityError:
                fila = conexion.execute(
                    "SELECT id, proyecto_id, red, creado_en FROM alcances "
                    "WHERE proyecto_id = ? AND red = ?",
                    (proyecto_id, red),
                ).fetchone()
                return Alcance(**fila)
            fila = conexion.execute(
                "SELECT id, proyecto_id, red, creado_en FROM alcances WHERE id = ?",
                (cursor.lastrowid,),
            ).fetchone()
            return Alcance(**fila)

    def listar_alcance(self, proyecto_id: int) -> list[Alcance]:
        with self._conectar() as conexion:
            filas = conexion.execute(
                "SELECT id, proyecto_id, red, creado_en FROM alcances "
                "WHERE proyecto_id = ? ORDER BY creado_en",
                (proyecto_id,),
            ).fetchall()
        return [Alcance(**fila) for fila in filas]

    # -- Resultados ----------------------------------------------------
    def agregar_resultado(
        self, proyecto_id: int, objetivo: str, puerto: int, estado: str
    ) -> Resultado:
        with self._conectar() as conexion:
            cursor = conexion.execute(
                "INSERT INTO resultados (proyecto_id, objetivo, puerto, estado, creado_en) "
                "VALUES (?, ?, ?, ?, ?)",
                (proyecto_id, objetivo, puerto, estado, _ahora()),
            )
            fila = conexion.execute(
                "SELECT id, proyecto_id, objetivo, puerto, estado, creado_en "
                "FROM resultados WHERE id = ?",
                (cursor.lastrowid,),
            ).fetchone()
            return Resultado(**fila)

    def agregar_resultados(
        self, proyecto_id: int, objetivo: str, resultados: list[tuple[int, str]]
    ) -> list[Resultado]:
        """Inserta varios resultados en una sola transaccion (todo o nada).

        Si cualquier insercion falla (o la llamada se interrumpe a mitad de
        camino, por ejemplo por una excepcion), ``_conectar`` nunca llega a
        hacer ``commit`` y la conexion se cierra sin confirmar nada: SQLite
        descarta la transaccion completa, por lo que no queda ningun
        resultado parcial. ``resultados`` es una lista de ``(puerto, estado)``.
        """
        guardados: list[Resultado] = []
        with self._conectar() as conexion:
            for puerto, estado in resultados:
                cursor = conexion.execute(
                    "INSERT INTO resultados (proyecto_id, objetivo, puerto, estado, creado_en) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (proyecto_id, objetivo, puerto, estado, _ahora()),
                )
                fila = conexion.execute(
                    "SELECT id, proyecto_id, objetivo, puerto, estado, creado_en "
                    "FROM resultados WHERE id = ?",
                    (cursor.lastrowid,),
                ).fetchone()
                guardados.append(Resultado(**fila))
        return guardados

    def listar_resultados(
        self, proyecto_id: int | None = None, limite: int = 200
    ) -> list[Resultado]:
        with self._conectar() as conexion:
            if proyecto_id is None:
                filas = conexion.execute(
                    "SELECT id, proyecto_id, objetivo, puerto, estado, creado_en "
                    "FROM resultados ORDER BY creado_en DESC LIMIT ?",
                    (limite,),
                ).fetchall()
            else:
                filas = conexion.execute(
                    "SELECT id, proyecto_id, objetivo, puerto, estado, creado_en "
                    "FROM resultados WHERE proyecto_id = ? ORDER BY creado_en DESC LIMIT ?",
                    (proyecto_id, limite),
                ).fetchall()
        return [Resultado(**fila) for fila in filas]

    # -- Resultados de Nmap ---------------------------------------------
    def agregar_resultados_nmap(
        self,
        proyecto_id: int,
        objetivo: str,
        resultados: list[tuple[int, str, str, str | None, str | None]],
    ) -> list[ResultadoNmap]:
        """Inserta resultados de Nmap en una sola transaccion (todo o nada).

        ``resultados`` es una lista de ``(puerto, protocolo, estado, servicio, version)``.
        Misma semantica de atomicidad que :meth:`agregar_resultados`.
        """
        guardados: list[ResultadoNmap] = []
        with self._conectar() as conexion:
            for puerto, protocolo, estado, servicio, version in resultados:
                cursor = conexion.execute(
                    "INSERT INTO resultados_nmap "
                    "(proyecto_id, objetivo, puerto, protocolo, estado, servicio, version, "
                    "creado_en) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (proyecto_id, objetivo, puerto, protocolo, estado, servicio, version, _ahora()),
                )
                fila = conexion.execute(
                    "SELECT id, proyecto_id, objetivo, puerto, protocolo, estado, servicio, "
                    "version, creado_en FROM resultados_nmap WHERE id = ?",
                    (cursor.lastrowid,),
                ).fetchone()
                guardados.append(ResultadoNmap(**fila))
        return guardados

    def listar_resultados_nmap(
        self, proyecto_id: int | None = None, limite: int = 200
    ) -> list[ResultadoNmap]:
        with self._conectar() as conexion:
            if proyecto_id is None:
                filas = conexion.execute(
                    "SELECT id, proyecto_id, objetivo, puerto, protocolo, estado, servicio, "
                    "version, creado_en FROM resultados_nmap ORDER BY creado_en DESC LIMIT ?",
                    (limite,),
                ).fetchall()
            else:
                filas = conexion.execute(
                    "SELECT id, proyecto_id, objetivo, puerto, protocolo, estado, servicio, "
                    "version, creado_en FROM resultados_nmap WHERE proyecto_id = ? "
                    "ORDER BY creado_en DESC LIMIT ?",
                    (proyecto_id, limite),
                ).fetchall()
        return [ResultadoNmap(**fila) for fila in filas]

    # -- Resultados de auditoria web ------------------------------------
    def agregar_resultados_web(
        self,
        proyecto_id: int,
        objetivo: str,
        tipo_analisis: str,
        hallazgos: list[tuple[str, str, str, str, str | None, str, str, str]],
    ) -> list[ResultadoWeb]:
        """Inserta hallazgos de auditoria web en una sola transaccion (todo o nada).

        ``hallazgos`` es una lista de tuplas ``(categoria, nombre_hallazgo, severidad,
        estado, valor_detectado, riesgo, recomendacion, referencia)``. Misma semantica de
        atomicidad que :meth:`agregar_resultados`: si la auditoria se cancela antes de
        llegar aqui, esta funcion no llega a invocarse y no se guarda nada.
        """
        guardados: list[ResultadoWeb] = []
        with self._conectar() as conexion:
            for (
                categoria,
                nombre_hallazgo,
                severidad,
                estado,
                valor_detectado,
                riesgo,
                recomendacion,
                referencia,
            ) in hallazgos:
                cursor = conexion.execute(
                    "INSERT INTO resultados_web (proyecto_id, objetivo, tipo_analisis, "
                    "categoria, nombre_hallazgo, severidad, estado, valor_detectado, "
                    "riesgo, recomendacion, referencia, creado_en) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        proyecto_id,
                        objetivo,
                        tipo_analisis,
                        categoria,
                        nombre_hallazgo,
                        severidad,
                        estado,
                        valor_detectado,
                        riesgo,
                        recomendacion,
                        referencia,
                        _ahora(),
                    ),
                )
                fila = conexion.execute(
                    "SELECT id, proyecto_id, objetivo, tipo_analisis, categoria, "
                    "nombre_hallazgo, severidad, estado, valor_detectado, riesgo, "
                    "recomendacion, referencia, creado_en FROM resultados_web WHERE id = ?",
                    (cursor.lastrowid,),
                ).fetchone()
                guardados.append(ResultadoWeb(**fila))
        return guardados

    def listar_resultados_web(
        self, proyecto_id: int | None = None, limite: int = 200
    ) -> list[ResultadoWeb]:
        columnas = (
            "id, proyecto_id, objetivo, tipo_analisis, categoria, nombre_hallazgo, "
            "severidad, estado, valor_detectado, riesgo, recomendacion, referencia, creado_en"
        )
        with self._conectar() as conexion:
            if proyecto_id is None:
                filas = conexion.execute(
                    f"SELECT {columnas} FROM resultados_web ORDER BY creado_en DESC LIMIT ?",
                    (limite,),
                ).fetchall()
            else:
                filas = conexion.execute(
                    f"SELECT {columnas} FROM resultados_web WHERE proyecto_id = ? "
                    "ORDER BY creado_en DESC LIMIT ?",
                    (proyecto_id, limite),
                ).fetchall()
        return [ResultadoWeb(**fila) for fila in filas]

    # -- Resultados de Nuclei --------------------------------------------
    def agregar_resultados_nuclei(
        self,
        proyecto_id: int,
        objetivo: str,
        resultados: list[tuple[str, str, str, str, str, str | None]],
    ) -> list[ResultadoNuclei]:
        """Inserta hallazgos de Nuclei en una sola transaccion (todo o nada).

        ``resultados`` es una lista de ``(plantilla_id, plantilla_version,
        nombre_hallazgo, severidad, descripcion, evidencia)``. Cada fila se guarda con
        ``estado_revision`` inicial ``'nuevo'`` (ver :meth:`actualizar_estado_revision_nuclei`
        para marcarlo como confirmado o falso positivo mas adelante). Misma semantica de
        atomicidad que :meth:`agregar_resultados_nmap`: un analisis cancelado no llega a
        llamar a este metodo, por lo que no queda ningun hallazgo parcial.
        """
        guardados: list[ResultadoNuclei] = []
        with self._conectar() as conexion:
            for (
                plantilla_id,
                plantilla_version,
                nombre_hallazgo,
                severidad,
                descripcion,
                evidencia,
            ) in resultados:
                cursor = conexion.execute(
                    "INSERT INTO resultados_nuclei (proyecto_id, objetivo, plantilla_id, "
                    "plantilla_version, nombre_hallazgo, severidad, descripcion, evidencia, "
                    "estado_revision, creado_en) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        proyecto_id,
                        objetivo,
                        plantilla_id,
                        plantilla_version,
                        nombre_hallazgo,
                        severidad,
                        descripcion,
                        evidencia,
                        "nuevo",
                        _ahora(),
                    ),
                )
                fila = conexion.execute(
                    "SELECT id, proyecto_id, objetivo, plantilla_id, plantilla_version, "
                    "nombre_hallazgo, severidad, descripcion, evidencia, estado_revision, "
                    "creado_en FROM resultados_nuclei WHERE id = ?",
                    (cursor.lastrowid,),
                ).fetchone()
                guardados.append(ResultadoNuclei(**fila))
        return guardados

    def listar_resultados_nuclei(
        self, proyecto_id: int | None = None, limite: int = 200
    ) -> list[ResultadoNuclei]:
        columnas = (
            "id, proyecto_id, objetivo, plantilla_id, plantilla_version, nombre_hallazgo, "
            "severidad, descripcion, evidencia, estado_revision, creado_en"
        )
        with self._conectar() as conexion:
            if proyecto_id is None:
                filas = conexion.execute(
                    f"SELECT {columnas} FROM resultados_nuclei ORDER BY creado_en DESC LIMIT ?",
                    (limite,),
                ).fetchall()
            else:
                filas = conexion.execute(
                    f"SELECT {columnas} FROM resultados_nuclei WHERE proyecto_id = ? "
                    "ORDER BY creado_en DESC LIMIT ?",
                    (proyecto_id, limite),
                ).fetchall()
        return [ResultadoNuclei(**fila) for fila in filas]

    def actualizar_estado_revision_nuclei(self, id_: int, estado_revision: str) -> None:
        with self._conectar() as conexion:
            conexion.execute(
                "UPDATE resultados_nuclei SET estado_revision = ? WHERE id = ?",
                (estado_revision, id_),
            )

    # -- Resultados de OWASP ZAP -----------------------------------------
    def agregar_resultados_zap(
        self,
        proyecto_id: int,
        objetivo: str,
        resultados: list[tuple[str, str, str, str, str, str | None, str, str | None]],
    ) -> list[ResultadoZAP]:
        """Inserta hallazgos de ZAP en una sola transaccion (todo o nada).

        ``resultados`` es una lista de ``(plugin_id, nombre_hallazgo, riesgo, confianza,
        descripcion, evidencia, solucion, referencia)``. Cada fila se guarda con
        ``estado_revision`` inicial ``'nuevo'``. Misma semantica de atomicidad que
        :meth:`agregar_resultados_nuclei`: un analisis cancelado no llega a llamar a este
        metodo, por lo que no queda ningun hallazgo parcial.
        """
        guardados: list[ResultadoZAP] = []
        with self._conectar() as conexion:
            for (
                plugin_id,
                nombre_hallazgo,
                riesgo,
                confianza,
                descripcion,
                evidencia,
                solucion,
                referencia,
            ) in resultados:
                cursor = conexion.execute(
                    "INSERT INTO resultados_zap (proyecto_id, objetivo, plugin_id, "
                    "nombre_hallazgo, riesgo, confianza, descripcion, evidencia, solucion, "
                    "referencia, estado_revision, creado_en) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        proyecto_id,
                        objetivo,
                        plugin_id,
                        nombre_hallazgo,
                        riesgo,
                        confianza,
                        descripcion,
                        evidencia,
                        solucion,
                        referencia,
                        "nuevo",
                        _ahora(),
                    ),
                )
                fila = conexion.execute(
                    "SELECT id, proyecto_id, objetivo, plugin_id, nombre_hallazgo, riesgo, "
                    "confianza, descripcion, evidencia, solucion, referencia, estado_revision, "
                    "creado_en FROM resultados_zap WHERE id = ?",
                    (cursor.lastrowid,),
                ).fetchone()
                guardados.append(ResultadoZAP(**fila))
        return guardados

    def listar_resultados_zap(
        self, proyecto_id: int | None = None, limite: int = 200
    ) -> list[ResultadoZAP]:
        columnas = (
            "id, proyecto_id, objetivo, plugin_id, nombre_hallazgo, riesgo, confianza, "
            "descripcion, evidencia, solucion, referencia, estado_revision, creado_en"
        )
        with self._conectar() as conexion:
            if proyecto_id is None:
                filas = conexion.execute(
                    f"SELECT {columnas} FROM resultados_zap ORDER BY creado_en DESC LIMIT ?",
                    (limite,),
                ).fetchall()
            else:
                filas = conexion.execute(
                    f"SELECT {columnas} FROM resultados_zap WHERE proyecto_id = ? "
                    "ORDER BY creado_en DESC LIMIT ?",
                    (proyecto_id, limite),
                ).fetchall()
        return [ResultadoZAP(**fila) for fila in filas]

    def actualizar_estado_revision_zap(self, id_: int, estado_revision: str) -> None:
        with self._conectar() as conexion:
            conexion.execute(
                "UPDATE resultados_zap SET estado_revision = ? WHERE id = ?",
                (estado_revision, id_),
            )

    # -- Vista unificada de resultados ----------------------------------
    def listar_resultados_unificados(
        self,
        proyecto_id: int | None = None,
        *,
        fuentes: frozenset[str] | None = None,
        severidad: str | None = None,
        estado: str | None = None,
        desde: str | None = None,
        hasta: str | None = None,
        limite: int = 200,
    ) -> list[ResultadoUnificado]:
        """Combina los resultados de las cinco tablas existentes en una sola vista.

        No crea ninguna tabla nueva ni modifica las existentes: cada fuente conserva su
        tabla y sus propios metodos ``agregar_resultados*``/``listar_resultados*`` (las
        consultas por herramienta, p. ej. ``est nuclei resultados``/``est zap
        resultados``, siguen usando esos metodos directamente y no pasan por este). Esta
        vista es de solo lectura: pide a cada fuente seleccionada sus filas mas
        recientes, las normaliza a :class:`ResultadoUnificado` y fusiona/ordena/filtra el
        resultado en Python (SQLite no tiene una sola tabla de la que hacer ``UNION``,
        ya que las columnas de cada fuente son distintas por diseno).

        ``severidad`` y ``estado`` filtran por grupo/igualdad insensible a mayusculas
        (ver :func:`agrupar_severidad`) para poder comparar, p. ej., 'alta' (auditoria
        web) con 'high' (Nuclei) o 'critical' (ZAP) sin renombrar el valor original de
        ningun registro. ``estado`` compara contra ``estado`` O ``estado_revision``
        (son mutuamente excluyentes por fuente: nunca ambos a la vez en la misma fila).
        ``desde``/``hasta`` comparan ``creado_en`` como texto ISO-8601 (comparacion
        lexicografica correcta para ese formato).
        """
        fuentes_activas = fuentes if fuentes is not None else frozenset(FUENTES_RESULTADOS)
        # Se pide un margen mayor que 'limite' a cada fuente porque los filtros se
        # aplican DESPUES de fusionar: si se pidiera solo 'limite' filas por fuente, un
        # filtro restrictivo podria descartar casi todas y devolver menos resultados de
        # los que en realidad existen dentro de la ventana solicitada.
        limite_por_fuente = max(limite, 500)

        combinados: list[ResultadoUnificado] = []
        if "tcp" in fuentes_activas:
            combinados.extend(
                _normalizar_tcp(r)
                for r in self.listar_resultados(proyecto_id, limite=limite_por_fuente)
            )
        if "nmap" in fuentes_activas:
            combinados.extend(
                _normalizar_nmap(r)
                for r in self.listar_resultados_nmap(proyecto_id, limite=limite_por_fuente)
            )
        if "web" in fuentes_activas:
            combinados.extend(
                _normalizar_web(r)
                for r in self.listar_resultados_web(proyecto_id, limite=limite_por_fuente)
            )
        if "nuclei" in fuentes_activas:
            combinados.extend(
                _normalizar_nuclei(r)
                for r in self.listar_resultados_nuclei(proyecto_id, limite=limite_por_fuente)
            )
        if "zap" in fuentes_activas:
            combinados.extend(
                _normalizar_zap(r)
                for r in self.listar_resultados_zap(proyecto_id, limite=limite_por_fuente)
            )

        if severidad is not None:
            grupo_buscado = agrupar_severidad(severidad)
            combinados = [r for r in combinados if agrupar_severidad(r.severidad) == grupo_buscado]
        if estado is not None:
            estado_bajo = estado.lower()
            combinados = [
                r
                for r in combinados
                if (r.estado or "").lower() == estado_bajo
                or (r.estado_revision or "").lower() == estado_bajo
            ]
        if desde is not None:
            combinados = [r for r in combinados if r.creado_en >= desde]
        if hasta is not None:
            combinados = [r for r in combinados if r.creado_en <= hasta]

        combinados.sort(key=lambda r: r.creado_en, reverse=True)
        return combinados[:limite]

    # -- Sesiones de reconocimiento automatico --------------------------
    def crear_sesion_reconocimiento(
        self, proyecto_id: int, objetivo_original: str, perfil: str
    ) -> SesionReconocimiento:
        ahora = _ahora()
        with self._conectar() as conexion:
            cursor = conexion.execute(
                "INSERT INTO sesiones_reconocimiento (proyecto_id, objetivo_original, "
                "nombre_host, ip, perfil, estado_general, etapas_json, limitaciones_json, "
                "ruta_informe_html, ruta_informe_json, creado_en, actualizado_en) "
                "VALUES (?, ?, NULL, NULL, ?, 'ejecutando', '[]', '[]', NULL, NULL, ?, ?)",
                (proyecto_id, objetivo_original, perfil, ahora, ahora),
            )
            nuevo_id = cursor.lastrowid
        return self.obtener_sesion_reconocimiento(nuevo_id)  # type: ignore[arg-type]

    def actualizar_sesion_reconocimiento(
        self,
        id_: int,
        *,
        nombre_host: str | None = None,
        ip: str | None = None,
        estado_general: str | None = None,
        etapas: list[dict] | None = None,
        limitaciones: list[str] | None = None,
        ruta_informe_html: str | None = None,
        ruta_informe_json: str | None = None,
    ) -> SesionReconocimiento:
        """Actualiza los campos indicados de una sesion; el resto se conserva tal cual.

        ``etapas`` y ``limitaciones`` son listas de datos primitivos (diccionarios y
        strings respectivamente) que se serializan aqui a JSON: el llamador (el
        orquestador) es quien convierte sus propias dataclasses antes de llamar a esto.
        """
        actual = self.obtener_sesion_reconocimiento(id_)
        conexion_nombre_host = nombre_host if nombre_host is not None else actual.nombre_host
        conexion_ip = ip if ip is not None else actual.ip
        conexion_estado = estado_general if estado_general is not None else actual.estado_general
        conexion_etapas_json = json.dumps(etapas) if etapas is not None else actual.etapas_json
        conexion_limitaciones_json = (
            json.dumps(limitaciones) if limitaciones is not None else actual.limitaciones_json
        )
        conexion_ruta_html = (
            ruta_informe_html if ruta_informe_html is not None else actual.ruta_informe_html
        )
        conexion_ruta_json = (
            ruta_informe_json if ruta_informe_json is not None else actual.ruta_informe_json
        )
        with self._conectar() as conexion:
            conexion.execute(
                "UPDATE sesiones_reconocimiento SET nombre_host = ?, ip = ?, "
                "estado_general = ?, etapas_json = ?, limitaciones_json = ?, "
                "ruta_informe_html = ?, ruta_informe_json = ?, actualizado_en = ? "
                "WHERE id = ?",
                (
                    conexion_nombre_host,
                    conexion_ip,
                    conexion_estado,
                    conexion_etapas_json,
                    conexion_limitaciones_json,
                    conexion_ruta_html,
                    conexion_ruta_json,
                    _ahora(),
                    id_,
                ),
            )
        return self.obtener_sesion_reconocimiento(id_)

    def obtener_sesion_reconocimiento(self, id_: int) -> SesionReconocimiento:
        with self._conectar() as conexion:
            fila = conexion.execute(
                "SELECT id, proyecto_id, objetivo_original, nombre_host, ip, perfil, "
                "estado_general, etapas_json, limitaciones_json, ruta_informe_html, "
                "ruta_informe_json, creado_en, actualizado_en "
                "FROM sesiones_reconocimiento WHERE id = ?",
                (id_,),
            ).fetchone()
        if fila is None:
            raise ErrorSesionReconocimientoNoEncontrada(
                f"No existe una sesion de reconocimiento con id {id_}."
            )
        return SesionReconocimiento(**fila)

    def listar_sesiones_reconocimiento(
        self, proyecto_id: int | None = None, limite: int = 50
    ) -> list[SesionReconocimiento]:
        columnas = (
            "id, proyecto_id, objetivo_original, nombre_host, ip, perfil, estado_general, "
            "etapas_json, limitaciones_json, ruta_informe_html, ruta_informe_json, "
            "creado_en, actualizado_en"
        )
        with self._conectar() as conexion:
            if proyecto_id is None:
                filas = conexion.execute(
                    f"SELECT {columnas} FROM sesiones_reconocimiento "
                    "ORDER BY creado_en DESC LIMIT ?",
                    (limite,),
                ).fetchall()
            else:
                filas = conexion.execute(
                    f"SELECT {columnas} FROM sesiones_reconocimiento WHERE proyecto_id = ? "
                    "ORDER BY creado_en DESC LIMIT ?",
                    (proyecto_id, limite),
                ).fetchall()
        return [SesionReconocimiento(**fila) for fila in filas]

    # -- Investigaciones OSINT ------------------------------------------
    _COLUMNAS_INVESTIGACION_OSINT = (
        "id, proyecto_id, tipo_objetivo, objetivo_original, objetivo_saneado, "
        "autorizado_datos_personales, fuentes_json, estado_general, etapas_json, "
        "limitaciones_json, ruta_informe_html, ruta_informe_json, creado_en, actualizado_en"
    )

    @staticmethod
    def _fila_a_investigacion_osint(fila: sqlite3.Row) -> InvestigacionOSINT:
        datos = dict(fila)
        datos["autorizado_datos_personales"] = bool(datos["autorizado_datos_personales"])
        return InvestigacionOSINT(**datos)

    def crear_investigacion_osint(
        self,
        proyecto_id: int,
        tipo_objetivo: str,
        objetivo_original: str,
        objetivo_saneado: str,
        autorizado_datos_personales: bool,
        fuentes_seleccionadas: list[str],
    ) -> InvestigacionOSINT:
        ahora = _ahora()
        with self._conectar() as conexion:
            cursor = conexion.execute(
                "INSERT INTO investigaciones_osint (proyecto_id, tipo_objetivo, "
                "objetivo_original, objetivo_saneado, autorizado_datos_personales, "
                "fuentes_json, estado_general, etapas_json, limitaciones_json, "
                "ruta_informe_html, ruta_informe_json, creado_en, actualizado_en) "
                "VALUES (?, ?, ?, ?, ?, ?, 'ejecutando', '[]', '[]', NULL, NULL, ?, ?)",
                (
                    proyecto_id,
                    tipo_objetivo,
                    objetivo_original,
                    objetivo_saneado,
                    int(autorizado_datos_personales),
                    json.dumps(fuentes_seleccionadas),
                    ahora,
                    ahora,
                ),
            )
            nuevo_id = cursor.lastrowid
        return self.obtener_investigacion_osint(nuevo_id)  # type: ignore[arg-type]

    def actualizar_investigacion_osint(
        self,
        id_: int,
        *,
        estado_general: str | None = None,
        etapas: list[dict] | None = None,
        limitaciones: list[str] | None = None,
        ruta_informe_html: str | None = None,
        ruta_informe_json: str | None = None,
    ) -> InvestigacionOSINT:
        actual = self.obtener_investigacion_osint(id_)
        nuevo_estado = estado_general if estado_general is not None else actual.estado_general
        nuevas_etapas_json = json.dumps(etapas) if etapas is not None else actual.etapas_json
        nuevas_limitaciones_json = (
            json.dumps(limitaciones) if limitaciones is not None else actual.limitaciones_json
        )
        nueva_ruta_html = (
            ruta_informe_html if ruta_informe_html is not None else actual.ruta_informe_html
        )
        nueva_ruta_json = (
            ruta_informe_json if ruta_informe_json is not None else actual.ruta_informe_json
        )
        with self._conectar() as conexion:
            conexion.execute(
                "UPDATE investigaciones_osint SET estado_general = ?, etapas_json = ?, "
                "limitaciones_json = ?, ruta_informe_html = ?, ruta_informe_json = ?, "
                "actualizado_en = ? WHERE id = ?",
                (
                    nuevo_estado,
                    nuevas_etapas_json,
                    nuevas_limitaciones_json,
                    nueva_ruta_html,
                    nueva_ruta_json,
                    _ahora(),
                    id_,
                ),
            )
        return self.obtener_investigacion_osint(id_)

    def obtener_investigacion_osint(self, id_: int) -> InvestigacionOSINT:
        with self._conectar() as conexion:
            fila = conexion.execute(
                f"SELECT {self._COLUMNAS_INVESTIGACION_OSINT} FROM investigaciones_osint "
                "WHERE id = ?",
                (id_,),
            ).fetchone()
        if fila is None:
            raise ErrorInvestigacionOSINTNoEncontrada(
                f"No existe una investigacion OSINT con id {id_}."
            )
        return self._fila_a_investigacion_osint(fila)

    def listar_investigaciones_osint(
        self, proyecto_id: int | None = None, limite: int = 50
    ) -> list[InvestigacionOSINT]:
        with self._conectar() as conexion:
            if proyecto_id is None:
                filas = conexion.execute(
                    f"SELECT {self._COLUMNAS_INVESTIGACION_OSINT} FROM investigaciones_osint "
                    "ORDER BY creado_en DESC LIMIT ?",
                    (limite,),
                ).fetchall()
            else:
                filas = conexion.execute(
                    f"SELECT {self._COLUMNAS_INVESTIGACION_OSINT} FROM investigaciones_osint "
                    "WHERE proyecto_id = ? ORDER BY creado_en DESC LIMIT ?",
                    (proyecto_id, limite),
                ).fetchall()
        return [self._fila_a_investigacion_osint(fila) for fila in filas]

    def eliminar_investigacion_osint(self, id_: int) -> None:
        """Borra la investigacion y todos sus hallazgos, en una sola transaccion.

        No depende de ``ON DELETE CASCADE`` (SQLite no lo aplica salvo que
        ``PRAGMA foreign_keys`` este activada en la conexion, y esta capa no la activa
        hoy para ninguna tabla): borra ``hallazgos_osint`` explicitamente antes de
        borrar la investigacion, dentro de la misma transaccion.
        """
        self.obtener_investigacion_osint(id_)  # ErrorInvestigacionOSINTNoEncontrada si no existe
        with self._conectar() as conexion:
            conexion.execute("DELETE FROM hallazgos_osint WHERE investigacion_id = ?", (id_,))
            conexion.execute("DELETE FROM investigaciones_osint WHERE id = ?", (id_,))

    def purgar_investigaciones_osint_expiradas(self, dias: int) -> int:
        """Borra (con sus hallazgos) toda investigacion OSINT creada hace mas de
        ``dias`` dias: politica de retencion explicita (ver docs/OSINT.md), nunca
        automatica/silenciosa -- quien llama a esto (``est osint purgar``) decide
        cuando ejecutarla. Devuelve cuantas investigaciones se borraron.
        """
        limite = (datetime.now(UTC) - timedelta(days=dias)).isoformat()
        with self._conectar() as conexion:
            ids = [
                fila["id"]
                for fila in conexion.execute(
                    "SELECT id FROM investigaciones_osint WHERE creado_en < ?", (limite,)
                ).fetchall()
            ]
            if ids:
                marcadores = ",".join("?" * len(ids))
                conexion.execute(
                    f"DELETE FROM hallazgos_osint WHERE investigacion_id IN ({marcadores})", ids
                )
                conexion.execute(
                    f"DELETE FROM investigaciones_osint WHERE id IN ({marcadores})", ids
                )
        return len(ids)

    # -- Hallazgos OSINT -------------------------------------------------
    _COLUMNAS_HALLAZGO_OSINT = (
        "id, investigacion_id, proyecto_id, fuente, categoria, titulo, descripcion, "
        "nivel_confianza, indicador_exposicion, evidencias_json, creado_en"
    )

    def agregar_hallazgos_osint(
        self, investigacion_id: int, proyecto_id: int, fuente: str, hallazgos: list[dict]
    ) -> list[HallazgoOSINTGuardado]:
        """Inserta los hallazgos de UNA fuente en una sola transaccion (todo o nada).

        ``hallazgos`` es una lista de ``HallazgoOSINT.como_dict()`` (ver
        ``modules/osint/modelos.py``). Misma semantica de atomicidad que
        :meth:`agregar_resultados_nmap`: si la investigacion se cancela antes de que una
        fuente termine, esta funcion no llega a invocarse para ella y no queda ningun
        hallazgo parcial de esa fuente.
        """
        guardados: list[HallazgoOSINTGuardado] = []
        with self._conectar() as conexion:
            for hallazgo in hallazgos:
                evidencias_json = json.dumps(hallazgo["evidencias"])
                cursor = conexion.execute(
                    "INSERT INTO hallazgos_osint (investigacion_id, proyecto_id, fuente, "
                    "categoria, titulo, descripcion, nivel_confianza, indicador_exposicion, "
                    "evidencias_json, creado_en) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        investigacion_id,
                        proyecto_id,
                        fuente,
                        hallazgo["categoria"],
                        hallazgo["titulo"],
                        hallazgo["descripcion"],
                        hallazgo["nivel_confianza"],
                        hallazgo["indicador_exposicion"],
                        evidencias_json,
                        _ahora(),
                    ),
                )
                fila = conexion.execute(
                    f"SELECT {self._COLUMNAS_HALLAZGO_OSINT} FROM hallazgos_osint WHERE id = ?",
                    (cursor.lastrowid,),
                ).fetchone()
                guardados.append(HallazgoOSINTGuardado(**dict(fila)))
        return guardados

    def listar_hallazgos_osint(
        self,
        investigacion_id: int | None = None,
        proyecto_id: int | None = None,
        limite: int = 500,
        desplazamiento: int = 0,
    ) -> list[HallazgoOSINTGuardado]:
        """``desplazamiento`` (OFFSET) permite paginar un numero de hallazgos mayor que
        ``limite`` sin tener que traerlos todos de una vez (ver ``est osint resultados
        --pagina``)."""
        condiciones: list[str] = []
        parametros: list[object] = []
        if investigacion_id is not None:
            condiciones.append("investigacion_id = ?")
            parametros.append(investigacion_id)
        if proyecto_id is not None:
            condiciones.append("proyecto_id = ?")
            parametros.append(proyecto_id)
        clausula = f"WHERE {' AND '.join(condiciones)}" if condiciones else ""
        parametros.extend([limite, desplazamiento])
        with self._conectar() as conexion:
            filas = conexion.execute(
                f"SELECT {self._COLUMNAS_HALLAZGO_OSINT} FROM hallazgos_osint {clausula} "
                "ORDER BY creado_en DESC, id DESC LIMIT ? OFFSET ?",
                parametros,
            ).fetchall()
        return [HallazgoOSINTGuardado(**dict(fila)) for fila in filas]

    def contar_hallazgos_osint(
        self, investigacion_id: int | None = None, proyecto_id: int | None = None
    ) -> int:
        """Total de hallazgos que coinciden con los filtros (sin aplicar limite ni
        desplazamiento): usado para que la CLI pueda mostrar 'pagina X de Y'."""
        condiciones: list[str] = []
        parametros: list[object] = []
        if investigacion_id is not None:
            condiciones.append("investigacion_id = ?")
            parametros.append(investigacion_id)
        if proyecto_id is not None:
            condiciones.append("proyecto_id = ?")
            parametros.append(proyecto_id)
        clausula = f"WHERE {' AND '.join(condiciones)}" if condiciones else ""
        with self._conectar() as conexion:
            fila = conexion.execute(
                f"SELECT COUNT(*) AS total FROM hallazgos_osint {clausula}", parametros
            ).fetchone()
        return int(fila["total"])
