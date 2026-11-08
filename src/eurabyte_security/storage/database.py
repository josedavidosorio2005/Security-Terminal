"""Repositorio SQLite para proyectos, alcances y resultados de EST."""

from __future__ import annotations

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from eurabyte_security.core.config import ruta_base_datos
from eurabyte_security.core.errores import ErrorProyectoDuplicado, ErrorProyectoNoEncontrado

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
