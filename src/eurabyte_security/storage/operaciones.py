"""Casos de auditoría, evidencias y mediciones defensivas por proyecto."""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime

from eurabyte_security.core.errores import ErrorValidacion
from eurabyte_security.core.redaccion import redactar_texto_libre
from eurabyte_security.storage.database import (
    BaseDatos,
    Resultado,
    ResultadoNmap,
    ResultadoNuclei,
    ResultadoWeb,
    ResultadoZAP,
    _ahora,
    _normalizar_nmap,
    _normalizar_nuclei,
    _normalizar_tcp,
    _normalizar_web,
    _normalizar_zap,
)

_ORIGENES = {
    "tcp": ("resultados", Resultado, _normalizar_tcp),
    "nmap": ("resultados_nmap", ResultadoNmap, _normalizar_nmap),
    "web": ("resultados_web", ResultadoWeb, _normalizar_web),
    "nuclei": ("resultados_nuclei", ResultadoNuclei, _normalizar_nuclei),
    "zap": ("resultados_zap", ResultadoZAP, _normalizar_zap),
}
ACCIONES = {
    "asignar": "Asignar responsable",
    "corregir": "Registrar corrección",
    "verificar": "Verificar y cerrar",
    "reabrir": "Reabrir",
    "ejercicio": "Registrar ejercicio acordado",
    "deteccion": "Vincular alerta a un ejercicio",
    "nota": "Añadir evidencia manual",
}
_ESQUEMA = """
CREATE TABLE IF NOT EXISTS casos_ast (
    id INTEGER PRIMARY KEY, proyecto_id INTEGER NOT NULL REFERENCES proyectos(id),
    activo TEXT NOT NULL, titulo TEXT NOT NULL, gravedad TEXT NOT NULL,
    estado TEXT NOT NULL, responsable TEXT NOT NULL DEFAULT '', creado TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS casos_ast_activo ON casos_ast(proyecto_id, activo);
CREATE TABLE IF NOT EXISTS eventos_caso_ast (
    id INTEGER PRIMARY KEY, caso_id INTEGER NOT NULL REFERENCES casos_ast(id),
    tipo TEXT NOT NULL, detalle TEXT NOT NULL, fecha TEXT NOT NULL,
    fuente TEXT, id_origen INTEGER, ejercicio_id INTEGER REFERENCES eventos_caso_ast(id),
    UNIQUE(caso_id, fuente, id_origen)
);
CREATE INDEX IF NOT EXISTS eventos_ast_caso ON eventos_caso_ast(caso_id, fecha);
CREATE TABLE IF NOT EXISTS muestras_ast (
    id INTEGER PRIMARY KEY, proyecto_id INTEGER NOT NULL REFERENCES proyectos(id),
    fecha TEXT NOT NULL, interfaz TEXT NOT NULL, segundos REAL NOT NULL,
    carga INTEGER NOT NULL, descarga INTEGER NOT NULL, umbral REAL NOT NULL, alerta INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS muestras_ast_proyecto ON muestras_ast(proyecto_id, interfaz, id);
"""


def _texto(valor, limite=2000):
    limpio = redactar_texto_libre(str(valor).strip())
    if not limpio or len(limpio) > limite or any(not c.isprintable() and c != "\n" for c in limpio):
        raise ErrorValidacion(f"Introduce texto válido de hasta {limite} caracteres.")
    return limpio


def _fecha(valor):
    if not valor:
        return _ahora()
    try:
        fecha = datetime.fromisoformat(valor)
        if fecha.tzinfo is None:
            raise ValueError
        return fecha.astimezone(UTC).isoformat()
    except (ValueError, OverflowError) as exc:
        raise ErrorValidacion("Introduce una fecha ISO con zona horaria.") from exc


class Operaciones(BaseDatos):
    def __init__(self, ruta=None):
        super().__init__(ruta)
        with self._conectar() as cn:
            cn.executescript(_ESQUEMA)

    def crear(self, proyecto, activo, titulo, gravedad, evidencia):
        if gravedad not in ("informativa", "baja", "media", "alta", "critica"):
            raise ErrorValidacion("Selecciona una gravedad válida.")
        fecha = _ahora()
        with self._conectar() as cn:
            caso = cn.execute(
                "INSERT INTO casos_ast(proyecto_id,activo,titulo,gravedad,estado,creado) "
                "VALUES(?,?,?,?,'abierto',?)",
                (proyecto, _texto(activo, 512), _texto(titulo, 200), gravedad, fecha),
            ).lastrowid
            cn.execute(
                "INSERT INTO eventos_caso_ast(caso_id,tipo,detalle,fecha) VALUES(?,'apertura',?,?)",
                (caso, _texto(evidencia), fecha),
            )
        return caso

    def listar(self, proyecto, activo=None):
        with self._conectar() as cn:
            filas = cn.execute(
                "SELECT * FROM casos_ast WHERE proyecto_id=? AND (? IS NULL OR activo=?) "
                "ORDER BY id DESC", (proyecto, activo, activo),
            )
            return [dict(f) for f in filas]

    @staticmethod
    def _caso(cn, proyecto, caso):
        fila = cn.execute(
            "SELECT * FROM casos_ast WHERE proyecto_id=? AND id=?", (proyecto, caso),
        ).fetchone()
        if fila is None:
            raise ErrorValidacion("El caso no existe en el proyecto activo.")
        return dict(fila)

    def detalle(self, proyecto, caso):
        with self._conectar() as cn:
            cn.execute("BEGIN")
            resultado = self._caso(cn, proyecto, caso)
            eventos = [dict(f) for f in cn.execute(
                "SELECT * FROM eventos_caso_ast WHERE caso_id=? ORDER BY fecha,id", (caso,),
            )]
        ejercicios = {e["id"]: e for e in eventos if e["tipo"] == "ejercicio"}
        for evento in eventos:
            if evento["ejercicio_id"] in ejercicios:
                inicio = ejercicios[evento["ejercicio_id"]]["fecha"]
                evento["segundos_hasta_deteccion"] = (
                    datetime.fromisoformat(evento["fecha"]) - datetime.fromisoformat(inicio)
                ).total_seconds()
        resultado["eventos"] = eventos
        return resultado

    def vincular(self, proyecto, caso, fuente, origen):
        if fuente not in _ORIGENES:
            raise ErrorValidacion("Fuente de evidencia desconocida.")
        tabla, modelo, normalizar = _ORIGENES[fuente]
        with self._conectar() as cn:
            cn.execute("BEGIN IMMEDIATE")
            self._caso(cn, proyecto, caso)
            fila = cn.execute(
                f"SELECT * FROM {tabla} WHERE proyecto_id=? AND id=?", (proyecto, origen),
            ).fetchone()
            if fila is None:
                raise ErrorValidacion("Ese resultado no existe en el proyecto activo.")
            r = asdict(normalizar(modelo(**dict(fila))))
            detalle = "\n".join(f"{k}: {r[k]}" for k in (
                "objetivo", "nombre", "estado", "severidad", "descripcion", "evidencia",
            ) if r[k])
            cn.execute(
                "INSERT INTO eventos_caso_ast(caso_id,tipo,detalle,fecha,fuente,id_origen) "
                "VALUES(?,'resultado',?,?,?,?) ON CONFLICT(caso_id,fuente,id_origen) DO NOTHING",
                (caso, redactar_texto_libre(detalle), r["creado_en"], fuente, origen),
            )

    def registrar(self, proyecto, caso, accion, detalle, fecha=None, ejercicio=None):
        if accion not in ACCIONES:
            raise ErrorValidacion("Acción desconocida.")
        detalle = _texto(detalle, 150 if accion == "asignar" else 2000)
        instante = _fecha(fecha)
        with self._conectar() as cn:
            cn.execute("BEGIN IMMEDIATE")
            actual = self._caso(cn, proyecto, caso)
            estado = actual["estado"]
            if accion == "deteccion":
                base = cn.execute(
                    "SELECT fecha FROM eventos_caso_ast WHERE caso_id=? AND id=?"
                    " AND tipo='ejercicio'",
                    (caso, ejercicio),
                ).fetchone()
                if not base or instante < base["fecha"]:
                    raise ErrorValidacion("Vincula un ejercicio del caso anterior a la detección.")
            elif ejercicio is not None:
                raise ErrorValidacion("Solo una detección se vincula a un ejercicio.")
            if accion == "verificar" and estado != "corregido":
                raise ErrorValidacion("Primero registra la corrección del caso.")
            if accion == "reabrir" and estado != "verificado":
                raise ErrorValidacion("Solo se puede reabrir un caso verificado.")
            if accion == "corregir" and estado == "verificado":
                raise ErrorValidacion("Reabre el caso antes de registrar una nueva corrección.")
            nuevo = {"verificar": "verificado", "corregir": "corregido", "reabrir": "abierto"}
            cn.execute(
                "UPDATE casos_ast SET estado=?, responsable=? WHERE id=?",
                (nuevo.get(accion, estado),
                 detalle if accion == "asignar" else actual["responsable"], caso),
            )
            return cn.execute(
                "INSERT INTO eventos_caso_ast(caso_id,tipo,detalle,fecha,ejercicio_id) "
                "VALUES(?,?,?,?,?)", (caso, accion, detalle, instante, ejercicio),
            ).lastrowid

    def guardar_muestra(self, proyecto, medicion, umbral):
        if not 0 < umbral <= 1_000_000:
            raise ErrorValidacion("El umbral debe estar entre 0 y 1 000 000 Mbps.")
        fecha = _ahora()
        with self._conectar() as cn:
            cn.execute("BEGIN IMMEDIATE")
            for interfaz, v in medicion.interfaces.items():
                velocidad = max(v.carga, v.descarga) * 8 / medicion.segundos / 1e6
                cn.execute(
                    "INSERT INTO muestras_ast(proyecto_id,fecha,interfaz,segundos,carga,"
                    "descarga,umbral,alerta) VALUES(?,?,?,?,?,?,?,?)",
                    (proyecto, fecha, interfaz, medicion.segundos, v.carga, v.descarga,
                     umbral, velocidad >= umbral),
                )

    def muestras(self, proyecto, limite=100):
        with self._conectar() as cn:
            return [dict(f) for f in cn.execute(
                "SELECT * FROM muestras_ast WHERE proyecto_id=? ORDER BY id DESC LIMIT ?",
                (proyecto, limite),
            )]
