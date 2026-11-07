"""Motor de comandos de la pestaña Terminal AST.

Interpreta texto escrito por el usuario y lo ejecuta llamando directamente a
la logica interna de EST (los mismos modulos ``commands/*``, ``core`` y
``storage`` que usa la CLI). No crea un proceso ni invoca un shell del
sistema: el "registro de comandos" es el diccionario ``ARBOL_COMANDOS`` de
este modulo, resuelto a mano contra funciones puras ya existentes.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from typing import Any

from rich.table import Table

from eurabyte_security.commands._comun import obtener_base_datos, resolver_proyecto
from eurabyte_security.commands.alcance import agregar_alcance as _agregar_alcance
from eurabyte_security.commands.alcance import listar_alcance as _listar_alcance
from eurabyte_security.commands.escanear import escanear_tcp as _escanear_tcp
from eurabyte_security.commands.explicar import EXPLICACIONES
from eurabyte_security.commands.proyecto import crear_proyecto as _crear_proyecto
from eurabyte_security.commands.proyecto import listar_proyectos as _listar_proyectos
from eurabyte_security.commands.proyecto import usar_proyecto as _usar_proyecto
from eurabyte_security.commands.reporte import generar_reporte as _generar_reporte
from eurabyte_security.commands.resultados import obtener_resultados as _obtener_resultados
from eurabyte_security.core.errores import ErrorEST, ErrorValidacion

COMANDOS_SALIDA = {"salir", "exit", "quit"}

ARBOL_COMANDOS: dict[str, dict[str, Any] | None] = {
    "proyecto": {"crear": None, "listar": None, "usar": None},
    "alcance": {"agregar": None, "listar": None},
    "escanear": {"tcp": None},
    "explicar": dict.fromkeys(EXPLICACIONES),
    "resultados": None,
    "reporte": {"generar": None},
    "ayuda": None,
    "salir": None,
}

_ESTILOS_ESTADO = {"abierto": "bold green", "cerrado": "grey70", "error": "bold red"}


@dataclass(frozen=True, slots=True)
class ResultadoComando:
    exito: bool
    contenido: Any  # str o un renderable de Rich (Table, etc.)


def _tabla_proyectos(base_datos) -> Table:
    proyectos, activo = _listar_proyectos(base_datos)
    tabla = Table(title="Proyectos")
    tabla.add_column("Activo")
    tabla.add_column("Nombre")
    tabla.add_column("Creado")
    for proyecto in proyectos:
        tabla.add_row("*" if proyecto.nombre == activo else "", proyecto.nombre, proyecto.creado_en)
    return tabla


def _tabla_alcance(alcances, titulo: str) -> Table:
    tabla = Table(title=titulo)
    tabla.add_column("Red")
    tabla.add_column("Registrado")
    for alcance in alcances:
        tabla.add_row(alcance.red, alcance.creado_en)
    return tabla


def _tabla_resultados(resultados, titulo: str) -> Table:
    tabla = Table(title=titulo)
    tabla.add_column("Objetivo")
    tabla.add_column("Puerto")
    tabla.add_column("Estado")
    tabla.add_column("Fecha")
    for resultado in resultados:
        estilo = _ESTILOS_ESTADO.get(resultado.estado, "")
        tabla.add_row(
            resultado.objetivo,
            str(resultado.puerto),
            f"[{estilo}]{resultado.estado}[/{estilo}]",
            resultado.creado_en,
        )
    return tabla


def _extraer_opcion(argumentos: list[str], nombre: str) -> tuple[str | None, list[str]]:
    """Extrae '--nombre valor' de una lista de argumentos. Devuelve (valor, resto)."""
    restantes: list[str] = []
    valor: str | None = None
    i = 0
    while i < len(argumentos):
        token = argumentos[i]
        if token == nombre and i + 1 < len(argumentos):
            valor = argumentos[i + 1]
            i += 2
            continue
        restantes.append(token)
        i += 1
    return valor, restantes


def completar(texto: str) -> str | None:
    """Devuelve la unica completion posible para ``texto``, o ``None``.

    Recorre ``ARBOL_COMANDOS`` token a token. Solo completa cuando, para el
    ultimo token escrito, existe exactamente una opcion posible: es el mismo
    comportamiento conservador que usan la mayoria de shells cuando hay
    ambiguedad (no completa nada hasta que el prefijo sea unico).
    """
    if not texto:
        return None

    partes = texto.split(" ")
    if texto.endswith(" "):
        previas, parcial = [p for p in partes if p], ""
    else:
        previas, parcial = partes[:-1], partes[-1]

    nodo: Any = ARBOL_COMANDOS
    for parte in previas:
        if not isinstance(nodo, dict) or parte not in nodo:
            return None
        nodo = nodo[parte]

    if not isinstance(nodo, dict):
        return None

    candidatos = sorted(c for c in nodo if c.startswith(parcial))
    if len(candidatos) != 1 or candidatos[0] == parcial:
        return None

    return " ".join([*previas, candidatos[0]]) + " "


class MotorComandos:
    """Interpreta y ejecuta comandos de texto sobre la logica real de AST."""

    def ejecutar(self, texto: str) -> ResultadoComando | None:
        """Devuelve ``None`` si el texto es una orden de salida (solo aplica en REPL)."""
        texto = texto.strip()
        if not texto:
            return ResultadoComando(True, "")
        if texto in COMANDOS_SALIDA:
            return None

        try:
            argumentos = shlex.split(texto)
        except ValueError as exc:
            return ResultadoComando(False, f"No se pudo interpretar el comando: {exc}")

        if not argumentos:
            return ResultadoComando(True, "")

        try:
            return self._despachar(argumentos)
        except ErrorEST as exc:
            return ResultadoComando(False, str(exc))

    def _despachar(self, argumentos: list[str]) -> ResultadoComando:
        comando, *resto = argumentos

        manejadores = {
            "proyecto": self._proyecto,
            "alcance": self._alcance,
            "escanear": self._escanear,
            "explicar": self._explicar,
            "resultados": self._resultados,
            "reporte": self._reporte,
            "ayuda": lambda _r: ResultadoComando(True, self._ayuda()),
            "--ayuda": lambda _r: ResultadoComando(True, self._ayuda()),
            "--help": lambda _r: ResultadoComando(True, self._ayuda()),
        }
        manejador = manejadores.get(comando)
        if manejador is None:
            return ResultadoComando(
                False, f"Comando desconocido: '{comando}'. Escribe 'ayuda' para ver la lista."
            )
        return manejador(resto)

    def _ayuda(self) -> str:
        lineas = ["Comandos disponibles en la Terminal AST:", ""]
        for nombre, hijos in ARBOL_COMANDOS.items():
            if hijos:
                lineas.append(f"  {nombre} {{{', '.join(hijos)}}}")
            else:
                lineas.append(f"  {nombre}")
        lineas.append("")
        lineas.append("Usa 'explicar <tema>' para una explicacion detallada de cada uno.")
        return "\n".join(lineas)

    # -- proyecto --------------------------------------------------
    def _proyecto(self, resto: list[str]) -> ResultadoComando:
        if not resto:
            return ResultadoComando(False, "Uso: proyecto crear|listar|usar [NOMBRE]")
        subcomando, *args = resto
        base_datos = obtener_base_datos()

        if subcomando == "crear":
            if not args:
                return ResultadoComando(False, "Uso: proyecto crear NOMBRE")
            proyecto = _crear_proyecto(base_datos, args[0])
            return ResultadoComando(
                True, f"Proyecto '{proyecto.nombre}' creado y marcado como activo."
            )
        if subcomando == "listar":
            return ResultadoComando(True, _tabla_proyectos(base_datos))
        if subcomando == "usar":
            if not args:
                return ResultadoComando(False, "Uso: proyecto usar NOMBRE")
            proyecto = _usar_proyecto(base_datos, args[0])
            return ResultadoComando(True, f"Proyecto activo: '{proyecto.nombre}'.")
        return ResultadoComando(False, f"Subcomando desconocido: 'proyecto {subcomando}'.")

    # -- alcance ---------------------------------------------------
    def _alcance(self, resto: list[str]) -> ResultadoComando:
        if not resto:
            return ResultadoComando(False, "Uso: alcance agregar|listar [OBJETIVO]")
        subcomando, *args = resto
        proyecto_nombre, args = _extraer_opcion(args, "--proyecto")
        base_datos = obtener_base_datos()
        proyecto = resolver_proyecto(base_datos, proyecto_nombre)

        if subcomando == "agregar":
            if not args:
                return ResultadoComando(False, "Uso: alcance agregar OBJETIVO [--proyecto NOMBRE]")
            alcance = _agregar_alcance(base_datos, proyecto, args[0])
            return ResultadoComando(
                True, f"Alcance '{alcance.red}' autorizado para '{proyecto.nombre}'."
            )
        if subcomando == "listar":
            alcances = _listar_alcance(base_datos, proyecto)
            return ResultadoComando(
                True, _tabla_alcance(alcances, f"Alcance autorizado - {proyecto.nombre}")
            )
        return ResultadoComando(False, f"Subcomando desconocido: 'alcance {subcomando}'.")

    # -- escanear ----------------------------------------------------
    def _escanear(self, resto: list[str]) -> ResultadoComando:
        if not resto or resto[0] != "tcp":
            return ResultadoComando(False, "Uso: escanear tcp OBJETIVO --puertos 22,80,443")
        args = resto[1:]
        proyecto_nombre, args = _extraer_opcion(args, "--proyecto")
        puertos, args = _extraer_opcion(args, "--puertos")
        timeout_txt, args = _extraer_opcion(args, "--timeout")
        concurrencia_txt, args = _extraer_opcion(args, "--concurrencia")

        if not args:
            return ResultadoComando(
                False, "Falta el objetivo. Uso: escanear tcp OBJETIVO --puertos ..."
            )
        if not puertos:
            return ResultadoComando(False, "Falta --puertos. Ej: --puertos 22,80,443")

        try:
            timeout = float(timeout_txt) if timeout_txt else 1.0
            concurrencia = int(concurrencia_txt) if concurrencia_txt else 50
        except ValueError:
            return ResultadoComando(False, "--timeout y --concurrencia deben ser numericos.")

        base_datos = obtener_base_datos()
        proyecto = resolver_proyecto(base_datos, proyecto_nombre)
        resultados = _escanear_tcp(
            base_datos, proyecto, args[0], puertos, tiempo_espera=timeout, concurrencia=concurrencia
        )
        return ResultadoComando(
            True, _tabla_resultados(resultados, f"Resultado del escaneo TCP - {args[0]}")
        )

    # -- explicar ----------------------------------------------------
    def _explicar(self, resto: list[str]) -> ResultadoComando:
        if not resto:
            temas = ", ".join(sorted(EXPLICACIONES))
            return ResultadoComando(True, f"Indica un tema. Temas disponibles: {temas}")
        texto = EXPLICACIONES.get(resto[0].lower())
        if texto is None:
            temas = ", ".join(sorted(EXPLICACIONES))
            return ResultadoComando(
                True, f"No hay una explicacion para '{resto[0]}'. Temas disponibles: {temas}"
            )
        return ResultadoComando(True, texto)

    # -- resultados --------------------------------------------------
    def _resultados(self, resto: list[str]) -> ResultadoComando:
        proyecto_nombre, resto = _extraer_opcion(resto, "--proyecto")
        limite_txt, _resto = _extraer_opcion(resto, "--limite")
        try:
            limite = int(limite_txt) if limite_txt else 50
        except ValueError:
            return ResultadoComando(False, "--limite debe ser un numero entero.")

        base_datos = obtener_base_datos()
        proyecto = resolver_proyecto(base_datos, proyecto_nombre)
        resultados = _obtener_resultados(base_datos, proyecto, limite=limite)
        titulo = f"Resultados - {proyecto.nombre}"
        return ResultadoComando(True, _tabla_resultados(resultados, titulo))

    # -- reporte -----------------------------------------------------
    def _reporte(self, resto: list[str]) -> ResultadoComando:
        if not resto or resto[0] != "generar":
            return ResultadoComando(False, "Uso: reporte generar --formato html|json")
        args = resto[1:]
        proyecto_nombre, args = _extraer_opcion(args, "--proyecto")
        formato, args = _extraer_opcion(args, "--formato")
        formato = formato or "html"

        base_datos = obtener_base_datos()
        proyecto = resolver_proyecto(base_datos, proyecto_nombre)
        try:
            ruta = _generar_reporte(base_datos, proyecto, formato)
        except ErrorValidacion as exc:
            return ResultadoComando(False, str(exc))
        return ResultadoComando(True, f"Informe generado en: {ruta}")
