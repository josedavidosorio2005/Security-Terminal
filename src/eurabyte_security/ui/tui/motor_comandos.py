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
from eurabyte_security.commands.nuclei import ejecutar_nuclei as _ejecutar_nuclei
from eurabyte_security.commands.proyecto import crear_proyecto as _crear_proyecto
from eurabyte_security.commands.proyecto import listar_proyectos as _listar_proyectos
from eurabyte_security.commands.proyecto import usar_proyecto as _usar_proyecto
from eurabyte_security.commands.reporte import generar_reporte as _generar_reporte
from eurabyte_security.commands.resultados import (
    obtener_resultados_unificados as _obtener_resultados_unificados,
)
from eurabyte_security.commands.web import TIPOS_VALIDOS as _TIPOS_WEB_VALIDOS
from eurabyte_security.commands.web import auditar_web as _auditar_web
from eurabyte_security.commands.zap import ejecutar_zap_pasivo as _ejecutar_zap_pasivo
from eurabyte_security.core.errores import ErrorEST, ErrorValidacion
from eurabyte_security.core.redaccion import redactar_url as _redactar_url
from eurabyte_security.integrations.nuclei import PLANTILLAS_APROBADAS as _PLANTILLAS_NUCLEI
from eurabyte_security.integrations.zap import AdaptadorZAP as _AdaptadorZAP
from eurabyte_security.storage.database import agrupar_severidad as _agrupar_severidad

COMANDOS_SALIDA = {"salir", "exit", "quit"}

ARBOL_COMANDOS: dict[str, dict[str, Any] | None] = {
    "proyecto": {"crear": None, "listar": None, "usar": None},
    "alcance": {"agregar": None, "listar": None},
    "escanear": {"tcp": None},
    "web": {"cabeceras": None, "tls": None, "cookies": None, "auditar": None},
    "nuclei": {"plantillas": None, "analizar": None, "resultados": None},
    "zap": {"estado": None, "pasivo": None, "resultados": None},
    "explicar": dict.fromkeys(EXPLICACIONES),
    "resultados": None,
    "reporte": {"generar": None},
    "ayuda": None,
    "salir": None,
}

_ESTILOS_ESTADO = {"abierto": "bold green", "cerrado": "grey70", "error": "bold red"}
_ESTILOS_SEVERIDAD = {"info": "grey70", "baja": "cyan", "media": "yellow", "alta": "bold red"}
_ETIQUETAS_FUENTE_RESULTADOS = {
    "tcp": "TCP", "nmap": "Nmap", "web": "Web", "nuclei": "Nuclei", "zap": "OWASP ZAP",
}
_ESTILOS_SEVERIDAD_NUCLEI = {
    "info": "grey70", "low": "cyan", "medium": "yellow", "high": "bold red",
    "critical": "bold red", "unknown": "grey70",
}
_ESTILOS_RIESGO_ZAP = {
    "informational": "grey70", "low": "cyan", "medium": "yellow", "high": "bold red",
}


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


def _tabla_resultados_unificados(resultados, titulo: str) -> Table:
    tabla = Table(title=titulo)
    tabla.add_column("Fuente")
    tabla.add_column("Objetivo")
    tabla.add_column("Hallazgo")
    tabla.add_column("Severidad")
    tabla.add_column("Estado")
    tabla.add_column("Revision")
    tabla.add_column("Fecha")
    for r in resultados:
        grupo = _agrupar_severidad(r.severidad) or ""
        estilo = _ESTILOS_SEVERIDAD.get(grupo, "")
        severidad_texto = (
            f"[{estilo}]{r.severidad}[/{estilo}]" if r.severidad and estilo
            else (r.severidad or "-")
        )
        tabla.add_row(
            _ETIQUETAS_FUENTE_RESULTADOS.get(r.fuente, r.fuente),
            r.objetivo,
            r.nombre,
            severidad_texto,
            r.estado or "-",
            r.estado_revision or "-",
            r.creado_en,
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


def _extraer_bandera(argumentos: list[str], nombre: str) -> tuple[bool, list[str]]:
    """Extrae una bandera booleana '--nombre' (sin valor). Devuelve (presente, resto)."""
    presente = nombre in argumentos
    return presente, [t for t in argumentos if t != nombre]


def _tabla_hallazgos_web(hallazgos: list, titulo: str) -> Table:
    tabla = Table(title=titulo)
    tabla.add_column("Categoria")
    tabla.add_column("Hallazgo")
    tabla.add_column("Estado")
    tabla.add_column("Severidad")
    for hallazgo in hallazgos:
        estilo = _ESTILOS_SEVERIDAD.get(hallazgo.severidad, "")
        severidad_texto = (
            f"[{estilo}]{hallazgo.severidad}[/{estilo}]" if estilo else hallazgo.severidad
        )
        tabla.add_row(hallazgo.categoria, hallazgo.nombre, hallazgo.estado, severidad_texto)
    return tabla


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
            "web": self._web,
            "nuclei": self._nuclei,
            "zap": self._zap,
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

    # -- web -----------------------------------------------------------
    def _web(self, resto: list[str]) -> ResultadoComando:
        if not resto or resto[0] not in ("cabeceras", "tls", "cookies", "auditar"):
            return ResultadoComando(
                False, "Uso: web cabeceras|tls|cookies|auditar URL [--proyecto NOMBRE]"
            )
        subcomando, *args = resto
        proyecto_nombre, args = _extraer_opcion(args, "--proyecto")
        tiempo_limite_txt, args = _extraer_opcion(args, "--tiempo-limite")
        seguir_redirecciones, args = _extraer_bandera(args, "--seguir-redirecciones")

        if not args:
            return ResultadoComando(False, f"Falta la URL. Uso: web {subcomando} URL")

        try:
            tiempo_limite = float(tiempo_limite_txt) if tiempo_limite_txt else 10.0
        except ValueError:
            return ResultadoComando(False, "--tiempo-limite debe ser numerico.")

        tipos = _TIPOS_WEB_VALIDOS if subcomando == "auditar" else frozenset({subcomando})
        base_datos = obtener_base_datos()
        proyecto = resolver_proyecto(base_datos, proyecto_nombre)
        resultado, _guardados = _auditar_web(
            base_datos, proyecto, args[0], subcomando,
            tipos=tipos, tiempo_limite=tiempo_limite, seguir_redirecciones=seguir_redirecciones,
        )
        url_mostrada = _redactar_url(args[0])
        return ResultadoComando(
            True, _tabla_hallazgos_web(resultado.hallazgos, f"Auditoria web - {url_mostrada}")
        )

    # -- nuclei --------------------------------------------------------
    def _nuclei(self, resto: list[str]) -> ResultadoComando:
        if not resto:
            return ResultadoComando(
                False, "Uso: nuclei plantillas|analizar|resultados"
            )
        subcomando, *args = resto

        if subcomando == "plantillas":
            tabla = Table(title="Plantillas de Nuclei aprobadas por AST")
            tabla.add_column("Id")
            tabla.add_column("Nombre")
            tabla.add_column("Severidad esperada")
            for info in _PLANTILLAS_NUCLEI.values():
                tabla.add_row(info.id_, info.nombre, info.severidad_esperada)
            return ResultadoComando(True, tabla)

        if subcomando == "analizar":
            proyecto_nombre, args = _extraer_opcion(args, "--proyecto")
            plantillas_txt, args = _extraer_opcion(args, "--plantillas")
            tiempo_limite_txt, args = _extraer_opcion(args, "--tiempo-limite")
            if not args:
                return ResultadoComando(
                    False, "Falta el objetivo. Uso: nuclei analizar OBJETIVO --plantillas id1,id2"
                )
            if not plantillas_txt:
                return ResultadoComando(
                    False, "Falta --plantillas. Ej: --plantillas exposed-env-file"
                )
            try:
                tiempo_limite = float(tiempo_limite_txt) if tiempo_limite_txt else 60.0
            except ValueError:
                return ResultadoComando(False, "--tiempo-limite debe ser numerico.")

            ids = [p.strip() for p in plantillas_txt.split(",") if p.strip()]
            base_datos = obtener_base_datos()
            proyecto = resolver_proyecto(base_datos, proyecto_nombre)
            resultado, _guardados = _ejecutar_nuclei(
                base_datos, proyecto, args[0], ids, tiempo_limite=tiempo_limite
            )
            tabla = Table(title=f"Nuclei - {args[0]}")
            tabla.add_column("Plantilla")
            tabla.add_column("Hallazgo")
            tabla.add_column("Severidad")
            for h in resultado.hallazgos:
                estilo = _ESTILOS_SEVERIDAD_NUCLEI.get(h.severidad.lower(), "")
                severidad_texto = f"[{estilo}]{h.severidad}[/{estilo}]" if estilo else h.severidad
                tabla.add_row(h.plantilla_id, h.plantilla_nombre, severidad_texto)
            return ResultadoComando(True, tabla)

        if subcomando == "resultados":
            proyecto_nombre, args = _extraer_opcion(args, "--proyecto")
            base_datos = obtener_base_datos()
            proyecto = resolver_proyecto(base_datos, proyecto_nombre)
            guardados = base_datos.listar_resultados_nuclei(proyecto.id, limite=200)
            tabla = Table(title=f"Hallazgos de Nuclei - {proyecto.nombre}")
            tabla.add_column("Objetivo")
            tabla.add_column("Plantilla")
            tabla.add_column("Severidad")
            tabla.add_column("Revision")
            for g in guardados:
                estilo = _ESTILOS_SEVERIDAD_NUCLEI.get(g.severidad.lower(), "")
                severidad_texto = f"[{estilo}]{g.severidad}[/{estilo}]" if estilo else g.severidad
                tabla.add_row(g.objetivo, g.plantilla_id, severidad_texto, g.estado_revision)
            return ResultadoComando(True, tabla)

        return ResultadoComando(False, f"Subcomando desconocido: 'nuclei {subcomando}'.")

    # -- zap -------------------------------------------------------------
    def _zap(self, resto: list[str]) -> ResultadoComando:
        if not resto:
            return ResultadoComando(False, "Uso: zap estado|pasivo|resultados")
        subcomando, *args = resto

        if subcomando == "estado":
            info = _AdaptadorZAP().info()
            if not info.disponible:
                return ResultadoComando(False, f"OWASP ZAP no esta disponible: {info.mensaje}")
            return ResultadoComando(
                True, f"OWASP ZAP disponible. Version: {info.version or 'desconocida'}"
            )

        if subcomando == "pasivo":
            proyecto_nombre, args = _extraer_opcion(args, "--proyecto")
            tiempo_limite_txt, args = _extraer_opcion(args, "--tiempo-limite")
            if not args:
                return ResultadoComando(False, "Falta la URL. Uso: zap pasivo URL")
            try:
                tiempo_limite = float(tiempo_limite_txt) if tiempo_limite_txt else 60.0
            except ValueError:
                return ResultadoComando(False, "--tiempo-limite debe ser numerico.")

            base_datos = obtener_base_datos()
            proyecto = resolver_proyecto(base_datos, proyecto_nombre)
            resultado, _guardados = _ejecutar_zap_pasivo(
                base_datos, proyecto, args[0], tiempo_limite=tiempo_limite
            )
            tabla = Table(title=f"OWASP ZAP - {_redactar_url(args[0])}")
            tabla.add_column("Regla")
            tabla.add_column("Hallazgo")
            tabla.add_column("Riesgo")
            for h in resultado.hallazgos:
                estilo = _ESTILOS_RIESGO_ZAP.get(h.riesgo.lower(), "")
                riesgo_texto = f"[{estilo}]{h.riesgo}[/{estilo}]" if estilo else h.riesgo
                tabla.add_row(h.plugin_id, h.nombre, riesgo_texto)
            return ResultadoComando(True, tabla)

        if subcomando == "resultados":
            proyecto_nombre, args = _extraer_opcion(args, "--proyecto")
            base_datos = obtener_base_datos()
            proyecto = resolver_proyecto(base_datos, proyecto_nombre)
            guardados = base_datos.listar_resultados_zap(proyecto.id, limite=200)
            tabla = Table(title=f"Hallazgos de OWASP ZAP - {proyecto.nombre}")
            tabla.add_column("Objetivo")
            tabla.add_column("Regla")
            tabla.add_column("Riesgo")
            tabla.add_column("Revision")
            for g in guardados:
                estilo = _ESTILOS_RIESGO_ZAP.get(g.riesgo.lower(), "")
                riesgo_texto = f"[{estilo}]{g.riesgo}[/{estilo}]" if estilo else g.riesgo
                tabla.add_row(g.objetivo, g.plugin_id, riesgo_texto, g.estado_revision)
            return ResultadoComando(True, tabla)

        return ResultadoComando(False, f"Subcomando desconocido: 'zap {subcomando}'.")

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
        fuente_txt, resto = _extraer_opcion(resto, "--fuente")
        severidad, resto = _extraer_opcion(resto, "--severidad")
        estado_txt, resto = _extraer_opcion(resto, "--estado")
        desde, resto = _extraer_opcion(resto, "--desde")
        hasta, resto = _extraer_opcion(resto, "--hasta")
        limite_txt, _resto = _extraer_opcion(resto, "--limite")
        try:
            limite = int(limite_txt) if limite_txt else 50
        except ValueError:
            return ResultadoComando(False, "--limite debe ser un numero entero.")

        fuentes = None
        if fuente_txt:
            fuentes = frozenset(f.strip().lower() for f in fuente_txt.split(",") if f.strip())

        base_datos = obtener_base_datos()
        proyecto = resolver_proyecto(base_datos, proyecto_nombre)
        try:
            resultados = _obtener_resultados_unificados(
                base_datos,
                proyecto,
                fuentes=fuentes,
                severidad=severidad,
                estado=estado_txt,
                desde=desde,
                hasta=hasta,
                limite=limite,
            )
        except ErrorValidacion as exc:
            return ResultadoComando(False, str(exc))
        titulo = f"Resultados - {proyecto.nombre}"
        return ResultadoComando(True, _tabla_resultados_unificados(resultados, titulo))

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
