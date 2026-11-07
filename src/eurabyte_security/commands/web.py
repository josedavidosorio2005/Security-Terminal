"""Comando de auditoria web no intrusiva: cabeceras, TLS, cookies y redirecciones."""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

import typer
from rich.table import Table

from eurabyte_security.commands._comun import obtener_base_datos, resolver_proyecto
from eurabyte_security.core.config import ruta_reportes
from eurabyte_security.core.errores import ErrorAuditoriaWeb, ErrorFueraDeAlcance, ErrorValidacion
from eurabyte_security.core.validation import (
    ComponentesURL,
    validar_tiempo_limite_web,
    validar_url_web,
)
from eurabyte_security.modules.reporting.generador import (
    construir_datos_informe_web,
    generar_html_web,
    generar_json_web,
)
from eurabyte_security.modules.web.auditor import (
    TIPOS_VALIDOS,
    ResultadoAuditoriaWeb,
    ejecutar_auditoria_web,
)
from eurabyte_security.modules.web.modelos import ORDEN_SEVERIDAD, Hallazgo
from eurabyte_security.modules.web.redaccion import redactar_url
from eurabyte_security.storage.database import BaseDatos, Proyecto
from eurabyte_security.storage.database import ResultadoWeb as ResultadoWebGuardado
from eurabyte_security.ui.consola import consola, texto_seguro

FORMATOS_VALIDOS_REPORTE = {"html", "json"}

web_app = typer.Typer(
    help="Auditoria web no intrusiva: cabeceras, TLS, cookies y redirecciones.",
    no_args_is_help=True,
)

_ESTILOS_SEVERIDAD = {
    "info": "grey70",
    "baja": "cyan",
    "media": "yellow",
    "alta": "bold red",
}

TIEMPO_LIMITE_POR_DEFECTO = 10.0


def _verificar_alcance(
    base_datos: BaseDatos, proyecto: Proyecto, componentes: ComponentesURL
) -> None:
    redes = [ipaddress.IPv4Network(a.red) for a in base_datos.listar_alcance(proyecto.id)]
    if not any(componentes.host in red for red in redes):
        raise ErrorFueraDeAlcance(
            f"El objetivo '{redactar_url(componentes.url_original)}' no esta dentro "
            f"del alcance autorizado del proyecto '{proyecto.nombre}'. Registralo "
            "primero con 'est alcance agregar'."
        )


def auditar_web(
    base_datos: BaseDatos,
    proyecto: Proyecto,
    url: str,
    tipo_analisis: str,
    *,
    tipos: frozenset[str] = TIPOS_VALIDOS,
    tiempo_limite: float = TIEMPO_LIMITE_POR_DEFECTO,
    seguir_redirecciones: bool = False,
    guardar: bool = True,
    debe_cancelar: Callable[[], bool] | None = None,
) -> tuple[ResultadoAuditoriaWeb, list[ResultadoWebGuardado]]:
    """Valida la URL/alcance, ejecuta la auditoria web y persiste los hallazgos.

    ``tipo_analisis`` identifica el comando que origino la auditoria ('cabeceras',
    'tls', 'cookies' o 'auditar') y se guarda junto con cada hallazgo para distinguir
    de donde vino. La verificacion de alcance ocurre ANTES de cualquier peticion de red,
    igual que en ``commands/escanear.py`` y ``commands/nmap.py``. ``tiempo_limite`` se
    valida contra el rango de UNA peticion (1-30s, ver ``core/validation.py``); el
    tiempo total de toda la auditoria al seguir redirecciones tiene su propio limite
    independiente (ver ``modules/web/auditor.py:TIEMPO_LIMITE_TOTAL_MAXIMO``).

    ``debe_cancelar`` se consulta durante la auditoria (dentro de cada peticion de red)
    y otra vez justo antes de persistir, igual que ``escanear_tcp``: si se cancela en
    ese segundo chequeo, no se guarda ningun hallazgo (ni siquiera los de un salto de
    redireccion que ya se hubiera completado), y se lanza ``ErrorAuditoriaWeb``.
    """
    componentes = validar_url_web(url)
    tiempo_limite = validar_tiempo_limite_web(tiempo_limite)
    _verificar_alcance(base_datos, proyecto, componentes)
    redes_autorizadas = [
        ipaddress.IPv4Network(a.red) for a in base_datos.listar_alcance(proyecto.id)
    ]

    resultado = ejecutar_auditoria_web(
        componentes,
        redes_autorizadas=redes_autorizadas,
        tipos=tipos,
        tiempo_limite=tiempo_limite,
        seguir_redirecciones=seguir_redirecciones,
        debe_cancelar=debe_cancelar,
    )

    if not guardar:
        return resultado, []

    if debe_cancelar is not None and debe_cancelar():
        raise ErrorAuditoriaWeb(
            f"La auditoria de '{redactar_url(componentes.url_original)}' se cancelo "
            "antes de completarse. No se guardo ningun hallazgo."
        )

    filas = [
        (
            h.categoria,
            h.nombre,
            h.severidad,
            h.estado,
            h.valor_detectado,
            h.riesgo,
            h.recomendacion,
            h.referencia,
        )
        for h in resultado.hallazgos
    ]
    guardados = base_datos.agregar_resultados_web(
        proyecto.id, redactar_url(componentes.url_original), tipo_analisis, filas
    )
    return resultado, guardados


def _tabla_hallazgos(hallazgos: list[Hallazgo], titulo: str) -> Table:
    tabla = Table(title=titulo)
    tabla.add_column("Categoria")
    tabla.add_column("Hallazgo")
    tabla.add_column("Estado")
    tabla.add_column("Severidad")
    tabla.add_column("Valor detectado")
    hallazgos_ordenados = sorted(hallazgos, key=lambda h: -ORDEN_SEVERIDAD[h.severidad])
    for h in hallazgos_ordenados:
        estilo = _ESTILOS_SEVERIDAD.get(h.severidad, "")
        severidad_texto = f"[{estilo}]{h.severidad}[/{estilo}]" if estilo else h.severidad
        valor = texto_seguro(h.valor_detectado) if h.valor_detectado else "-"
        if len(valor) > 80:
            valor = valor[:77] + "..."
        tabla.add_row(
            texto_seguro(h.categoria), texto_seguro(h.nombre), texto_seguro(h.estado),
            severidad_texto, valor,
        )
    return tabla


def _mostrar_explicaciones(hallazgos: list[Hallazgo]) -> None:
    for h in hallazgos:
        consola.print(
            f"\n[bold]{texto_seguro(h.nombre)}[/bold] ({texto_seguro(h.categoria)})\n"
            f"  Significado: {texto_seguro(h.significado)}\n"
            f"  Proposito: {texto_seguro(h.proposito)}\n"
            f"  Riesgo: {texto_seguro(h.riesgo)}\n"
            f"  Recomendacion: {texto_seguro(h.recomendacion)}\n"
            f"  Referencia: {texto_seguro(h.referencia)}"
        )


def _opcion_proyecto() -> typer.Option:
    return typer.Option(None, "--proyecto", help="Proyecto a usar (por defecto, el activo).")


def _opcion_tiempo_limite() -> typer.Option:
    return typer.Option(
        TIEMPO_LIMITE_POR_DEFECTO, "--tiempo-limite", help="Segundos maximos de espera (1-30)."
    )


def _opcion_seguir_redirecciones() -> typer.Option:
    return typer.Option(
        False,
        "--seguir-redirecciones",
        help="Si el objetivo redirige a otro destino autorizado en el alcance, auditalo tambien.",
    )


def _opcion_detallado() -> typer.Option:
    return typer.Option(
        False, "--detallado", help="Muestra la explicacion completa de cada hallazgo."
    )


def _ejecutar_y_mostrar(
    url: str,
    tipos: frozenset[str],
    tipo_analisis: str,
    proyecto: str | None,
    tiempo_limite: float,
    seguir_redirecciones: bool,
    *,
    detallado: bool,
) -> None:
    base_datos = obtener_base_datos()
    proyecto_obj = resolver_proyecto(base_datos, proyecto)

    url_mostrada = redactar_url(url)
    with consola.status(f"Auditando {texto_seguro(url_mostrada)}..."):
        resultado, _guardados = auditar_web(
            base_datos, proyecto_obj, url, tipo_analisis,
            tipos=tipos, tiempo_limite=tiempo_limite, seguir_redirecciones=seguir_redirecciones,
        )

    codigo_estado_texto = (
        str(resultado.codigo_estado)
        if resultado.codigo_estado is not None
        else "N/A (peticion HTTP no completada, ver hallazgo de TLS)"
    )
    consola.print(
        f"Codigo de estado final: {codigo_estado_texto} "
        f"({texto_seguro(redactar_url(resultado.componentes_final.url_original))})"
    )
    if resultado.saltos_seguidos:
        saltos_texto = ", ".join(texto_seguro(redactar_url(s)) for s in resultado.saltos_seguidos)
        consola.print(f"Redirecciones seguidas: {saltos_texto}")
    consola.print(_tabla_hallazgos(resultado.hallazgos, f"Auditoria web - {url_mostrada}"))
    if detallado:
        _mostrar_explicaciones(resultado.hallazgos)


@web_app.command("cabeceras")
def cabeceras_cmd(
    url: str = typer.Argument(..., help="URL del objetivo, ej: https://127.0.0.1:8443/"),
    proyecto: str | None = _opcion_proyecto(),
    tiempo_limite: float = _opcion_tiempo_limite(),
    seguir_redirecciones: bool = _opcion_seguir_redirecciones(),
    detallado: bool = _opcion_detallado(),
) -> None:
    """Audita las cabeceras HTTP de seguridad de un objetivo autorizado."""
    _ejecutar_y_mostrar(
        url, frozenset({"cabeceras"}), "cabeceras", proyecto, tiempo_limite,
        seguir_redirecciones, detallado=detallado,
    )


@web_app.command("tls")
def tls_cmd(
    url: str = typer.Argument(..., help="URL del objetivo, ej: https://127.0.0.1:8443/"),
    proyecto: str | None = _opcion_proyecto(),
    tiempo_limite: float = _opcion_tiempo_limite(),
    seguir_redirecciones: bool = _opcion_seguir_redirecciones(),
    detallado: bool = _opcion_detallado(),
) -> None:
    """Audita el certificado y la configuracion TLS de un objetivo autorizado."""
    _ejecutar_y_mostrar(
        url, frozenset({"tls"}), "tls", proyecto, tiempo_limite,
        seguir_redirecciones, detallado=detallado,
    )


@web_app.command("cookies")
def cookies_cmd(
    url: str = typer.Argument(..., help="URL del objetivo, ej: https://127.0.0.1:8443/"),
    proyecto: str | None = _opcion_proyecto(),
    tiempo_limite: float = _opcion_tiempo_limite(),
    seguir_redirecciones: bool = _opcion_seguir_redirecciones(),
    detallado: bool = _opcion_detallado(),
) -> None:
    """Audita los atributos de seguridad de las cookies de un objetivo autorizado."""
    _ejecutar_y_mostrar(
        url, frozenset({"cookies"}), "cookies", proyecto, tiempo_limite,
        seguir_redirecciones, detallado=detallado,
    )


@web_app.command("auditar")
def auditar_cmd(
    url: str = typer.Argument(..., help="URL del objetivo, ej: https://127.0.0.1:8443/"),
    proyecto: str | None = _opcion_proyecto(),
    tiempo_limite: float = _opcion_tiempo_limite(),
    seguir_redirecciones: bool = _opcion_seguir_redirecciones(),
    detallado: bool = _opcion_detallado(),
) -> None:
    """Ejecuta la auditoria web completa: cabeceras, TLS, cookies y redirecciones."""
    _ejecutar_y_mostrar(
        url, TIPOS_VALIDOS, "auditar", proyecto, tiempo_limite,
        seguir_redirecciones, detallado=detallado,
    )


def generar_reporte_web(
    base_datos: BaseDatos, proyecto: Proyecto, formato: str, salida: Path | None = None
) -> Path:
    """Genera un informe HTML/JSON con los hallazgos de auditoria web guardados.

    Reutiliza el mismo esqueleto (CSS, cabecera) que ``commands/reporte.py`` usa para
    los resultados de ``escanear tcp``, en vez de duplicar la generacion del informe:
    ver ``modules/reporting/generador.py``.
    """
    formato = formato.lower()
    if formato not in FORMATOS_VALIDOS_REPORTE:
        raise ErrorValidacion(
            f"Formato '{formato}' no soportado. Usa uno de: "
            f"{', '.join(sorted(FORMATOS_VALIDOS_REPORTE))}."
        )

    resultados = base_datos.listar_resultados_web(proyecto.id, limite=10_000)
    datos = construir_datos_informe_web(proyecto.nombre, resultados)
    contenido = generar_html_web(datos) if formato == "html" else generar_json_web(datos)

    if salida is None:
        marca_tiempo = datetime.now().strftime("%Y%m%d-%H%M%S")
        ruta_salida = ruta_reportes() / f"informe-web-{proyecto.nombre}-{marca_tiempo}.{formato}"
    else:
        ruta_salida = salida
    ruta_salida.parent.mkdir(parents=True, exist_ok=True)
    ruta_salida.write_text(contenido, encoding="utf-8")
    return ruta_salida


@web_app.command("reporte")
def reporte_cmd(
    formato: str = typer.Option("html", "--formato", help="Formato del informe: html o json."),
    proyecto: str | None = _opcion_proyecto(),
    salida: str | None = typer.Option(None, "--salida", help="Ruta del archivo de salida."),
) -> None:
    """Genera un informe HTML o JSON con los hallazgos de auditoria web guardados."""
    base_datos = obtener_base_datos()
    proyecto_obj = resolver_proyecto(base_datos, proyecto)
    ruta = generar_reporte_web(
        base_datos, proyecto_obj, formato, Path(salida) if salida else None
    )
    consola.print(f"[bold green]OK[/bold green] Informe generado en: {texto_seguro(ruta)}")
