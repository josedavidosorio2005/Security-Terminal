"""Comandos OSINT: investigacion de fuentes publicas sobre un objetivo autorizado."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Group
from rich.panel import Panel
from rich.table import Table

from eurabyte_security.commands._comun import obtener_base_datos, resolver_proyecto
from eurabyte_security.core.config import ruta_reportes
from eurabyte_security.core.errores import ErrorValidacion
from eurabyte_security.integrations.osint.registro import FUENTES_OSINT, fuentes_para_tipo
from eurabyte_security.integrations.osint.twilio_lookup import AVISO_COSTO as AVISO_COSTO_TWILIO
from eurabyte_security.modules.osint.exposicion import construir_resumen_exposicion
from eurabyte_security.modules.osint.modelos import EtapaFuenteOSINT
from eurabyte_security.modules.osint.motor import ejecutar_investigacion_osint
from eurabyte_security.modules.reporting.generador import (
    construir_datos_informe_osint,
    generar_html_osint,
    generar_json_osint,
)
from eurabyte_security.storage.database import BaseDatos, HallazgoOSINTGuardado, Proyecto
from eurabyte_security.ui.consola import consola, texto_seguro

FORMATOS_INFORME_VALIDOS = {"html", "json"}

# Sin paginacion real desde la CLI (ver BaseDatos.listar_hallazgos_osint), este limite
# amplio cubre con holgura una investigacion OSINT real (nunca miles de hallazgos, ver
# docs/OSINT.md) cuando se pide la vista completa ('--solo-urls') en vez de una pagina.
_LIMITE_SIN_PAGINAR = 10_000

_ESTADOS_VERIFICACION = {
    "confirmado": "Dato confirmado directamente por la fuente.",
    "probable": "Evidencia indirecta o historica: no confirma el estado actual.",
    "no_verificado": "Asociacion no verificada: tratar como estimacion, no como hecho.",
}


def _es_url_http(texto: str | None) -> bool:
    if not texto:
        return False
    return texto.strip().lower().startswith(("http://", "https://"))


def _urls_de_hallazgo(hallazgo: HallazgoOSINTGuardado) -> list[str]:
    """URL realmente observadas y guardadas en un hallazgo (nunca un subdominio o un
    nombre convertido en URL por la propia CLI, ver seccion 2 de la especificacion de
    evidencia completa: "no convertir automaticamente un subdominio en una URL")."""
    urls: list[str] = []
    for evidencia in json.loads(hallazgo.evidencias_json):
        for campo in ("referencia", "valor"):
            valor = evidencia.get(campo)
            if _es_url_http(valor) and valor not in urls:
                urls.append(valor)
    return urls

osint_app = typer.Typer(
    help="Investiga fuentes publicas (OSINT) sobre un objetivo autorizado.",
    no_args_is_help=True,
)

_AYUDA_PROYECTO = "Proyecto a usar (por defecto, el activo)."
_AYUDA_FUENTES = "Fuentes a usar, separadas por comas (por defecto, todas las aplicables)."

_ESTILOS_ESTADO_FUENTE = {
    "completada": "bold green",
    "ejecutando": "bold yellow",
    "pendiente": "grey70",
    "omitida": "grey70",
    "fallida": "bold red",
    "cancelada": "bold red",
}
_ESTILOS_CONFIANZA = {
    "confirmado": "bold green",
    "probable": "yellow",
    "no_verificado": "grey70",
}


def _parsear_fuentes(fuentes_txt: str | None, tipo_objetivo: str) -> frozenset[str] | None:
    if not fuentes_txt:
        return None
    pedidas = frozenset(f.strip().lower() for f in fuentes_txt.split(",") if f.strip())
    disponibles = set(fuentes_para_tipo(tipo_objetivo))
    desconocidas = pedidas - disponibles
    if desconocidas:
        consola.print(
            f"[bold yellow]Aviso:[/bold yellow] fuente(s) no aplicable(s) a "
            f"'{tipo_objetivo}' ignorada(s): {', '.join(sorted(desconocidas))}."
        )
    return pedidas & disponibles or None


def _tabla_etapas(etapas: tuple[EtapaFuenteOSINT, ...], titulo: str) -> Table:
    tabla = Table(title=titulo)
    tabla.add_column("Fuente")
    tabla.add_column("Estado")
    tabla.add_column("Detalle")
    for etapa in etapas:
        adaptador = FUENTES_OSINT.get(etapa.fuente)
        nombre_fuente = adaptador.nombre if adaptador is not None else etapa.fuente
        estilo = _ESTILOS_ESTADO_FUENTE.get(etapa.estado, "")
        estado_texto = f"[{estilo}]{etapa.estado}[/{estilo}]" if estilo else etapa.estado
        tabla.add_row(nombre_fuente, estado_texto, texto_seguro(etapa.detalle))
    return tabla


def _ejecutar_y_mostrar(
    base_datos: BaseDatos,
    proyecto: Proyecto,
    tipo_objetivo: str,
    objetivo: str,
    *,
    autorizado: bool,
    fuentes_txt: str | None,
    region: str | None = None,
) -> None:
    fuentes = _parsear_fuentes(fuentes_txt, tipo_objetivo)

    def _mostrar_progreso(etapa: EtapaFuenteOSINT) -> None:
        estilo = _ESTILOS_ESTADO_FUENTE.get(etapa.estado, "")
        estado_texto = f"[{estilo}]{etapa.estado}[/{estilo}]" if estilo else etapa.estado
        detalle = texto_seguro(etapa.detalle)
        consola.print(f"[bold]{etapa.fuente}[/bold]: {estado_texto} - {detalle}")

    resultado = ejecutar_investigacion_osint(
        base_datos,
        proyecto,
        tipo_objetivo,
        objetivo,
        autorizado_datos_personales=autorizado,
        region_telefono=region,
        fuentes_seleccionadas=fuentes,
        callback_progreso=_mostrar_progreso,
    )
    titulo = f"Investigacion OSINT #{resultado.investigacion_id} - {objetivo}"
    consola.print(_tabla_etapas(resultado.etapas, titulo))
    consola.print(f"\nTotal de hallazgos: {resultado.total_hallazgos}")

    hallazgos_guardados = base_datos.listar_hallazgos_osint(
        investigacion_id=resultado.investigacion_id, limite=10_000
    )
    resumen = construir_resumen_exposicion(hallazgos_guardados)
    if resumen.total_indicadores:
        consola.print(
            f"\n[bold yellow]Indicadores de exposicion: {resumen.total_indicadores}[/bold yellow] "
            f"(fuentes: {', '.join(resumen.fuentes_con_indicador)})"
        )
        for indicador in resumen.indicadores:
            consola.print(f"- {texto_seguro(indicador)}")
    else:
        consola.print("\n[bold green]Sin indicadores de exposicion.[/bold green]")

    if resultado.limitaciones:
        consola.print("\n[bold yellow]Limitaciones:[/bold yellow]")
        for limitacion in resultado.limitaciones:
            consola.print(f"- {texto_seguro(limitacion)}")
    consola.print(
        f"\nUsa 'est osint resultados --investigacion {resultado.investigacion_id}' "
        "para ver el detalle."
    )


def generar_reporte_osint(
    base_datos: BaseDatos,
    proyecto: Proyecto,
    investigacion_id: int,
    formato: str,
    *,
    minimizar: bool = False,
    salida: Path | None = None,
) -> Path:
    """Genera el informe de UNA investigacion OSINT (separado del informe global
    de hallazgos tecnicos, ver ``commands/reporte.py``)."""
    formato = formato.lower()
    if formato not in FORMATOS_INFORME_VALIDOS:
        raise ErrorValidacion(
            f"Formato '{formato}' no soportado. Usa uno de: "
            f"{', '.join(sorted(FORMATOS_INFORME_VALIDOS))}."
        )

    investigacion = base_datos.obtener_investigacion_osint(investigacion_id)
    hallazgos = base_datos.listar_hallazgos_osint(investigacion_id=investigacion_id, limite=10_000)
    datos = construir_datos_informe_osint(
        proyecto.nombre, investigacion, hallazgos, minimizar=minimizar
    )
    contenido = generar_html_osint(datos) if formato == "html" else generar_json_osint(datos)

    if salida is None:
        marca_tiempo = datetime.now().strftime("%Y%m%d-%H%M%S")
        ruta_salida = (
            ruta_reportes()
            / f"informe-osint-{proyecto.nombre}-{investigacion_id}-{marca_tiempo}.{formato}"
        )
    else:
        ruta_salida = salida
    ruta_salida.parent.mkdir(parents=True, exist_ok=True)
    ruta_salida.write_text(contenido, encoding="utf-8")
    return ruta_salida


@osint_app.command("dominio")
def dominio_cmd(
    dominio: str = typer.Argument(..., help="Dominio corporativo autorizado (ej. ejemplo.com)."),
    proyecto: str | None = typer.Option(None, "--proyecto", help=_AYUDA_PROYECTO),
    fuentes: str | None = typer.Option(None, "--fuentes", help=_AYUDA_FUENTES),
) -> None:
    """Investiga un dominio: DNS, RDAP, infraestructura y Certificate Transparency."""
    base_datos = obtener_base_datos()
    proyecto_obj = resolver_proyecto(base_datos, proyecto)
    # 'dominio' no exige autorizacion de datos personales (se trata como informacion
    # corporativa, ver core/osint/validacion.py): False refleja que no se pidio ni se
    # confirmo ningun consentimiento de ese tipo, no que la investigacion sea invalida.
    _ejecutar_y_mostrar(
        base_datos, proyecto_obj, "dominio", dominio, autorizado=False, fuentes_txt=fuentes
    )


@osint_app.command("correo")
def correo_cmd(
    correo: str = typer.Argument(..., help="Correo propio o cuya revision esta autorizada."),
    autorizo: bool = typer.Option(
        False, "--autorizo", help="Confirma que el correo es propio o su revision esta autorizada."
    ),
    proyecto: str | None = typer.Option(None, "--proyecto", help=_AYUDA_PROYECTO),
    fuentes: str | None = typer.Option(None, "--fuentes", help=_AYUDA_FUENTES),
) -> None:
    """Investiga un correo: sintaxis, MX/SPF/DMARC de su dominio."""
    base_datos = obtener_base_datos()
    proyecto_obj = resolver_proyecto(base_datos, proyecto)
    _ejecutar_y_mostrar(
        base_datos, proyecto_obj, "correo", correo, autorizado=autorizo, fuentes_txt=fuentes
    )


@osint_app.command("telefono")
def telefono_cmd(
    telefono: str = typer.Argument(..., help="Numero propio o cuya revision esta autorizada."),
    autorizo: bool = typer.Option(
        False, "--autorizo", help="Confirma que el numero es propio o su revision esta autorizada."
    ),
    region: str | None = typer.Option(
        None, "--region", help="Codigo de region ISO (ej. CO) si el numero no incluye '+pais'."
    ),
    proyecto: str | None = typer.Option(None, "--proyecto", help=_AYUDA_PROYECTO),
    fuentes: str | None = typer.Option(
        None,
        "--fuentes",
        help=(
            _AYUDA_FUENTES
            + " 'twilio_lookup' es de PAGO POR CONSULTA y solo corre si se nombra aqui."
        ),
    ),
) -> None:
    """Metadatos de numeracion (E.164, region, tipo de numero, zona horaria...).

    Nunca identifica al titular de la linea: ver docs/OSINT.md, seccion de metadatos
    telefonicos.
    """
    base_datos = obtener_base_datos()
    proyecto_obj = resolver_proyecto(base_datos, proyecto)
    if fuentes and "twilio_lookup" in {f.strip().lower() for f in fuentes.split(",")}:
        consola.print(f"[bold yellow]Aviso de costo:[/bold yellow] {AVISO_COSTO_TWILIO}")
    _ejecutar_y_mostrar(
        base_datos,
        proyecto_obj,
        "telefono",
        telefono,
        autorizado=autorizo,
        fuentes_txt=fuentes,
        region=region,
    )


@osint_app.command("usuario")
def usuario_cmd(
    usuario: str = typer.Argument(
        ..., help="Nombre de usuario propio o cuya revision esta autorizada."
    ),
    autorizo: bool = typer.Option(
        False, "--autorizo", help="Confirma que la cuenta es propia o su revision esta autorizada."
    ),
    proyecto: str | None = typer.Option(None, "--proyecto", help=_AYUDA_PROYECTO),
    fuentes: str | None = typer.Option(None, "--fuentes", help=_AYUDA_FUENTES),
) -> None:
    """Busca coincidencias de un nombre de usuario en perfiles publicos (GitHub, GitLab)."""
    base_datos = obtener_base_datos()
    proyecto_obj = resolver_proyecto(base_datos, proyecto)
    _ejecutar_y_mostrar(
        base_datos, proyecto_obj, "usuario", usuario, autorizado=autorizo, fuentes_txt=fuentes
    )


@osint_app.command("fuentes")
def fuentes_cmd(
    tipo: str | None = typer.Option(
        None, "--tipo", help="Filtra por tipo de objetivo: dominio, correo, telefono o usuario."
    ),
) -> None:
    """Lista las fuentes OSINT disponibles y si estan configuradas."""
    catalogo = fuentes_para_tipo(tipo) if tipo else FUENTES_OSINT
    tabla = Table(title="Fuentes OSINT")
    tabla.add_column("Id")
    tabla.add_column("Nombre")
    tabla.add_column("Tipos de objetivo")
    tabla.add_column("Estado")
    for id_fuente, adaptador in catalogo.items():
        estado = "Disponible" if adaptador.configurada() else "Requiere configuracion"
        tabla.add_row(
            id_fuente,
            adaptador.nombre,
            ", ".join(sorted(adaptador.tipos_objetivo)),
            estado,
        )
    consola.print(tabla)


@osint_app.command("investigaciones")
def investigaciones_cmd(
    proyecto: str | None = typer.Option(None, "--proyecto", help=_AYUDA_PROYECTO),
    limite: int = typer.Option(20, "--limite", help="Numero maximo de investigaciones a mostrar."),
) -> None:
    """Lista las investigaciones OSINT guardadas de un proyecto."""
    base_datos = obtener_base_datos()
    proyecto_obj = resolver_proyecto(base_datos, proyecto)
    investigaciones = base_datos.listar_investigaciones_osint(proyecto_obj.id, limite=limite)

    if not investigaciones:
        consola.print(
            f"El proyecto '{proyecto_obj.nombre}' no tiene investigaciones OSINT guardadas."
        )
        return

    tabla = Table(title=f"Investigaciones OSINT - {proyecto_obj.nombre}")
    tabla.add_column("Id")
    tabla.add_column("Tipo")
    tabla.add_column("Objetivo")
    tabla.add_column("Estado")
    tabla.add_column("Fecha")
    for inv in investigaciones:
        estilo = _ESTILOS_ESTADO_FUENTE.get(inv.estado_general, "")
        estado_texto = (
            f"[{estilo}]{inv.estado_general}[/{estilo}]" if estilo else inv.estado_general
        )
        tabla.add_row(
            str(inv.id),
            inv.tipo_objetivo,
            texto_seguro(inv.objetivo_saneado),
            estado_texto,
            inv.creado_en,
        )
    consola.print(tabla)


def _tabla_resultados(
    hallazgos: list[HallazgoOSINTGuardado], titulo: str, *, pagina: int, total_paginas: int
) -> Table:
    sufijo_pagina = f" (pagina {pagina}/{total_paginas})" if total_paginas > 1 else ""
    tabla = Table(title=f"{titulo}{sufijo_pagina}")
    tabla.add_column("Id")
    tabla.add_column("Fuente")
    tabla.add_column("Categoria")
    tabla.add_column("Titulo")
    tabla.add_column("Confianza")
    tabla.add_column("Indicador de exposicion")
    tabla.add_column("Fecha")
    for h in hallazgos:
        estilo = _ESTILOS_CONFIANZA.get(h.nivel_confianza, "")
        confianza_texto = (
            f"[{estilo}]{h.nivel_confianza}[/{estilo}]" if estilo else h.nivel_confianza
        )
        tabla.add_row(
            str(h.id),
            h.fuente,
            h.categoria,
            texto_seguro(h.titulo),
            confianza_texto,
            texto_seguro(h.indicador_exposicion) if h.indicador_exposicion else "-",
            h.creado_en,
        )
    return tabla


def _panel_detallado(h: HallazgoOSINTGuardado) -> Panel:
    estilo = _ESTILOS_CONFIANZA.get(h.nivel_confianza, "")
    confianza_texto = f"[{estilo}]{h.nivel_confianza}[/{estilo}]" if estilo else h.nivel_confianza
    cuerpo = [
        f"[bold]Categoria:[/bold] {texto_seguro(h.categoria)}",
        f"[bold]Descripcion:[/bold] {texto_seguro(h.descripcion)}",
        f"[bold]Indicador de exposicion:[/bold] "
        f"{texto_seguro(h.indicador_exposicion) if h.indicador_exposicion else '(ninguno)'}",
        f"[bold]Confianza:[/bold] {confianza_texto}",
        f"[bold]Estado de verificacion:[/bold] "
        f"{_ESTADOS_VERIFICACION.get(h.nivel_confianza, 'Sin clasificar.')}",
        f"[bold]Fuente:[/bold] {texto_seguro(h.fuente)} · [bold]Fecha:[/bold] {h.creado_en}",
    ]
    evidencias = json.loads(h.evidencias_json)
    if evidencias:
        tabla_ev = Table(box=None, show_edge=False, pad_edge=False)
        tabla_ev.add_column("Fuente")
        tabla_ev.add_column("Fecha consulta")
        tabla_ev.add_column("Fecha observada")
        tabla_ev.add_column("Valor")
        tabla_ev.add_column("Referencia (URL)")
        for e in evidencias:
            tabla_ev.add_row(
                texto_seguro(e.get("fuente")),
                texto_seguro(e.get("fecha_consulta")),
                texto_seguro(e.get("fecha_observada")) if e.get("fecha_observada") else "-",
                texto_seguro(e.get("valor")),
                texto_seguro(e.get("referencia")) if e.get("referencia") else "-",
            )
        cuerpo.append("[bold]Evidencias:[/bold]")
    else:
        tabla_ev = None
        cuerpo.append("[bold]Evidencias:[/bold] (ninguna)")

    contenido = Group(*cuerpo) if tabla_ev is None else Group(*cuerpo, tabla_ev)
    return Panel(contenido, title=f"Hallazgo #{h.id} - {texto_seguro(h.titulo)}", expand=True)


@osint_app.command("resultados")
def resultados_cmd(
    proyecto: str | None = typer.Option(None, "--proyecto", help=_AYUDA_PROYECTO),
    investigacion: int | None = typer.Option(
        None,
        "--investigacion",
        help="Limita a una investigacion concreta (ver 'est osint investigaciones').",
    ),
    limite: int = typer.Option(
        100, "--limite", help="Numero maximo de hallazgos a mostrar por pagina."
    ),
    pagina: int = typer.Option(
        1, "--pagina", help="Numero de pagina (1 = la primera), usando --limite por pagina."
    ),
    detallado: bool = typer.Option(
        False,
        "--detallado",
        help=(
            "Muestra cada hallazgo completo: descripcion, evidencias, URL y estado de "
            "verificacion."
        ),
    ),
    solo_urls: bool = typer.Option(
        False,
        "--solo-urls",
        help="Lista unicamente las URL observadas y guardadas, una por linea, sin duplicados.",
    ),
    guardar: Path | None = typer.Option(  # noqa: B008
        None,
        "--guardar",
        help="Guarda la salida de --detallado/--solo-urls en un archivo .txt o .json.",
    ),
) -> None:
    """Muestra los hallazgos OSINT guardados de un proyecto o investigacion."""
    if pagina < 1:
        consola.print("[bold red]Error:[/bold red] --pagina debe ser al menos 1.")
        raise typer.Exit(code=1)
    if limite < 1:
        consola.print("[bold red]Error:[/bold red] --limite debe ser al menos 1.")
        raise typer.Exit(code=1)

    base_datos = obtener_base_datos()
    proyecto_obj = resolver_proyecto(base_datos, proyecto)

    if solo_urls:
        # Las URL se deduplican sobre TODO lo guardado (filtrado por proyecto/
        # investigacion), no solo sobre una pagina: paginar aqui fragmentaria la
        # deduplicacion de forma confusa para el usuario.
        hallazgos = base_datos.listar_hallazgos_osint(
            investigacion_id=investigacion, proyecto_id=proyecto_obj.id, limite=_LIMITE_SIN_PAGINAR
        )
        urls: list[str] = []
        for h in hallazgos:
            for url in _urls_de_hallazgo(h):
                if url not in urls:
                    urls.append(url)
        if not urls:
            consola.print("No hay URL observadas y guardadas con esos filtros.")
            return
        if guardar is not None:
            _guardar_salida_urls(guardar, urls)
            consola.print(f"Se guardaron {len(urls)} URL en: {texto_seguro(guardar)}")
            return
        for url in urls:
            consola.print(url)
        return

    total = base_datos.contar_hallazgos_osint(
        investigacion_id=investigacion, proyecto_id=proyecto_obj.id
    )
    if total == 0:
        consola.print(
            f"No hay hallazgos OSINT guardados para '{proyecto_obj.nombre}' con esos filtros."
        )
        return
    total_paginas = max(1, (total + limite - 1) // limite)
    if pagina > total_paginas:
        consola.print(
            f"[bold yellow]Aviso:[/bold yellow] solo hay {total_paginas} pagina(s) "
            f"disponible(s) con --limite {limite}."
        )
        return

    hallazgos = base_datos.listar_hallazgos_osint(
        investigacion_id=investigacion,
        proyecto_id=proyecto_obj.id,
        limite=limite,
        desplazamiento=(pagina - 1) * limite,
    )

    if detallado:
        if guardar is not None:
            _guardar_salida_detallada(guardar, hallazgos)
            consola.print(f"Se guardaron {len(hallazgos)} hallazgo(s) en: {texto_seguro(guardar)}")
            return
        for h in hallazgos:
            consola.print(_panel_detallado(h))
        if total_paginas > 1:
            consola.print(f"\nPagina {pagina}/{total_paginas} ({total} hallazgo(s) en total).")
        return

    consola.print(
        _tabla_resultados(
            hallazgos,
            f"Hallazgos OSINT - {proyecto_obj.nombre}",
            pagina=pagina,
            total_paginas=total_paginas,
        )
    )


def _guardar_salida_urls(ruta: Path, urls: list[str]) -> None:
    ruta.parent.mkdir(parents=True, exist_ok=True)
    if ruta.suffix.lower() == ".json":
        ruta.write_text(json.dumps(urls, ensure_ascii=False, indent=2), encoding="utf-8")
    else:
        ruta.write_text("\n".join(urls) + ("\n" if urls else ""), encoding="utf-8")


def _hallazgo_a_dict_completo(h: HallazgoOSINTGuardado) -> dict:
    return {
        "id": h.id,
        "fuente": h.fuente,
        "categoria": h.categoria,
        "titulo": h.titulo,
        "descripcion": h.descripcion,
        "nivel_confianza": h.nivel_confianza,
        "estado_verificacion": _ESTADOS_VERIFICACION.get(h.nivel_confianza, "Sin clasificar."),
        "indicador_exposicion": h.indicador_exposicion,
        "creado_en": h.creado_en,
        "evidencias": json.loads(h.evidencias_json),
    }


def _guardar_salida_detallada(ruta: Path, hallazgos: list[HallazgoOSINTGuardado]) -> None:
    ruta.parent.mkdir(parents=True, exist_ok=True)
    datos = [_hallazgo_a_dict_completo(h) for h in hallazgos]
    if ruta.suffix.lower() == ".json":
        ruta.write_text(json.dumps(datos, ensure_ascii=False, indent=2), encoding="utf-8")
        return
    lineas: list[str] = []
    for d in datos:
        lineas.append(f"# Hallazgo #{d['id']} - {d['titulo']}")
        lineas.append(
            f"Fuente: {d['fuente']} | Categoria: {d['categoria']} | Fecha: {d['creado_en']}"
        )
        lineas.append(f"Confianza: {d['nivel_confianza']} ({d['estado_verificacion']})")
        lineas.append(f"Descripcion: {d['descripcion']}")
        lineas.append(f"Indicador de exposicion: {d['indicador_exposicion'] or '(ninguno)'}")
        lineas.append("Evidencias:")
        for e in d["evidencias"]:
            observado = e.get("fecha_observada") or "-"
            referencia = e.get("referencia") or "-"
            lineas.append(
                f"  - [{e.get('fuente')}] {e.get('valor')} "
                f"(consultado: {e.get('fecha_consulta')}, observado: {observado}, "
                f"referencia: {referencia})"
            )
        lineas.append("")
    ruta.write_text("\n".join(lineas), encoding="utf-8")


@osint_app.command("reporte")
def reporte_cmd(
    investigacion_id: int = typer.Argument(
        ..., help="Id de la investigacion (ver 'est osint investigaciones')."
    ),
    formato: str = typer.Option("html", "--formato", help="Formato del informe: html o json."),
    minimizar: bool = typer.Option(
        False, "--minimizar", help="Enmascara el objetivo (correo/telefono/usuario) en el informe."
    ),
    proyecto: str | None = typer.Option(None, "--proyecto", help=_AYUDA_PROYECTO),
    salida: Path | None = typer.Option(  # noqa: B008
        None, "--salida", help="Ruta del archivo de salida (por defecto, se genera una)."
    ),
) -> None:
    """Genera el informe (HTML/JSON) de una investigacion OSINT concreta."""
    base_datos = obtener_base_datos()
    proyecto_obj = resolver_proyecto(base_datos, proyecto)
    ruta = generar_reporte_osint(
        base_datos, proyecto_obj, investigacion_id, formato, minimizar=minimizar, salida=salida
    )
    consola.print(f"Informe OSINT generado en: {texto_seguro(ruta)}")


@osint_app.command("eliminar")
def eliminar_cmd(
    investigacion_id: int = typer.Argument(
        ..., help="Id de la investigacion (ver 'est osint investigaciones')."
    ),
    confirmar: bool = typer.Option(
        False, "--confirmar", help="Confirma el borrado permanente de la investigacion y hallazgos."
    ),
) -> None:
    """Borra una investigacion OSINT y todos sus hallazgos asociados (irreversible)."""
    if not confirmar:
        consola.print(
            "[bold yellow]Aviso:[/bold yellow] este comando borra la investigacion y todos "
            "sus hallazgos de forma permanente. Repite el comando con --confirmar para continuar."
        )
        raise typer.Exit(code=1)
    base_datos = obtener_base_datos()
    base_datos.eliminar_investigacion_osint(investigacion_id)
    consola.print(f"Investigacion OSINT #{investigacion_id} y sus hallazgos se borraron.")


@osint_app.command("purgar")
def purgar_cmd(
    dias: int = typer.Option(
        90, "--dias", help="Borra investigaciones (y sus hallazgos) creadas hace mas de N dias."
    ),
    confirmar: bool = typer.Option(
        False, "--confirmar", help="Confirma el borrado permanente de las investigaciones expiradas"
    ),
) -> None:
    """Aplica una politica de retencion: borra investigaciones OSINT antiguas (irreversible)."""
    if dias < 1:
        consola.print("[bold red]Error:[/bold red] --dias debe ser al menos 1.")
        raise typer.Exit(code=1)
    if not confirmar:
        consola.print(
            f"[bold yellow]Aviso:[/bold yellow] esto borraria permanentemente toda investigacion "
            f"OSINT (y sus hallazgos) creada hace mas de {dias} dia(s). Repite el comando con "
            "--confirmar para continuar."
        )
        raise typer.Exit(code=1)
    base_datos = obtener_base_datos()
    total = base_datos.purgar_investigaciones_osint_expiradas(dias)
    consola.print(f"Se borraron {total} investigacion(es) OSINT con mas de {dias} dia(s).")
