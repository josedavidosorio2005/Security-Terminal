"""Comandos OSINT: investigacion de fuentes publicas sobre un objetivo autorizado."""

from __future__ import annotations

import typer
from rich.table import Table

from eurabyte_security.commands._comun import obtener_base_datos, resolver_proyecto
from eurabyte_security.integrations.osint.registro import FUENTES_OSINT, fuentes_para_tipo
from eurabyte_security.modules.osint.modelos import EtapaFuenteOSINT
from eurabyte_security.modules.osint.motor import ejecutar_investigacion_osint
from eurabyte_security.storage.database import BaseDatos, Proyecto
from eurabyte_security.ui.consola import consola, texto_seguro

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
    if resultado.limitaciones:
        consola.print("\n[bold yellow]Limitaciones:[/bold yellow]")
        for limitacion in resultado.limitaciones:
            consola.print(f"- {texto_seguro(limitacion)}")
    consola.print(
        f"\nUsa 'est osint resultados --investigacion {resultado.investigacion_id}' "
        "para ver el detalle."
    )


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
) -> None:
    """Normaliza y valida un numero de telefono (E.164, region, tipo de numero)."""
    base_datos = obtener_base_datos()
    proyecto_obj = resolver_proyecto(base_datos, proyecto)
    _ejecutar_y_mostrar(
        base_datos,
        proyecto_obj,
        "telefono",
        telefono,
        autorizado=autorizo,
        fuentes_txt=None,
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


@osint_app.command("resultados")
def resultados_cmd(
    proyecto: str | None = typer.Option(None, "--proyecto", help=_AYUDA_PROYECTO),
    investigacion: int | None = typer.Option(
        None,
        "--investigacion",
        help="Limita a una investigacion concreta (ver 'est osint investigaciones').",
    ),
    limite: int = typer.Option(100, "--limite", help="Numero maximo de hallazgos a mostrar."),
) -> None:
    """Muestra los hallazgos OSINT guardados de un proyecto o investigacion."""
    base_datos = obtener_base_datos()
    proyecto_obj = resolver_proyecto(base_datos, proyecto)
    hallazgos = base_datos.listar_hallazgos_osint(
        investigacion_id=investigacion, proyecto_id=proyecto_obj.id, limite=limite
    )

    if not hallazgos:
        consola.print(
            f"No hay hallazgos OSINT guardados para '{proyecto_obj.nombre}' con esos filtros."
        )
        return

    tabla = Table(title=f"Hallazgos OSINT - {proyecto_obj.nombre}")
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
            h.fuente,
            h.categoria,
            texto_seguro(h.titulo),
            confianza_texto,
            texto_seguro(h.indicador_exposicion) if h.indicador_exposicion else "-",
            h.creado_en,
        )
    consola.print(tabla)


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
