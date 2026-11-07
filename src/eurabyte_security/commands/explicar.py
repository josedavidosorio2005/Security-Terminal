"""Ayuda interactiva: explicaciones en espanol de cada comando."""

from __future__ import annotations

import typer
from rich.panel import Panel

from eurabyte_security.ui.consola import consola, texto_seguro

EXPLICACIONES: dict[str, str] = {
    "proyecto": (
        "Gestiona proyectos de auditoria.\n\n"
        "- est proyecto crear NOMBRE   -> crea un proyecto y lo activa.\n"
        "- est proyecto listar          -> muestra todos los proyectos (el activo con '*').\n"
        "- est proyecto usar NOMBRE     -> cambia el proyecto activo."
    ),
    "alcance": (
        "Registra el alcance autorizado de un proyecto: solo se podra escanear\n"
        "dentro de las IP/redes aqui registradas.\n\n"
        "- est alcance agregar OBJETIVO [--proyecto NOMBRE]\n"
        "  OBJETIVO puede ser una IP (127.0.0.1) o una red CIDR (192.168.1.0/24).\n"
        "- est alcance listar [--proyecto NOMBRE]"
    ),
    "tcp": (
        "Comprueba el estado de puertos TCP mediante una conexion directa\n"
        "(connect scan). Solo funciona contra objetivos ya autorizados en el\n"
        "alcance del proyecto.\n\n"
        "est escanear tcp OBJETIVO --puertos 22,80,443 [--proyecto NOMBRE] "
        "[--timeout 1.0] [--concurrencia 50]\n\n"
        "- OBJETIVO: direccion IPv4 (no se admiten nombres de dominio en esta fase).\n"
        "- --timeout: segundos de espera por puerto (0.1 a 10).\n"
        "- --concurrencia: conexiones simultaneas permitidas (1 a 200)."
    ),
    "escanear": (
        "Grupo de comandos de comprobacion de red. En la Fase 1 solo incluye\n"
        "'tcp'. Usa 'est explicar tcp' para ver el detalle."
    ),
    "resultados": (
        "Muestra los resultados guardados de escaneos anteriores.\n\n"
        "est resultados [--proyecto NOMBRE] [--limite 50]"
    ),
    "reporte": (
        "Genera un informe a partir de los resultados guardados.\n\n"
        "est reporte generar --formato html|json [--proyecto NOMBRE] [--salida RUTA]"
    ),
    "interactivo": (
        "Abre la terminal interactiva de linea de comandos, con autocompletado\n"
        "(Tab) e historial de comandos (flechas arriba/abajo).\n\n"
        "est interactivo"
    ),
    "interfaz": (
        "Abre la interfaz visual completa de AST (Textual): barra lateral de\n"
        "secciones, terminal integrada, formularios y tablas de resultados,\n"
        "con teclado y raton. Requiere una consola real.\n\n"
        "est interfaz"
    ),
    "nmap": (
        "Integracion con Nmap (Fase 3): descubrimiento de puertos y, si se\n"
        "autoriza explicitamente, identificacion de servicios/version. Solo\n"
        "funciona contra objetivos ya autorizados en el alcance del proyecto,\n"
        "igual que 'escanear tcp'. Requiere tener Nmap instalado.\n\n"
        "est nmap descubrir OBJETIVO --puertos 22,80,443 [--proyecto NOMBRE]\n"
        "    [--deteccion-version] [--tiempo-limite 120]\n"
        "est nmap version\n\n"
        "- --deteccion-version: activa '-sV' (identificacion de servicios).\n"
        "  Usalo solo si esa comprobacion esta explicitamente autorizada.\n"
        "- --tiempo-limite: segundos maximos de espera para Nmap (5 a 600).\n"
        "- Cada analisis guarda su salida XML original como evidencia en el\n"
        "  directorio de datos de AST (carpeta 'evidencias/nmap')."
    ),
}

def explicar_cmd(
    tema: str = typer.Argument(
        None, help="Tema a explicar (proyecto, alcance, tcp, escanear, resultados, reporte...)."
    ),
) -> None:
    """Explica en espanol como funciona un comando y sus parametros."""
    if not tema:
        temas = ", ".join(sorted(EXPLICACIONES))
        consola.print(f"Indica un tema. Temas disponibles: {temas}")
        return

    texto = EXPLICACIONES.get(tema.lower())
    if texto is None:
        temas = ", ".join(sorted(EXPLICACIONES))
        consola.print(
            f"No hay una explicacion para '{texto_seguro(tema)}'. Temas disponibles: {temas}"
        )
        return

    consola.print(Panel(texto, title=f"Explicacion: {texto_seguro(tema)}", border_style="cyan"))
