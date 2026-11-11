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
    "web": (
        "Auditoria web no intrusiva (Fase 3, Paso 3): cabeceras de seguridad,\n"
        "certificado/TLS, cookies y redirecciones. Solo funciona contra objetivos\n"
        "ya autorizados en el alcance del proyecto; por ahora solo se admiten URL\n"
        "con direcciones IPv4 literales (no nombres de dominio).\n\n"
        "est web cabeceras URL [--proyecto NOMBRE] [--tiempo-limite 10]\n"
        "    [--seguir-redirecciones] [--detallado]\n"
        "est web tls URL [...]\n"
        "est web cookies URL [...]\n"
        "est web auditar URL [...]   (las cuatro categorias a la vez)\n"
        "est web reporte --formato html|json [--proyecto NOMBRE] [--salida RUTA]\n\n"
        "- URL: por ejemplo 'https://127.0.0.1:8443/panel'. Debe estar autorizada\n"
        "  en el alcance del proyecto (misma IP que 'est alcance agregar').\n"
        "- --tiempo-limite: segundos maximos de espera por peticion (1 a 30).\n"
        "- --seguir-redirecciones: si el objetivo redirige, audita tambien el\n"
        "  destino, pero solo si tambien es una IPv4 literal autorizada en el\n"
        "  alcance; si no, AST se detiene y lo reporta como hallazgo (no sigue\n"
        "  redirecciones fuera de alcance ni hacia nombres de dominio, para\n"
        "  evitar SSRF).\n"
        "- --detallado: muestra la explicacion completa (que significa, para que\n"
        "  sirve, riesgo, recomendacion y referencia) de cada hallazgo.\n"
        "- Cada hallazgo indica una severidad justificada (info/baja/media/alta):\n"
        "  AST nunca marca automaticamente toda cabecera ausente como critica.\n"
        "- AST nunca desactiva la validacion TLS para dar un resultado exitoso\n"
        "  falso: si el certificado no es confiable, lo reporta como tal.\n"
        "- Los valores de cookies nunca se muestran ni se guardan: solo su\n"
        "  nombre y sus atributos (Secure, HttpOnly, SameSite...)."
    ),
    "nuclei": (
        "Integracion con Nuclei (Fase 3, Paso 4): solo plantillas HTTP de bajo\n"
        "impacto, elegidas de un catalogo aprobado por AST (nunca una ruta de\n"
        "plantilla arbitraria). Cada plantilla es una unica peticion GET de\n"
        "solo lectura; nunca sigue redirecciones ni usa Interactsh/OAST. Solo\n"
        "funciona contra objetivos ya autorizados en el alcance del proyecto.\n"
        "Requiere tener Nuclei instalado.\n\n"
        "est nuclei version\n"
        "est nuclei plantillas\n"
        "est nuclei analizar OBJETIVO --plantillas id1,id2 [--proyecto NOMBRE]\n"
        "    [--tiempo-limite 60]\n"
        "est nuclei resultados [--proyecto NOMBRE] [--limite 50]\n"
        "est nuclei revisar ID --estado nuevo|confirmado|falso_positivo\n"
        "est nuclei reporte --formato html|json [--proyecto NOMBRE] [--salida RUTA]\n\n"
        "- OBJETIVO: IP, o esquema://IP[:puerto] (sin ruta: las rutas las define\n"
        "  cada plantilla, nunca el usuario).\n"
        "- --plantillas: identificadores del catalogo aprobado (ver\n"
        "  'est nuclei plantillas'); no se acepta ninguna otra plantilla.\n"
        "- --tiempo-limite: segundos maximos de espera para Nuclei (5 a 120).\n"
        "- Ningun hallazgo guarda el request/response completo de Nuclei ni\n"
        "  cookies de sesion: solo un resumen saneado (plantilla, severidad,\n"
        "  descripcion y donde se detecto)."
    ),
    "zap": (
        "Integracion con OWASP ZAP (Fase 3, Paso 5): analisis pasivo unicamente, nunca\n"
        "active scan, spider, ajaxSpider ni fuzzing. ZAP no lo instala AST: debe estar\n"
        "ya corriendo por tu cuenta, con su API expuesta en loopback.\n\n"
        "est zap estado\n"
        "est zap pasivo URL [--proyecto NOMBRE] [--tiempo-limite 60]\n"
        "est zap resultados [--proyecto NOMBRE] [--limite 50]\n"
        "est zap revisar ID --estado nuevo|confirmado|falso_positivo\n"
        "est zap reporte --formato html|json [--proyecto NOMBRE] [--salida RUTA]\n\n"
        "- URL: debe ser una IPv4 literal ya autorizada en el alcance del proyecto\n"
        "  (misma regla que 'est web auditar'); no se admiten nombres de dominio.\n"
        "- 'est zap pasivo' hace una unica peticion GET controlada (via la propia\n"
        "  API de ZAP, 'accessUrl', sin seguir redirecciones) para alimentar el\n"
        "  analizador pasivo, y luego lee solo las alertas de ESE objetivo -- nunca\n"
        "  mezcla alertas de otras auditorias que pudiera tener la misma instancia\n"
        "  de ZAP.\n"
        "- Configuracion: variables de entorno EST_ZAP_URL (por defecto\n"
        "  'http://127.0.0.1:8080', siempre loopback) y EST_ZAP_API_KEY (opcional;\n"
        "  nunca se muestra en pantalla, en logs ni en informes).\n"
        "- Ningun hallazgo guarda peticiones/respuestas completas: solo un resumen\n"
        "  saneado (regla, riesgo, confianza, evidencia truncada y redactada)."
    ),
    "osint": (
        "Investigacion de fuentes publicas (OSINT) sobre un dominio, correo,\n"
        "telefono o nombre de usuario. Nunca ejecuta un escaneo activo contra el\n"
        "objetivo: solo consulta fuentes publicas documentadas (DNS, RDAP,\n"
        "Certificate Transparency, APIs publicas de GitHub/GitLab...).\n\n"
        "est osint dominio DOMINIO [--proyecto NOMBRE] [--fuentes ...]\n"
        "est osint correo CORREO --autorizo [--proyecto NOMBRE] [--fuentes ...]\n"
        "est osint telefono NUMERO --autorizo [--region CO] [--proyecto NOMBRE]\n"
        "est osint usuario NOMBRE_USUARIO --autorizo [--proyecto NOMBRE]\n"
        "est osint fuentes [--tipo dominio|correo|telefono|usuario]\n"
        "est osint investigaciones [--proyecto NOMBRE] [--limite 20]\n"
        "est osint resultados [--proyecto NOMBRE] [--investigacion ID]\n"
        "est osint eliminar INVESTIGACION_ID --confirmar\n\n"
        "- --autorizo es obligatorio para correo/telefono/usuario (datos\n"
        "  potencialmente personales): confirma que el objetivo es propio o que\n"
        "  su revision esta autorizada. 'dominio' no lo exige.\n"
        "- Cada hallazgo indica su nivel de confianza (confirmado/probable/\n"
        "  no_verificado): una coincidencia de usuario NUNCA se trata como una\n"
        "  identidad confirmada.\n"
        "- Las investigaciones OSINT se guardan separadas de los hallazgos\n"
        "  tecnicos (nunca aparecen en 'est resultados').\n"
        "- Ver docs/OSINT.md para el detalle de cada fuente y sus limitaciones."
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
