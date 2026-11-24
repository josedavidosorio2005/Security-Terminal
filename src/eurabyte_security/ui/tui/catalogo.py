"""Navegación y fichas de la interfaz, en el orden del menú."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Seccion:
    panel: str
    titulo: str
    descripcion: str
    requisitos: str


_ESPACIO_TRABAJO = (
    "Espacio de trabajo",
    (
        Seccion(
            "panel-inicio",
            "Inicio",
            "Resume el proyecto, sus objetivos y resultados técnicos.",
            "Instalación de AST. Crea un proyecto para empezar.",
        ),
        Seccion(
            "panel-terminal",
            "Terminal",
            "Ejecuta comandos de AST con autocompletado, historial y ayuda.",
            "Los requisitos dependen del comando. Escribe «ayuda» para consultar el listado.",
        ),
        Seccion(
            "panel-proyectos",
            "Proyectos",
            "Crea proyectos, consulta los existentes y cambia el proyecto activo.",
            "Nombre único (hasta 64 caracteres): letras, números, puntos, guiones o guiones bajos.",
        ),
        Seccion(
            "panel-alcance",
            "Alcance",
            "Registra las direcciones IP o redes CIDR autorizadas.",
            "Proyecto activo y direcciones autorizadas.",
        ),
        Seccion(
            "panel-modulos",
            "Módulos",
            "Consulta qué hace cada módulo y qué necesita para funcionar.",
            "Abre Herramientas para revisar las dependencias externas.",
        ),
    ),
)

GRUPOS_MODULOS = (
    (
        "Análisis",
        (
            Seccion(
                "panel-web",
                "Análisis web",
                "Revisa cabeceras HTTP, TLS, cookies y redirecciones.",
                "Proyecto y URL HTTP(S) con IPv4 autorizada.",
            ),
            Seccion(
                "panel-redes",
                "Redes",
                "Comprueba la conectividad TCP y registra resultados por puerto.",
                "Proyecto activo, IP autorizada y puertos que quieras comprobar.",
            ),
            Seccion(
                "panel-reconocimiento",
                "Reconocimiento",
                "Consulta sesiones y etapas de reconocimiento y el inventario de Nmap.",
                "Nmap en PATH, proyecto activo y objetivo autorizado. Nuclei y ZAP son opcionales.",
            ),
            Seccion(
                "panel-vulnerabilidades",
                "Vulnerabilidades",
                "Revisa hallazgos de Nuclei, su evidencia y su estado de validación.",
                "Para un análisis nuevo: Nuclei en PATH, proyecto y objetivo autorizado.",
            ),
            Seccion(
                "panel-zap",
                "OWASP ZAP",
                "Consulta alertas de análisis pasivo, evidencia y recomendaciones.",
                "Para analizar: API de ZAP activa en loopback, proyecto y URL autorizada.",
            ),
            Seccion(
                "panel-osint",
                "OSINT",
                "Consulta fuentes públicas e investigaciones guardadas sobre dominios, correos, "
                "teléfonos y usuarios.",
                "Proyecto y conectividad para fuentes remotas. Los datos personales requieren "
                "autorización y algunos proveedores usan credenciales opcionales.",
            ),
        ),
    ),
    (
        "Defensa",
        (
            Seccion(
                "panel-trafico",
                "Tráfico de red",
                "Mide carga y descarga locales y resume el tráfico registrado de una LAN.",
                "Para medir usa psutil, incluido con AST. Para la LAN, usa conn.log de Zeek "
                "en JSON y las subredes en CIDR.",
            ),
            Seccion(
                "panel-operaciones",
                "Operaciones",
                "Documenta casos y correcciones, vincula evidencia y monitorea interfaces locales.",
                "Proyecto activo. El monitoreo requiere un umbral de velocidad en Mbps.",
            ),
        ),
    ),
    (
        "Evidencia",
        (
            Seccion(
                "panel-resultados",
                "Resultados",
                "Filtra resultados técnicos guardados y consulta su evidencia.",
                "Proyecto activo y resultados guardados para poblar la vista.",
            ),
            Seccion(
                "panel-reportes",
                "Reportes",
                "Exporta el informe técnico global del proyecto en HTML o JSON.",
                "Proyecto activo y acceso de escritura al directorio de reportes.",
            ),
        ),
    ),
)

_SISTEMA = (
    "Sistema",
    (
        Seccion(
            "panel-herramientas",
            "Herramientas",
            "Comprueba la disponibilidad de Nmap, Nuclei, OWASP ZAP y tshark.",
            "Los binarios deben estar en PATH. Para ZAP se comprueba su API local.",
        ),
        Seccion(
            "panel-aprendizaje",
            "Aprendizaje",
            "Consulta las explicaciones en español de los comandos y herramientas.",
            "Instalación de AST.",
        ),
        Seccion(
            "panel-configuracion",
            "Configuración",
            "Muestra las rutas de datos, base de datos e historial. Activa un proyecto.",
            "Para cambiar de proyecto, indica el nombre de uno existente.",
        ),
    ),
)

GRUPOS = (_ESPACIO_TRABAJO, *GRUPOS_MODULOS, _SISTEMA)
SECCIONES_POR_PANEL = {seccion.panel: seccion for _, grupo in GRUPOS for seccion in grupo}
