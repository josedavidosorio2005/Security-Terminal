"""Construccion de informes de auditoria en JSON y HTML."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from html import escape

from eurabyte_security.core.osint.redaccion import minimizar_objetivo
from eurabyte_security.core.redaccion import redactar_texto_libre
from eurabyte_security.modules.osint.exposicion import (
    ResumenExposicion,
    construir_resumen_exposicion,
)
from eurabyte_security.storage.database import (
    FUENTES_RESULTADOS,
    HallazgoOSINTGuardado,
    InvestigacionOSINT,
    Resultado,
    ResultadoNuclei,
    ResultadoUnificado,
    ResultadoWeb,
    ResultadoZAP,
    agrupar_severidad,
)

_ETIQUETAS_FUENTE = {
    "tcp": "TCP",
    "nmap": "Nmap",
    "web": "Auditoria web",
    "nuclei": "Nuclei",
    "zap": "OWASP ZAP",
}

# Fuentes que reportan conectividad/reconocimiento (puertos), no vulnerabilidades: el
# informe global las muestra en una tabla aparte para no mezclar ambos conceptos (ver
# ``ResultadoUnificado``).
_FUENTES_RED = frozenset({"tcp", "nmap"})
_FUENTES_VULNERABILIDAD = frozenset(FUENTES_RESULTADOS) - _FUENTES_RED

_ORDEN_GRUPO_SEVERIDAD = {"alta": 3, "media": 2, "baja": 1, "info": 0}


@dataclass(frozen=True, slots=True)
class DatosInforme:
    proyecto: str
    generado_en: str
    resultados: list[Resultado]


def construir_datos_informe(proyecto: str, resultados: list[Resultado]) -> DatosInforme:
    return DatosInforme(
        proyecto=proyecto,
        generado_en=datetime.now(UTC).isoformat(),
        resultados=resultados,
    )


def generar_json(datos: DatosInforme) -> str:
    cuerpo = {
        "proyecto": datos.proyecto,
        "generado_en": datos.generado_en,
        "total_resultados": len(datos.resultados),
        "resultados": [
            {
                "objetivo": r.objetivo,
                "puerto": r.puerto,
                "estado": r.estado,
                "creado_en": r.creado_en,
            }
            for r in datos.resultados
        ],
    }
    return json.dumps(cuerpo, ensure_ascii=False, indent=2)


_ESTILOS = """
body {
  font-family: 'Segoe UI', Arial, sans-serif;
  background: #0f1117;
  color: #e6e6e6;
  margin: 2rem;
}
h1 { color: #4fd1c5; }
table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
th, td { padding: 0.5rem 0.75rem; border-bottom: 1px solid #2d2f36; text-align: left; }
th { background: #1a1d26; }
.abierto { color: #68d391; font-weight: bold; }
.cerrado { color: #a0aec0; }
.error { color: #fc8181; }
.resumen { color: #a0aec0; margin-bottom: 1rem; }
.severidad-info, .severidad-unknown, .severidad-informational { color: #a0aec0; }
.severidad-baja, .severidad-low { color: #4fd1c5; }
.severidad-media, .severidad-medium { color: #f6e05e; font-weight: bold; }
.severidad-alta, .severidad-high, .severidad-critical { color: #fc8181; font-weight: bold; }
.severidad-confirmado { color: #68d391; font-weight: bold; }
.severidad-probable { color: #f6e05e; }
.severidad-no_verificado { color: #a0aec0; }
"""


def _pagina_html(titulo: str, resumen: str, cuerpo_tabla: str) -> str:
    """Esqueleto HTML comun a todos los informes de AST (mismo CSS y cabecera)."""
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>{escape(titulo)}</title>
<style>{_ESTILOS}</style>
</head>
<body>
<h1>AURABYTE Security Terminal - Informe de auditoria</h1>
<p class="resumen">{resumen}</p>
{cuerpo_tabla}
</body>
</html>
"""


def generar_html(datos: DatosInforme) -> str:
    filas = "\n".join(
        f"<tr><td>{escape(r.objetivo)}</td><td>{r.puerto}</td>"
        f"<td class=\"{escape(r.estado)}\">{escape(r.estado)}</td>"
        f"<td>{escape(r.creado_en)}</td></tr>"
        for r in datos.resultados
    )
    if not filas:
        filas = "<tr><td colspan=\"4\">No hay resultados registrados.</td></tr>"

    cuerpo_tabla = (
        "<table>\n"
        "<thead><tr><th>Objetivo</th><th>Puerto</th><th>Estado</th><th>Fecha</th></tr></thead>\n"
        f"<tbody>\n{filas}\n</tbody>\n</table>"
    )
    resumen = (
        f"Proyecto: <strong>{escape(datos.proyecto)}</strong> &middot; "
        f"Generado: {escape(datos.generado_en)} &middot; "
        f"Total de resultados: {len(datos.resultados)}"
    )
    return _pagina_html(f"Informe AST - {datos.proyecto}", resumen, cuerpo_tabla)


@dataclass(frozen=True, slots=True)
class DatosInformeWeb:
    proyecto: str
    generado_en: str
    hallazgos: list[ResultadoWeb]


def construir_datos_informe_web(proyecto: str, hallazgos: list[ResultadoWeb]) -> DatosInformeWeb:
    return DatosInformeWeb(
        proyecto=proyecto,
        generado_en=datetime.now(UTC).isoformat(),
        hallazgos=hallazgos,
    )


def generar_json_web(datos: DatosInformeWeb) -> str:
    cuerpo = {
        "proyecto": datos.proyecto,
        "generado_en": datos.generado_en,
        "total_hallazgos": len(datos.hallazgos),
        "hallazgos": [
            {
                "objetivo": h.objetivo,
                "tipo_analisis": h.tipo_analisis,
                "categoria": h.categoria,
                "nombre_hallazgo": h.nombre_hallazgo,
                "severidad": h.severidad,
                "estado": h.estado,
                "valor_detectado": h.valor_detectado,
                "riesgo": h.riesgo,
                "recomendacion": h.recomendacion,
                "referencia": h.referencia,
                "creado_en": h.creado_en,
            }
            for h in datos.hallazgos
        ],
    }
    return json.dumps(cuerpo, ensure_ascii=False, indent=2)


def generar_html_web(datos: DatosInformeWeb) -> str:
    filas = "\n".join(
        f"<tr><td>{escape(h.objetivo)}</td><td>{escape(h.categoria)}</td>"
        f"<td>{escape(h.nombre_hallazgo)}</td><td>{escape(h.estado)}</td>"
        f"<td class=\"severidad-{escape(h.severidad)}\">{escape(h.severidad)}</td>"
        f"<td>{escape(h.valor_detectado or '-')}</td>"
        f"<td>{escape(h.recomendacion)}</td><td>{escape(h.creado_en)}</td></tr>"
        for h in datos.hallazgos
    )
    if not filas:
        filas = "<tr><td colspan=\"8\">No hay hallazgos de auditoria web registrados.</td></tr>"

    cuerpo_tabla = (
        "<table>\n<thead><tr><th>Objetivo</th><th>Categoria</th><th>Hallazgo</th>"
        "<th>Estado</th><th>Severidad</th><th>Valor detectado</th><th>Recomendacion</th>"
        "<th>Fecha</th></tr></thead>\n"
        f"<tbody>\n{filas}\n</tbody>\n</table>"
    )
    resumen = (
        f"Proyecto: <strong>{escape(datos.proyecto)}</strong> &middot; "
        f"Generado: {escape(datos.generado_en)} &middot; "
        f"Total de hallazgos: {len(datos.hallazgos)}"
    )
    return _pagina_html(f"Informe web AST - {datos.proyecto}", resumen, cuerpo_tabla)


@dataclass(frozen=True, slots=True)
class DatosInformeNuclei:
    proyecto: str
    generado_en: str
    hallazgos: list[ResultadoNuclei]


def construir_datos_informe_nuclei(
    proyecto: str, hallazgos: list[ResultadoNuclei]
) -> DatosInformeNuclei:
    return DatosInformeNuclei(
        proyecto=proyecto,
        generado_en=datetime.now(UTC).isoformat(),
        hallazgos=hallazgos,
    )


def generar_json_nuclei(datos: DatosInformeNuclei) -> str:
    cuerpo = {
        "proyecto": datos.proyecto,
        "generado_en": datos.generado_en,
        "total_hallazgos": len(datos.hallazgos),
        "hallazgos": [
            {
                "objetivo": h.objetivo,
                "plantilla_id": h.plantilla_id,
                "plantilla_version": h.plantilla_version,
                "nombre_hallazgo": h.nombre_hallazgo,
                "severidad": h.severidad,
                "descripcion": h.descripcion,
                "evidencia": h.evidencia,
                "estado_revision": h.estado_revision,
                "creado_en": h.creado_en,
            }
            for h in datos.hallazgos
        ],
    }
    return json.dumps(cuerpo, ensure_ascii=False, indent=2)


def generar_html_nuclei(datos: DatosInformeNuclei) -> str:
    filas = "\n".join(
        f"<tr><td>{escape(h.objetivo)}</td><td>{escape(h.plantilla_id)}</td>"
        f"<td>{escape(h.plantilla_version)}</td><td>{escape(h.nombre_hallazgo)}</td>"
        f"<td class=\"severidad-{escape(h.severidad)}\">{escape(h.severidad)}</td>"
        f"<td>{escape(h.descripcion)}</td><td>{escape(h.evidencia or '-')}</td>"
        f"<td>{escape(h.estado_revision)}</td><td>{escape(h.creado_en)}</td></tr>"
        for h in datos.hallazgos
    )
    if not filas:
        filas = "<tr><td colspan=\"9\">No hay hallazgos de Nuclei registrados.</td></tr>"

    cuerpo_tabla = (
        "<table>\n<thead><tr><th>Objetivo</th><th>Plantilla</th><th>Version</th>"
        "<th>Hallazgo</th><th>Severidad</th><th>Descripcion</th><th>Evidencia</th>"
        "<th>Revision</th><th>Fecha</th></tr></thead>\n"
        f"<tbody>\n{filas}\n</tbody>\n</table>"
    )
    resumen = (
        f"Proyecto: <strong>{escape(datos.proyecto)}</strong> &middot; "
        f"Generado: {escape(datos.generado_en)} &middot; "
        f"Total de hallazgos: {len(datos.hallazgos)}"
    )
    return _pagina_html(f"Informe Nuclei AST - {datos.proyecto}", resumen, cuerpo_tabla)


@dataclass(frozen=True, slots=True)
class DatosInformeZAP:
    proyecto: str
    generado_en: str
    hallazgos: list[ResultadoZAP]


def construir_datos_informe_zap(proyecto: str, hallazgos: list[ResultadoZAP]) -> DatosInformeZAP:
    return DatosInformeZAP(
        proyecto=proyecto,
        generado_en=datetime.now(UTC).isoformat(),
        hallazgos=hallazgos,
    )


def generar_json_zap(datos: DatosInformeZAP) -> str:
    cuerpo = {
        "proyecto": datos.proyecto,
        "generado_en": datos.generado_en,
        "total_hallazgos": len(datos.hallazgos),
        "hallazgos": [
            {
                "objetivo": h.objetivo,
                "plugin_id": h.plugin_id,
                "nombre_hallazgo": h.nombre_hallazgo,
                "riesgo": h.riesgo,
                "confianza": h.confianza,
                "descripcion": h.descripcion,
                "evidencia": h.evidencia,
                "solucion": h.solucion,
                "referencia": h.referencia,
                "estado_revision": h.estado_revision,
                "creado_en": h.creado_en,
            }
            for h in datos.hallazgos
        ],
    }
    return json.dumps(cuerpo, ensure_ascii=False, indent=2)


def generar_html_zap(datos: DatosInformeZAP) -> str:
    filas = "\n".join(
        f"<tr><td>{escape(h.objetivo)}</td><td>{escape(h.plugin_id)}</td>"
        f"<td>{escape(h.nombre_hallazgo)}</td>"
        f"<td class=\"severidad-{escape(h.riesgo.lower())}\">{escape(h.riesgo)}</td>"
        f"<td>{escape(h.confianza)}</td>"
        f"<td>{escape(h.solucion)}</td><td>{escape(h.estado_revision)}</td>"
        f"<td>{escape(h.creado_en)}</td></tr>"
        for h in datos.hallazgos
    )
    if not filas:
        filas = "<tr><td colspan=\"8\">No hay hallazgos de OWASP ZAP registrados.</td></tr>"

    cuerpo_tabla = (
        "<table>\n<thead><tr><th>Objetivo</th><th>Regla</th><th>Hallazgo</th>"
        "<th>Riesgo</th><th>Confianza</th><th>Solucion</th><th>Revision</th>"
        "<th>Fecha</th></tr></thead>\n"
        f"<tbody>\n{filas}\n</tbody>\n</table>"
    )
    resumen = (
        f"Proyecto: <strong>{escape(datos.proyecto)}</strong> &middot; "
        f"Generado: {escape(datos.generado_en)} &middot; "
        f"Total de hallazgos: {len(datos.hallazgos)}"
    )
    return _pagina_html(f"Informe OWASP ZAP AST - {datos.proyecto}", resumen, cuerpo_tabla)


@dataclass(frozen=True, slots=True)
class DatosInformeGlobal:
    """Datos de entrada del informe global: una auditoria completa, no una herramienta."""

    proyecto: str
    generado_en: str
    resultados: list[ResultadoUnificado]
    herramientas: tuple[str, ...]
    alcance: tuple[str, ...]


def _redactar_resultado_unificado(r: ResultadoUnificado) -> ResultadoUnificado:
    """Segunda pasada de redaccion, propia del informe global, antes de exportarlo.

    Cada herramienta ya redacta lo que persiste en su propia tabla (ver
    ``commands/web.py:auditar_web`` y ``commands/zap.py:ejecutar_zap_pasivo``), pero un
    informe exportado sale de AST hacia fuera (se comparte, se adjunta a un correo...),
    asi que esta funcion vuelve a tratar como no confiable TODO campo de texto libre que
    pueda venir de una herramienta externa, igual que ``core/redaccion.py`` ya hace para
    la salida cruda de Nuclei/ZAP, en vez de confiar unicamente en lo que se redacto al
    guardar.
    """
    return replace(
        r,
        objetivo=redactar_texto_libre(r.objetivo),
        nombre=redactar_texto_libre(r.nombre),
        descripcion=redactar_texto_libre(r.descripcion) if r.descripcion else r.descripcion,
        evidencia=redactar_texto_libre(r.evidencia) if r.evidencia else r.evidencia,
        recomendacion=(
            redactar_texto_libre(r.recomendacion) if r.recomendacion else r.recomendacion
        ),
        referencia=redactar_texto_libre(r.referencia) if r.referencia else r.referencia,
    )


def construir_datos_informe_global(
    proyecto: str,
    resultados: list[ResultadoUnificado],
    *,
    herramientas: tuple[str, ...] = FUENTES_RESULTADOS,
    alcance: tuple[str, ...] = (),
) -> DatosInformeGlobal:
    return DatosInformeGlobal(
        proyecto=proyecto,
        generado_en=datetime.now(UTC).isoformat(),
        resultados=[_redactar_resultado_unificado(r) for r in resultados],
        herramientas=herramientas,
        alcance=alcance,
    )


def _resumen_por_fuente(resultados: list[ResultadoUnificado]) -> dict[str, int]:
    conteo: dict[str, int] = {}
    for r in resultados:
        conteo[r.fuente] = conteo.get(r.fuente, 0) + 1
    return conteo


def _resumen_por_severidad(resultados: list[ResultadoUnificado]) -> dict[str, int]:
    conteo: dict[str, int] = {}
    for r in resultados:
        if r.fuente not in _FUENTES_VULNERABILIDAD:
            continue
        grupo = agrupar_severidad(r.severidad) or "sin_clasificar"
        conteo[grupo] = conteo.get(grupo, 0) + 1
    return conteo


def _resumen_por_revision(resultados: list[ResultadoUnificado]) -> dict[str, int]:
    conteo: dict[str, int] = {}
    for r in resultados:
        if r.estado_revision is None:
            continue
        conteo[r.estado_revision] = conteo.get(r.estado_revision, 0) + 1
    return conteo


def generar_json_global(datos: DatosInformeGlobal) -> str:
    cuerpo = {
        "proyecto": datos.proyecto,
        "generado_en": datos.generado_en,
        "herramientas_utilizadas": list(datos.herramientas),
        "alcance_autorizado": list(datos.alcance),
        "total_resultados": len(datos.resultados),
        "resumen_por_herramienta": _resumen_por_fuente(datos.resultados),
        "resumen_por_severidad": _resumen_por_severidad(datos.resultados),
        "resumen_por_estado_revision": _resumen_por_revision(datos.resultados),
        "nota_metodologica": (
            "Cada registro proviene de una unica herramienta (campo 'fuente') y conserva "
            "su id de origen ('id_origen'): AST no fusiona ni deduplica hallazgos de "
            "distintas herramientas por compartir titulo. 'tcp' y 'nmap' son resultados "
            "de conectividad/puertos (nunca llevan severidad); 'web', 'nuclei' y 'zap' "
            "son hallazgos de auditoria/vulnerabilidad."
        ),
        "resultados": [
            {
                "fuente": r.fuente,
                "id_origen": r.id_origen,
                "objetivo": r.objetivo,
                "tipo": r.tipo,
                "nombre": r.nombre,
                "descripcion": r.descripcion,
                "severidad": r.severidad,
                "estado": r.estado,
                "estado_revision": r.estado_revision,
                "evidencia": r.evidencia,
                "recomendacion": r.recomendacion,
                "referencia": r.referencia,
                "creado_en": r.creado_en,
            }
            for r in datos.resultados
        ],
    }
    return json.dumps(cuerpo, ensure_ascii=False, indent=2)


def _fila_red(r: ResultadoUnificado) -> str:
    return (
        f"<tr><td>{escape(_ETIQUETAS_FUENTE.get(r.fuente, r.fuente))}</td>"
        f"<td>{escape(r.objetivo)}</td><td>{escape(r.nombre)}</td>"
        f"<td class=\"{escape(r.estado or '')}\">{escape(r.estado or '-')}</td>"
        f"<td>{escape(r.descripcion or '-')}</td><td>{escape(r.creado_en)}</td></tr>"
    )


def _fila_vulnerabilidad(r: ResultadoUnificado) -> str:
    grupo = agrupar_severidad(r.severidad) or "unknown"
    return (
        f"<tr><td>{escape(_ETIQUETAS_FUENTE.get(r.fuente, r.fuente))}</td>"
        f"<td>{escape(r.objetivo)}</td><td>{escape(r.tipo)}</td>"
        f"<td>{escape(r.nombre)}</td>"
        f"<td class=\"severidad-{escape(grupo)}\">{escape(r.severidad or '-')}</td>"
        f"<td>{escape(r.estado_revision or 'N/A')}</td>"
        f"<td>{escape(r.descripcion or '-')}</td>"
        f"<td>{escape(r.evidencia or '-')}</td>"
        f"<td>{escape(r.recomendacion or '-')}</td>"
        f"<td>{escape(r.creado_en)}</td></tr>"
    )


def generar_html_global(datos: DatosInformeGlobal) -> str:
    resultados_red = [r for r in datos.resultados if r.fuente in _FUENTES_RED]
    resultados_vuln = sorted(
        (r for r in datos.resultados if r.fuente in _FUENTES_VULNERABILIDAD),
        key=lambda r: (
            _ORDEN_GRUPO_SEVERIDAD.get(agrupar_severidad(r.severidad) or "", -1),
            r.creado_en,
        ),
        reverse=True,
    )

    filas_red = "\n".join(_fila_red(r) for r in resultados_red)
    if not filas_red:
        filas_red = "<tr><td colspan=\"6\">No hay resultados de red/puertos registrados.</td></tr>"

    filas_vuln = "\n".join(_fila_vulnerabilidad(r) for r in resultados_vuln)
    if not filas_vuln:
        filas_vuln = (
            "<tr><td colspan=\"9\">No hay hallazgos de vulnerabilidad registrados.</td></tr>"
        )

    resumen_severidad = _resumen_por_severidad(datos.resultados)
    resumen_fuente = _resumen_por_fuente(datos.resultados)
    resumen_revision = _resumen_por_revision(datos.resultados)

    objetivos = sorted({r.objetivo for r in datos.resultados})
    objetivos_html = "".join(f"<li>{escape(o)}</li>" for o in objetivos) or "<li>(ninguno)</li>"
    alcance_html = (
        "".join(f"<li>{escape(red)}</li>" for red in datos.alcance) or "<li>(sin registrar)</li>"
    )
    herramientas_html = ", ".join(
        escape(_ETIQUETAS_FUENTE.get(h, h)) for h in datos.herramientas
    ) or "(ninguna)"
    resumen_fuente_html = ", ".join(
        f"{escape(_ETIQUETAS_FUENTE.get(f, f))}: {n}" for f, n in sorted(resumen_fuente.items())
    ) or "(sin datos)"
    resumen_severidad_html = ", ".join(
        f"{escape(g)}: {n}" for g, n in sorted(resumen_severidad.items())
    ) or "(sin hallazgos de vulnerabilidad)"
    resumen_revision_html = ", ".join(
        f"{escape(e)}: {n}" for e, n in sorted(resumen_revision.items())
    ) or "(ninguno con flujo de revision)"

    cuerpo_tabla = f"""
<h2>Resumen ejecutivo</h2>
<ul>
<li>Total de registros: {len(datos.resultados)}</li>
<li>Por herramienta: {resumen_fuente_html}</li>
<li>Hallazgos de vulnerabilidad por severidad: {resumen_severidad_html}</li>
<li>Hallazgos por estado de revision (Nuclei/ZAP): {resumen_revision_html}</li>
</ul>

<h2>Objetivos y alcance</h2>
<p>Herramientas utilizadas en esta auditoria: {herramientas_html}.</p>
<p>Alcance autorizado del proyecto:</p>
<ul>{alcance_html}</ul>
<p>Objetivos con resultados guardados:</p>
<ul>{objetivos_html}</ul>

<h2>Resultados de red y reconocimiento (TCP, Nmap)</h2>
<p class="resumen">Informacion de conectividad/puertos. No son vulnerabilidades y nunca
llevan una severidad asignada.</p>
<table>
<thead><tr><th>Herramienta</th><th>Objetivo</th><th>Hallazgo</th><th>Estado</th>
<th>Detalle</th><th>Fecha</th></tr></thead>
<tbody>
{filas_red}
</tbody>
</table>

<h2>Hallazgos de vulnerabilidad (auditoria web, Nuclei, OWASP ZAP)</h2>
<p class="resumen">Ordenados por severidad (de alta a informativa). La columna "Revision"
distingue hallazgos nuevos, confirmados y falsos positivos cuando la herramienta ofrece
ese flujo (Nuclei, ZAP); 'N/A' indica que la herramienta de origen no lo tiene.</p>
<table>
<thead><tr><th>Herramienta</th><th>Objetivo</th><th>Tipo</th><th>Hallazgo</th>
<th>Severidad</th><th>Revision</th><th>Descripcion</th><th>Evidencia</th>
<th>Recomendacion</th><th>Fecha</th></tr></thead>
<tbody>
{filas_vuln}
</tbody>
</table>

<h2>Limitaciones tecnicas</h2>
<ul>
<li>Este informe refleja unicamente lo detectado en el momento de cada analisis: no
implica monitoreo continuo ni garantiza que no existan otras debilidades.</li>
<li>Ningun modulo de AST realiza explotacion activa: Nmap limita su deteccion a puertos
y servicios, la auditoria web es pasiva (cabeceras/TLS/cookies), Nuclei solo ejecuta
plantillas aprobadas de bajo impacto, y OWASP ZAP se usa unicamente en modo pasivo.</li>
<li>AST no agrupa, fusiona ni deduplica hallazgos entre herramientas distintas aunque
compartan titulo: cada fila de este informe corresponde a un unico registro de una unica
herramienta (ver 'fuente' e 'id_origen' en la version JSON de este mismo informe).</li>
<li>La evidencia y los campos de texto libre se redactan automaticamente para ocultar
posibles secretos (tokens, contrasenas, cabeceras de autenticacion); esa redaccion puede
ocultar informacion relevante ademas de la sensible, por diseno.</li>
</ul>
"""
    resumen = (
        f"Proyecto: <strong>{escape(datos.proyecto)}</strong> &middot; "
        f"Generado: {escape(datos.generado_en)} &middot; "
        f"Total de registros: {len(datos.resultados)}"
    )
    return _pagina_html(f"Informe global AST - {datos.proyecto}", resumen, cuerpo_tabla)


# ---------------------------------------------------------------------------
# Informe OSINT (ver docs/OSINT.md) -- investigacion de fuentes publicas,
# deliberadamente separado del informe global de hallazgos tecnicos (nunca se
# mezclan ambos conjuntos de datos).
# ---------------------------------------------------------------------------

_RECOMENDACIONES_POR_CATEGORIA = {
    "correo": (
        "Revisa y refuerza la configuracion SPF/DMARC del dominio para reducir el "
        "riesgo de suplantacion de correo."
    ),
    "exposicion": (
        "Si el correo aparece en una brecha conocida, cambia la contrasena asociada "
        "y activa verificacion en dos pasos donde sea posible."
    ),
    "certificados": (
        "Revisa los subdominios observados: si alguno expone un servicio que no "
        "deberia ser publico, retiralo o restringe su acceso."
    ),
    "perfil_publico": (
        "Revisa la configuracion de privacidad de los perfiles publicos encontrados "
        "si no reconoces alguna cuenta como propia."
    ),
    "infraestructura": (
        "Verifica que la infraestructura/ASN reportada corresponda a un proveedor "
        "que reconoces."
    ),
    "historial_escaneos": (
        "Revisa los escaneos historicos: si alguno corresponde a una version antigua "
        "o a contenido que ya no deberia ser publico, considera solicitar su retiro."
    ),
}


@dataclass(frozen=True, slots=True)
class DatosInformeOSINT:
    """Datos de entrada del informe de una investigacion OSINT (ver modules/osint/)."""

    proyecto: str
    generado_en: str
    investigacion_id: int
    tipo_objetivo: str
    objetivo_mostrado: str
    autorizado_datos_personales: bool
    estado_general: str
    fuentes_utilizadas: tuple[str, ...]
    limitaciones: tuple[str, ...]
    hallazgos: list[HallazgoOSINTGuardado]
    resumen_exposicion: ResumenExposicion
    recomendaciones: tuple[str, ...]


def _minimizar_texto(texto: str | None, objetivo_real: str, objetivo_minimizado: str) -> str | None:
    if texto is None:
        return None
    return texto.replace(objetivo_real, objetivo_minimizado)


def _minimizar_hallazgo(
    hallazgo: HallazgoOSINTGuardado, objetivo_real: str, objetivo_minimizado: str
) -> HallazgoOSINTGuardado:
    """Sustituye el objetivo real por su version minimizada en TODO el texto del
    hallazgo -- no solo el campo 'objetivo' superior del informe. Un hallazgo de
    perfiles publicos, por ejemplo, repite el nombre de usuario/correo investigado en
    su titulo, descripcion y evidencia (URL del perfil, valor de la evidencia...): si
    solo se minimizara el campo superior, ``--minimizar`` no minimizaria nada en la
    practica (ver revision de seguridad de esta PR)."""
    evidencias = json.loads(hallazgo.evidencias_json)
    evidencias_minimizadas = [
        {
            **e,
            "valor": _minimizar_texto(e.get("valor"), objetivo_real, objetivo_minimizado),
            "referencia": _minimizar_texto(e.get("referencia"), objetivo_real, objetivo_minimizado),
        }
        for e in evidencias
    ]
    return replace(
        hallazgo,
        titulo=(
            _minimizar_texto(hallazgo.titulo, objetivo_real, objetivo_minimizado) or hallazgo.titulo
        ),
        descripcion=(
            _minimizar_texto(hallazgo.descripcion, objetivo_real, objetivo_minimizado)
            or hallazgo.descripcion
        ),
        indicador_exposicion=_minimizar_texto(
            hallazgo.indicador_exposicion, objetivo_real, objetivo_minimizado
        ),
        evidencias_json=json.dumps(evidencias_minimizadas, ensure_ascii=False),
    )


def construir_datos_informe_osint(
    proyecto: str,
    investigacion: InvestigacionOSINT,
    hallazgos: list[HallazgoOSINTGuardado],
    *,
    minimizar: bool = False,
) -> DatosInformeOSINT:
    """Construye los datos del informe de una investigacion ya guardada.

    ``minimizar=True`` enmascara el objetivo (correo/telefono/usuario; un dominio
    nunca se minimiza, ver ``core/osint/redaccion.py``) para una exportacion pensada
    para un publico mas amplio que el propio proyecto; por defecto se muestra completo,
    porque es la propia investigacion autorizada del usuario. La sustitucion se aplica
    en TODO el texto de cada hallazgo (titulo, descripcion, indicador de exposicion y
    evidencias), no solo en el campo 'objetivo' superior del informe.
    """
    etapas = json.loads(investigacion.etapas_json)
    fuentes_utilizadas = tuple(e["fuente"] for e in etapas if e["estado"] != "pendiente")
    limitaciones = tuple(json.loads(investigacion.limitaciones_json))

    if minimizar:
        objetivo_mostrado = minimizar_objetivo(
            investigacion.tipo_objetivo, investigacion.objetivo_saneado
        )
        hallazgos = [
            _minimizar_hallazgo(h, investigacion.objetivo_saneado, objetivo_mostrado)
            for h in hallazgos
        ]
    else:
        objetivo_mostrado = investigacion.objetivo_saneado

    categorias_presentes = {h.categoria for h in hallazgos}
    recomendaciones = tuple(
        sorted(
            mensaje
            for categoria, mensaje in _RECOMENDACIONES_POR_CATEGORIA.items()
            if categoria in categorias_presentes
        )
    )

    return DatosInformeOSINT(
        proyecto=proyecto,
        generado_en=datetime.now(UTC).isoformat(),
        investigacion_id=investigacion.id,
        tipo_objetivo=investigacion.tipo_objetivo,
        objetivo_mostrado=objetivo_mostrado,
        autorizado_datos_personales=investigacion.autorizado_datos_personales,
        estado_general=investigacion.estado_general,
        fuentes_utilizadas=fuentes_utilizadas,
        limitaciones=limitaciones,
        hallazgos=hallazgos,
        resumen_exposicion=construir_resumen_exposicion(hallazgos),
        recomendaciones=recomendaciones,
    )


def generar_json_osint(datos: DatosInformeOSINT) -> str:
    cuerpo = {
        "proyecto": datos.proyecto,
        "generado_en": datos.generado_en,
        "investigacion_id": datos.investigacion_id,
        "tipo_objetivo": datos.tipo_objetivo,
        "objetivo": datos.objetivo_mostrado,
        "autorizacion_datos_personales": datos.autorizado_datos_personales,
        "estado_general": datos.estado_general,
        "fuentes_utilizadas": list(datos.fuentes_utilizadas),
        "limitaciones": list(datos.limitaciones),
        "resumen_exposicion": {
            "total_hallazgos": datos.resumen_exposicion.total_hallazgos,
            "total_indicadores": datos.resumen_exposicion.total_indicadores,
            "fuentes_con_indicador": list(datos.resumen_exposicion.fuentes_con_indicador),
            "indicadores": list(datos.resumen_exposicion.indicadores),
        },
        "recomendaciones": list(datos.recomendaciones),
        "hallazgos": [
            {
                "fuente": h.fuente,
                "categoria": h.categoria,
                "titulo": h.titulo,
                "descripcion": h.descripcion,
                "nivel_confianza": h.nivel_confianza,
                "indicador_exposicion": h.indicador_exposicion,
                "evidencias": json.loads(h.evidencias_json),
                "creado_en": h.creado_en,
            }
            for h in datos.hallazgos
        ],
        "nota_metodologica": (
            "Cada hallazgo indica su nivel de confianza (confirmado/probable/"
            "no_verificado): una coincidencia de nombre de usuario o un nombre "
            "observado en Certificate Transparency nunca se trata como una identidad "
            "o un servicio activo confirmado. Este informe refleja unicamente lo que "
            "las fuentes consultadas devolvieron en el momento de la investigacion."
        ),
    }
    return json.dumps(cuerpo, ensure_ascii=False, indent=2)


def generar_html_osint(datos: DatosInformeOSINT) -> str:
    filas = "\n".join(
        f"<tr><td>{escape(h.fuente)}</td><td>{escape(h.categoria)}</td>"
        f"<td>{escape(h.titulo)}</td>"
        f"<td class=\"severidad-{escape(h.nivel_confianza)}\">{escape(h.nivel_confianza)}</td>"
        f"<td>{escape(h.indicador_exposicion or '-')}</td>"
        f"<td>{escape(h.descripcion)}</td><td>{escape(h.creado_en)}</td></tr>"
        for h in datos.hallazgos
    )
    if not filas:
        filas = "<tr><td colspan=\"7\">No hay hallazgos OSINT registrados.</td></tr>"

    fuentes_html = ", ".join(escape(f) for f in datos.fuentes_utilizadas) or "(ninguna)"
    limitaciones_html = (
        "".join(f"<li>{escape(limite)}</li>" for limite in datos.limitaciones)
        or "<li>(ninguna)</li>"
    )
    indicadores_html = (
        "".join(f"<li>{escape(ind)}</li>" for ind in datos.resumen_exposicion.indicadores)
        or "<li>Sin indicadores de exposicion.</li>"
    )
    recomendaciones_html = (
        "".join(f"<li>{escape(r)}</li>" for r in datos.recomendaciones)
        or "<li>Sin recomendaciones especificas: revisa igualmente las limitaciones.</li>"
    )
    autorizacion_html = (
        "Confirmada por el usuario antes de consultar cualquier fuente."
        if datos.autorizado_datos_personales
        else "No aplica (objetivo tratado como informacion corporativa, no personal)."
    )

    cuerpo_tabla = f"""
<h2>Resumen ejecutivo</h2>
<ul>
<li>Tipo de investigacion: {escape(datos.tipo_objetivo)}</li>
<li>Objetivo: {escape(datos.objetivo_mostrado)}</li>
<li>Estado de autorizacion sobre datos personales: {autorizacion_html}</li>
<li>Estado general: {escape(datos.estado_general)}</li>
<li>Fuentes utilizadas: {fuentes_html}</li>
<li>Total de hallazgos: {datos.resumen_exposicion.total_hallazgos}</li>
<li>Indicadores de exposicion: {datos.resumen_exposicion.total_indicadores}</li>
</ul>

<h2>Indicadores de exposicion</h2>
<ul>{indicadores_html}</ul>

<h2>Hallazgos verificados</h2>
<table>
<thead><tr><th>Fuente</th><th>Categoria</th><th>Titulo</th><th>Confianza</th>
<th>Indicador de exposicion</th><th>Descripcion</th><th>Fecha</th></tr></thead>
<tbody>
{filas}
</tbody>
</table>

<h2>Recomendaciones</h2>
<ul>{recomendaciones_html}</ul>

<h2>Limitaciones</h2>
<ul>{limitaciones_html}</ul>

<h2>Nota metodologica</h2>
<p class="resumen">Cada hallazgo indica su nivel de confianza (confirmado/probable/
no_verificado): una coincidencia de nombre de usuario o un nombre observado en
Certificate Transparency nunca se trata como una identidad o un servicio activo
confirmado. Este informe refleja unicamente lo que las fuentes consultadas
devolvieron en el momento de la investigacion; AST no promete cobertura total de
Internet ni de las filtraciones existentes.</p>
"""
    resumen = (
        f"Proyecto: <strong>{escape(datos.proyecto)}</strong> &middot; "
        f"Generado: {escape(datos.generado_en)} &middot; "
        f"Investigacion #{datos.investigacion_id} ({escape(datos.tipo_objetivo)})"
    )
    return _pagina_html(f"Informe OSINT AST - {datos.proyecto}", resumen, cuerpo_tabla)
