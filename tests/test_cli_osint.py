"""Pruebas de la CLI de OSINT (``est osint ...``).

El motor (``ejecutar_investigacion_osint``) se sustituye por un doble: estas pruebas
verifican el cableado de la CLI (parseo de argumentos, autorizacion, salida), no las
fuentes externas (ya cubiertas en ``test_osint_motor.py`` y
``test_osint_integraciones*.py``). Ninguna prueba toca una red de terceros.
"""

from __future__ import annotations

from eurabyte_security import commands
from eurabyte_security.cli.app import app
from eurabyte_security.modules.osint.modelos import EtapaFuenteOSINT, ResultadoInvestigacionOSINT


def _resultado_falso(investigacion_id=1, total_hallazgos=0, limitaciones=()):
    return ResultadoInvestigacionOSINT(
        investigacion_id=investigacion_id,
        tipo_objetivo="dominio",
        objetivo_original="ejemplo.com",
        objetivo_saneado="ejemplo.com",
        estado_general="completada",
        etapas=(EtapaFuenteOSINT("dns", "completada", "1 hallazgo(s)."),),
        limitaciones=tuple(limitaciones),
        total_hallazgos=total_hallazgos,
    )


def _preparar_proyecto(runner, nombre="laboratorio"):
    runner.invoke(app, ["proyecto", "crear", nombre])


def test_osint_dominio_ejecuta_y_muestra_resumen(runner, monkeypatch):
    _preparar_proyecto(runner)
    monkeypatch.setattr(
        commands.osint, "ejecutar_investigacion_osint", lambda *_a, **_k: _resultado_falso()
    )
    resultado = runner.invoke(app, ["osint", "dominio", "ejemplo.com"])
    assert resultado.exit_code == 0
    assert "Investigacion OSINT #1" in resultado.stdout


def test_osint_correo_sin_autorizar_falla(runner):
    _preparar_proyecto(runner)
    resultado = runner.invoke(app, ["osint", "correo", "usuario@ejemplo.com"])
    assert resultado.exit_code != 0


def test_osint_correo_autorizado_ejecuta(runner, monkeypatch):
    _preparar_proyecto(runner)
    recibido = {}

    def _fake(_base_datos, _proyecto, tipo, objetivo, **kwargs):
        recibido["tipo"] = tipo
        recibido["objetivo"] = objetivo
        recibido["autorizado"] = kwargs["autorizado_datos_personales"]
        return _resultado_falso()

    monkeypatch.setattr(commands.osint, "ejecutar_investigacion_osint", _fake)
    resultado = runner.invoke(
        app, ["osint", "correo", "usuario@ejemplo.com", "--autorizo"]
    )
    assert resultado.exit_code == 0
    assert recibido["tipo"] == "correo"
    assert recibido["autorizado"] is True


def test_osint_telefono_sin_autorizar_falla(runner):
    _preparar_proyecto(runner)
    resultado = runner.invoke(app, ["osint", "telefono", "+573001234567"])
    assert resultado.exit_code != 0


def test_osint_usuario_sin_autorizar_falla(runner):
    _preparar_proyecto(runner)
    resultado = runner.invoke(app, ["osint", "usuario", "alguien"])
    assert resultado.exit_code != 0


def test_osint_fuentes_lista_catalogo(runner):
    resultado = runner.invoke(app, ["osint", "fuentes"])
    assert resultado.exit_code == 0
    assert "dns" in resultado.stdout


def test_osint_fuentes_filtra_por_tipo(runner):
    resultado = runner.invoke(app, ["osint", "fuentes", "--tipo", "usuario"])
    assert resultado.exit_code == 0
    assert "perfiles_publicos" in resultado.stdout
    assert "certificados" not in resultado.stdout


def test_osint_investigaciones_y_resultados_vacios(runner):
    _preparar_proyecto(runner)
    resultado = runner.invoke(app, ["osint", "investigaciones"])
    assert resultado.exit_code == 0
    assert "no tiene investigaciones" in resultado.stdout

    resultado = runner.invoke(app, ["osint", "resultados"])
    assert resultado.exit_code == 0
    assert "No hay hallazgos" in resultado.stdout


def test_osint_eliminar_sin_confirmar_no_borra(runner):
    from eurabyte_security.commands._comun import obtener_base_datos, resolver_proyecto

    _preparar_proyecto(runner)
    base_datos = obtener_base_datos()
    proyecto = resolver_proyecto(base_datos, None)
    investigacion = base_datos.crear_investigacion_osint(
        proyecto.id, "dominio", "ejemplo.com", "ejemplo.com", False, []
    )

    resultado = runner.invoke(app, ["osint", "eliminar", str(investigacion.id)])
    assert resultado.exit_code != 0

    resultado = runner.invoke(app, ["osint", "investigaciones"])
    assert "no tiene investigaciones" not in resultado.stdout


def test_osint_eliminar_investigacion_inexistente_falla(runner):
    resultado = runner.invoke(app, ["osint", "eliminar", "999", "--confirmar"])
    assert resultado.exit_code != 0


def test_osint_dominio_muestra_indicadores_de_exposicion(runner, monkeypatch):
    from eurabyte_security.commands._comun import obtener_base_datos, resolver_proyecto

    _preparar_proyecto(runner)
    base_datos = obtener_base_datos()
    proyecto = resolver_proyecto(base_datos, None)
    investigacion = base_datos.crear_investigacion_osint(
        proyecto.id, "dominio", "ejemplo.com", "ejemplo.com", False, []
    )
    base_datos.agregar_hallazgos_osint(
        investigacion.id,
        proyecto.id,
        "dns",
        [
            {
                "categoria": "correo",
                "titulo": "SPF no configurado",
                "descripcion": "d",
                "nivel_confianza": "confirmado",
                "indicador_exposicion": "Sin SPF configurado",
                "evidencias": [],
            }
        ],
    )
    monkeypatch.setattr(
        commands.osint,
        "ejecutar_investigacion_osint",
        lambda *_a, **_k: _resultado_falso(investigacion_id=investigacion.id),
    )
    resultado = runner.invoke(app, ["osint", "dominio", "ejemplo.com"])
    assert resultado.exit_code == 0
    assert "Indicadores de exposicion: 1" in resultado.stdout
    assert "Sin SPF configurado" in resultado.stdout


def test_osint_purgar_sin_confirmar_no_borra(runner):
    resultado = runner.invoke(app, ["osint", "purgar"])
    assert resultado.exit_code != 0


def test_osint_purgar_dias_invalido_falla(runner):
    resultado = runner.invoke(app, ["osint", "purgar", "--dias", "0", "--confirmar"])
    assert resultado.exit_code != 0


def test_osint_purgar_con_confirmar_borra_antiguas(runner):
    from datetime import UTC, datetime, timedelta

    from eurabyte_security.commands._comun import obtener_base_datos, resolver_proyecto

    _preparar_proyecto(runner)
    base_datos = obtener_base_datos()
    proyecto = resolver_proyecto(base_datos, None)
    antigua = base_datos.crear_investigacion_osint(
        proyecto.id, "dominio", "vieja.com", "vieja.com", False, []
    )
    fecha = (datetime.now(UTC) - timedelta(days=100)).isoformat()
    with base_datos._conectar() as conexion:  # noqa: SLF001 - solo en pruebas
        conexion.execute(
            "UPDATE investigaciones_osint SET creado_en = ? WHERE id = ?", (fecha, antigua.id)
        )

    resultado = runner.invoke(app, ["osint", "purgar", "--dias", "90", "--confirmar"])
    assert resultado.exit_code == 0
    assert "1" in resultado.stdout

    resultado = runner.invoke(app, ["osint", "investigaciones"])
    assert "no tiene investigaciones" in resultado.stdout


def test_osint_reporte_html(runner, tmp_path):
    from eurabyte_security.commands._comun import obtener_base_datos, resolver_proyecto

    _preparar_proyecto(runner)
    base_datos = obtener_base_datos()
    proyecto = resolver_proyecto(base_datos, None)
    investigacion = base_datos.crear_investigacion_osint(
        proyecto.id, "dominio", "ejemplo.com", "ejemplo.com", False, []
    )

    ruta_salida = tmp_path / "informe.html"
    resultado = runner.invoke(
        app,
        [
            "osint",
            "reporte",
            str(investigacion.id),
            "--formato",
            "html",
            "--salida",
            str(ruta_salida),
        ],
    )
    assert resultado.exit_code == 0
    assert ruta_salida.exists()
    assert "Informe OSINT AST" in ruta_salida.read_text(encoding="utf-8")


def test_osint_reporte_json_minimizado(runner, tmp_path):
    from eurabyte_security.commands._comun import obtener_base_datos, resolver_proyecto

    _preparar_proyecto(runner)
    base_datos = obtener_base_datos()
    proyecto = resolver_proyecto(base_datos, None)
    investigacion = base_datos.crear_investigacion_osint(
        proyecto.id, "correo", "usuario@ejemplo.com", "usuario@ejemplo.com", True, []
    )

    ruta_salida = tmp_path / "informe.json"
    resultado = runner.invoke(
        app,
        [
            "osint",
            "reporte",
            str(investigacion.id),
            "--formato",
            "json",
            "--minimizar",
            "--salida",
            str(ruta_salida),
        ],
    )
    assert resultado.exit_code == 0
    contenido = ruta_salida.read_text(encoding="utf-8")
    assert "usuario@ejemplo.com" not in contenido


def test_osint_reporte_investigacion_inexistente_falla(runner):
    resultado = runner.invoke(app, ["osint", "reporte", "999"])
    assert resultado.exit_code != 0


def test_osint_reporte_formato_invalido_falla(runner):
    from eurabyte_security.commands._comun import obtener_base_datos, resolver_proyecto

    _preparar_proyecto(runner)
    base_datos = obtener_base_datos()
    proyecto = resolver_proyecto(base_datos, None)
    investigacion = base_datos.crear_investigacion_osint(
        proyecto.id, "dominio", "ejemplo.com", "ejemplo.com", False, []
    )
    resultado = runner.invoke(
        app, ["osint", "reporte", str(investigacion.id), "--formato", "pdf"]
    )
    assert resultado.exit_code != 0


def _hallazgo_con_evidencias(titulo: str, evidencias: list[dict]) -> dict:
    return {
        "categoria": "historial_escaneos",
        "titulo": titulo,
        "descripcion": "Descripcion completa de prueba.",
        "nivel_confianza": "probable",
        "indicador_exposicion": None,
        "evidencias": evidencias,
    }


def _investigacion_con_hallazgos(runner, evidencias_hallazgo_1, evidencias_hallazgo_2=None):
    from eurabyte_security.commands._comun import obtener_base_datos, resolver_proyecto

    _preparar_proyecto(runner)
    base_datos = obtener_base_datos()
    proyecto = resolver_proyecto(base_datos, None)
    investigacion = base_datos.crear_investigacion_osint(
        proyecto.id, "dominio", "ejemplo.com", "ejemplo.com", False, []
    )
    hallazgos = [_hallazgo_con_evidencias("Hallazgo 1", evidencias_hallazgo_1)]
    if evidencias_hallazgo_2 is not None:
        hallazgos.append(_hallazgo_con_evidencias("Hallazgo 2", evidencias_hallazgo_2))
    base_datos.agregar_hallazgos_osint(
        investigacion.id, proyecto.id, "urlscan_historial", hallazgos
    )
    return investigacion


def test_osint_resultados_detallado_muestra_descripcion_y_evidencias(runner, monkeypatch):
    # Un ancho de consola amplio evita que Rich trunque con '...' las URL largas al
    # renderizar la tabla de evidencias (en una terminal real, el usuario controla ese
    # ancho; aqui se fija para poder comprobar el contenido completo, no un resumen).
    monkeypatch.setenv("COLUMNS", "200")
    evidencias = [
        {
            "fuente": "urlscan_historial",
            "fecha_consulta": "2026-01-01T00:00:00+00:00",
            "referencia": "https://urlscan.io/result/abc/",
            "valor": "https://ejemplo.com/pagina",
            "fecha_observada": "2025-12-01T00:00:00+00:00",
        }
    ]
    investigacion = _investigacion_con_hallazgos(runner, evidencias)
    resultado = runner.invoke(
        app, ["osint", "resultados", "--investigacion", str(investigacion.id), "--detallado"]
    )
    assert resultado.exit_code == 0
    assert "Descripcion completa de prueba" in resultado.stdout
    assert "https://ejemplo.com/pagina" in resultado.stdout
    assert "https://urlscan.io/result/abc/" in resultado.stdout
    assert "Estado de verificacion" in resultado.stdout


def test_osint_resultados_solo_urls_deduplica(runner):
    evidencias = [
        {
            "fuente": "urlscan_historial",
            "fecha_consulta": "x",
            "referencia": "https://urlscan.io/result/abc/",
            "valor": "https://ejemplo.com/pagina",
            "fecha_observada": "2025-12-01",
        },
        {
            "fuente": "urlscan_historial",
            "fecha_consulta": "x",
            "referencia": "https://urlscan.io/result/abc/",
            "valor": "https://ejemplo.com/pagina",
            "fecha_observada": "2025-12-02",
        },
    ]
    investigacion = _investigacion_con_hallazgos(runner, evidencias)
    resultado = runner.invoke(
        app, ["osint", "resultados", "--investigacion", str(investigacion.id), "--solo-urls"]
    )
    assert resultado.exit_code == 0
    lineas = [linea for linea in resultado.stdout.splitlines() if linea.strip()]
    assert lineas.count("https://ejemplo.com/pagina") == 1
    assert lineas.count("https://urlscan.io/result/abc/") == 1


def test_osint_resultados_solo_urls_nunca_inventa_una_url_de_un_subdominio(runner):
    """Un 'valor' que no empieza por http(s):// (p. ej. un subdominio de Certificate
    Transparency, o un metadato de telefono) nunca debe listarse como si fuera una URL
    observada (seccion 2: "no convertir automaticamente un subdominio en una URL")."""
    evidencias = [
        {
            "fuente": "certificados",
            "fecha_consulta": "x",
            "referencia": "https://crt.sh/?id=1",
            "valor": "api.ejemplo.com",
            "fecha_observada": None,
        }
    ]
    investigacion = _investigacion_con_hallazgos(runner, evidencias)
    resultado = runner.invoke(
        app, ["osint", "resultados", "--investigacion", str(investigacion.id), "--solo-urls"]
    )
    assert resultado.exit_code == 0
    assert "api.ejemplo.com" not in resultado.stdout
    assert "https://crt.sh/?id=1" in resultado.stdout


def test_osint_resultados_guardar_json_conserva_evidencias(runner, tmp_path):
    evidencias = [
        {
            "fuente": "urlscan_historial",
            "fecha_consulta": "2026-01-01T00:00:00+00:00",
            "referencia": "https://urlscan.io/result/abc/",
            "valor": "https://ejemplo.com/pagina",
            "fecha_observada": "2025-12-01T00:00:00+00:00",
        }
    ]
    investigacion = _investigacion_con_hallazgos(runner, evidencias)
    ruta_salida = tmp_path / "detalle.json"
    resultado = runner.invoke(
        app,
        [
            "osint",
            "resultados",
            "--investigacion",
            str(investigacion.id),
            "--detallado",
            "--guardar",
            str(ruta_salida),
        ],
    )
    assert resultado.exit_code == 0
    assert ruta_salida.exists()
    import json

    datos = json.loads(ruta_salida.read_text(encoding="utf-8"))
    assert datos[0]["evidencias"][0]["valor"] == "https://ejemplo.com/pagina"
    assert datos[0]["evidencias"][0]["referencia"] == "https://urlscan.io/result/abc/"


def test_osint_resultados_guardar_urls_txt(runner, tmp_path):
    evidencias = [
        {
            "fuente": "urlscan_historial",
            "fecha_consulta": "x",
            "referencia": "https://urlscan.io/result/abc/",
            "valor": "https://ejemplo.com/pagina",
            "fecha_observada": None,
        }
    ]
    investigacion = _investigacion_con_hallazgos(runner, evidencias)
    ruta_salida = tmp_path / "urls.txt"
    resultado = runner.invoke(
        app,
        [
            "osint",
            "resultados",
            "--investigacion",
            str(investigacion.id),
            "--solo-urls",
            "--guardar",
            str(ruta_salida),
        ],
    )
    assert resultado.exit_code == 0
    contenido = ruta_salida.read_text(encoding="utf-8")
    assert "https://ejemplo.com/pagina" in contenido
    assert "https://urlscan.io/result/abc/" in contenido


def test_osint_resultados_pagina_divide_los_hallazgos(runner, monkeypatch):
    monkeypatch.setenv("COLUMNS", "200")
    evidencias_vacias: list[dict] = []
    investigacion = _investigacion_con_hallazgos(runner, evidencias_vacias, evidencias_vacias)
    resultado = runner.invoke(
        app,
        [
            "osint",
            "resultados",
            "--investigacion",
            str(investigacion.id),
            "--limite",
            "1",
            "--pagina",
            "2",
        ],
    )
    assert resultado.exit_code == 0
    assert "Hallazgo 1" in resultado.stdout or "Hallazgo 2" in resultado.stdout
    assert "pagina 2/2" in resultado.stdout.lower()


def test_osint_resultados_pagina_fuera_de_rango_avisa(runner):
    investigacion = _investigacion_con_hallazgos(runner, [])
    resultado = runner.invoke(
        app,
        [
            "osint",
            "resultados",
            "--investigacion",
            str(investigacion.id),
            "--pagina",
            "99",
        ],
    )
    assert resultado.exit_code == 0
    assert "Aviso" in resultado.stdout


def test_osint_resultados_pagina_invalida_falla(runner):
    resultado = runner.invoke(app, ["osint", "resultados", "--pagina", "0"])
    assert resultado.exit_code != 0


def test_osint_telefono_con_twilio_avisa_el_costo(runner, monkeypatch):
    _preparar_proyecto(runner)
    monkeypatch.setattr(
        commands.osint, "ejecutar_investigacion_osint", lambda *_a, **_k: _resultado_falso()
    )
    resultado = runner.invoke(
        app,
        [
            "osint",
            "telefono",
            "+573001234567",
            "--autorizo",
            "--fuentes",
            "twilio_lookup",
        ],
    )
    assert resultado.exit_code == 0
    assert "costo" in resultado.stdout.lower()


def test_osint_telefono_sin_twilio_no_avisa_el_costo(runner, monkeypatch):
    _preparar_proyecto(runner)
    monkeypatch.setattr(
        commands.osint, "ejecutar_investigacion_osint", lambda *_a, **_k: _resultado_falso()
    )
    resultado = runner.invoke(
        app, ["osint", "telefono", "+573001234567", "--autorizo"]
    )
    assert resultado.exit_code == 0
    assert "aviso de costo" not in resultado.stdout.lower()
