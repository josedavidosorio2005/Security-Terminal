"""Pruebas del adaptador Nmap y del comando asociado.

Ninguna de estas pruebas ejecuta Nmap de verdad: se sustituye
``AdaptadorNmap._ejecutar_binario`` (el unico punto de la clase que invoca un
proceso externo) por un doble que simula su comportamiento escribiendo un XML
de ejemplo, exactamente como lo haria el binario real con ``-oX``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from eurabyte_security.commands.nmap import _tabla_resultado_nmap, ejecutar_nmap
from eurabyte_security.commands.proyecto import crear_proyecto
from eurabyte_security.core.errores import (
    ErrorEscaneoCancelado,
    ErrorFueraDeAlcance,
    ErrorHerramientaNoDisponible,
    ErrorIntegracion,
    ErrorParametrosIntegracion,
    ErrorValidacion,
)
from eurabyte_security.integrations.nmap import AdaptadorNmap
from eurabyte_security.integrations.proceso import ResultadoProceso
from eurabyte_security.storage.database import BaseDatos

XML_EJEMPLO = """<?xml version="1.0"?>
<nmaprun>
<host>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
<port protocol="tcp" portid="80"><state state="closed"/></port>
<port protocol="tcp" portid="443">
  <state state="open"/>
  <service name="https" product="nginx" version="1.18"/>
</port>
</ports>
</host>
</nmaprun>
"""


def _instalar_nmap_falso(monkeypatch, salida_xml: str | None = XML_EJEMPLO) -> None:
    """Simula que Nmap esta instalado y que, al ejecutarse, escribe ``salida_xml``."""
    monkeypatch.setattr(AdaptadorNmap, "esta_instalado", lambda self: True)
    monkeypatch.setattr(AdaptadorNmap, "ruta_binario", lambda self: "/usr/bin/nmap")

    def _ejecutar_binario_falso(self, argumentos, *, tiempo_limite, debe_cancelar=None):
        ruta_xml = Path(argumentos[argumentos.index("-oX") + 1])
        if salida_xml is not None:
            ruta_xml.write_text(salida_xml, encoding="utf-8")
        return ResultadoProceso(codigo_salida=0, stdout="", stderr="", agotado_por_tiempo=False)

    monkeypatch.setattr(AdaptadorNmap, "_ejecutar_binario", _ejecutar_binario_falso)


# ---------------------------------------------------------------------------
# AdaptadorNmap: deteccion, validacion y ejecucion (con el proceso simulado).
# ---------------------------------------------------------------------------


def test_nmap_no_instalado_lanza_error_claro(monkeypatch):
    # ruta_binario() es la fuente de verdad real (esta_instalado() delega en
    # ella); se simula "no instalado" como lo haria shutil.which de verdad.
    monkeypatch.setattr(AdaptadorNmap, "ruta_binario", lambda self: None)
    with pytest.raises(ErrorHerramientaNoDisponible):
        AdaptadorNmap().ejecutar(objetivo="127.0.0.1", puertos_especificacion="80")


def test_nmap_rechaza_objetivo_invalido(monkeypatch):
    _instalar_nmap_falso(monkeypatch)
    with pytest.raises(ErrorValidacion):
        AdaptadorNmap().ejecutar(objetivo="example.com", puertos_especificacion="80")


def test_nmap_rechaza_tiempo_limite_fuera_de_rango(monkeypatch):
    _instalar_nmap_falso(monkeypatch)
    with pytest.raises(ErrorParametrosIntegracion):
        AdaptadorNmap().ejecutar(
            objetivo="127.0.0.1", puertos_especificacion="80", tiempo_limite=0.5
        )


def test_nmap_analiza_el_xml_correctamente(monkeypatch):
    _instalar_nmap_falso(monkeypatch)
    resultado = AdaptadorNmap().ejecutar(objetivo="127.0.0.1", puertos_especificacion="22,80,443")

    assert resultado.objetivo == "127.0.0.1"
    assert [p.puerto for p in resultado.puertos] == [22, 80, 443]

    ssh, http, https = resultado.puertos
    assert ssh.estado == "open" and ssh.servicio == "ssh" and ssh.version is None
    assert http.estado == "closed" and http.servicio is None
    assert https.estado == "open" and https.servicio == "https" and https.version == "nginx 1.18"


def test_nmap_deteccion_version_agrega_sv(monkeypatch):
    _instalar_nmap_falso(monkeypatch)
    resultado = AdaptadorNmap().ejecutar(
        objetivo="127.0.0.1", puertos_especificacion="80", deteccion_version=True
    )
    assert "-sV" in resultado.comando_ejecutado


def test_nmap_sin_deteccion_version_no_agrega_sv(monkeypatch):
    _instalar_nmap_falso(monkeypatch)
    resultado = AdaptadorNmap().ejecutar(objetivo="127.0.0.1", puertos_especificacion="80")
    assert "-sV" not in resultado.comando_ejecutado


def test_nmap_usa_connect_scan_sin_privilegios(monkeypatch):
    _instalar_nmap_falso(monkeypatch)
    resultado = AdaptadorNmap().ejecutar(objetivo="127.0.0.1", puertos_especificacion="80")
    assert "-sT" in resultado.comando_ejecutado
    assert "-Pn" in resultado.comando_ejecutado


def test_nmap_tiempo_agotado_lanza_error_integracion(monkeypatch):
    _instalar_nmap_falso(monkeypatch)

    def _agotado(self, argumentos, *, tiempo_limite, debe_cancelar=None):
        return ResultadoProceso(codigo_salida=-1, stdout="", stderr="", agotado_por_tiempo=True)

    monkeypatch.setattr(AdaptadorNmap, "_ejecutar_binario", _agotado)
    with pytest.raises(ErrorIntegracion):
        AdaptadorNmap().ejecutar(objetivo="127.0.0.1", puertos_especificacion="80")


def test_nmap_cancelado_lanza_error_escaneo_cancelado(monkeypatch):
    _instalar_nmap_falso(monkeypatch)

    def _cancelado(self, argumentos, *, tiempo_limite, debe_cancelar=None):
        return ResultadoProceso(
            codigo_salida=-1, stdout="", stderr="", agotado_por_tiempo=False, cancelado=True
        )

    monkeypatch.setattr(AdaptadorNmap, "_ejecutar_binario", _cancelado)
    with pytest.raises(ErrorEscaneoCancelado):
        AdaptadorNmap().ejecutar(
            objetivo="127.0.0.1", puertos_especificacion="80", debe_cancelar=lambda: True
        )


def test_nmap_sin_xml_de_salida_lanza_error_integracion(monkeypatch):
    _instalar_nmap_falso(monkeypatch, salida_xml=None)
    with pytest.raises(ErrorIntegracion):
        AdaptadorNmap().ejecutar(objetivo="127.0.0.1", puertos_especificacion="80")


def test_nmap_xml_malformado_lanza_error_integracion(monkeypatch):
    _instalar_nmap_falso(monkeypatch, salida_xml="esto no es xml valido <<<")
    with pytest.raises(ErrorIntegracion):
        AdaptadorNmap().ejecutar(objetivo="127.0.0.1", puertos_especificacion="80")


def test_nmap_info_cuando_no_esta_instalado(monkeypatch):
    monkeypatch.setattr(AdaptadorNmap, "esta_instalado", lambda self: False)
    monkeypatch.setattr(AdaptadorNmap, "ruta_binario", lambda self: None)
    info = AdaptadorNmap().info()
    assert info.instalada is False
    assert info.version is None


# ---------------------------------------------------------------------------
# Correcciones de seguridad: escape de datos del objetivo escaneado y
# resolucion de la ruta absoluta del binario antes de ejecutarlo.
# ---------------------------------------------------------------------------


def test_servicio_con_marcado_rich_no_rompe_la_tabla_de_resultados(monkeypatch):
    """servicio/version/protocolo/estado vienen del objetivo escaneado: no son de fiar."""
    xml_malicioso = """<?xml version="1.0"?>
<nmaprun>
<host>
<ports>
<port protocol="tcp" portid="80">
  <state state="open"/>
  <service name="[/]" product="[bold red]x" version="1]"/>
</port>
</ports>
</host>
</nmaprun>
"""
    _instalar_nmap_falso(monkeypatch, salida_xml=xml_malicioso)
    resultado = AdaptadorNmap().ejecutar(objetivo="127.0.0.1", puertos_especificacion="80")

    # Ni construir la tabla ni imprimirla con un Console real debe lanzar
    # rich.errors.MarkupError (ver ui/consola.py:texto_seguro).
    from rich.console import Console

    tabla = _tabla_resultado_nmap(resultado)
    Console().print(tabla)


def test_ejecutar_binario_usa_la_ruta_absoluta_resuelta_no_el_nombre_pelado(monkeypatch):
    """Evita una segunda resolucion de PATH (y el riesgo de 'binary planting')."""
    capturado: dict[str, list[str]] = {}

    def ruta_falsa(self) -> str:
        return "/opt/herramientas/nmap"

    def ejecutar_proceso_falso(comando, *, tiempo_limite, entrada=None, debe_cancelar=None):
        capturado["comando"] = comando
        return ResultadoProceso(codigo_salida=0, stdout="", stderr="", agotado_por_tiempo=False)

    monkeypatch.setattr(AdaptadorNmap, "ruta_binario", ruta_falsa)
    monkeypatch.setattr(
        "eurabyte_security.integrations.base.ejecutar_proceso", ejecutar_proceso_falso
    )

    AdaptadorNmap()._ejecutar_binario(["-sT"], tiempo_limite=5.0)

    assert capturado["comando"][0] == "/opt/herramientas/nmap"
    assert capturado["comando"][0] != AdaptadorNmap.comando


def test_base_desactiva_la_busqueda_en_el_directorio_de_trabajo_en_windows():
    import os

    # Se define al importar integrations/base.py (ver ese modulo). No tiene
    # efecto fuera de Windows, pero debe estar presente igual.
    assert os.environ.get("NoDefaultCurrentDirectoryInExePath") is not None


# ---------------------------------------------------------------------------
# commands/nmap.py: verificacion de alcance, persistencia y evidencia.
# ---------------------------------------------------------------------------


def test_ejecutar_nmap_fuera_de_alcance_no_llega_a_ejecutar_nada(tmp_path):
    """Sin alcance registrado, se rechaza antes de siquiera comprobar si Nmap existe."""
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "nmap-rechazo")
    base_datos.agregar_alcance(proyecto.id, "10.0.0.0/24")

    with pytest.raises(ErrorFueraDeAlcance):
        ejecutar_nmap(base_datos, proyecto, "127.0.0.1", "80")

    assert base_datos.listar_resultados_nmap(proyecto.id) == []


def test_ejecutar_nmap_dentro_de_alcance_persiste_y_guarda_evidencia(tmp_path, monkeypatch):
    (tmp_path / "datos").mkdir()
    monkeypatch.setenv("EST_HOME", str(tmp_path / "datos"))
    _instalar_nmap_falso(monkeypatch)

    base_datos = BaseDatos(tmp_path / "datos" / "est.db")
    proyecto = crear_proyecto(base_datos, "nmap-ok")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")

    resultado, guardados, ruta_xml = ejecutar_nmap(base_datos, proyecto, "127.0.0.1", "22,80,443")

    assert len(guardados) == 3
    assert len(base_datos.listar_resultados_nmap(proyecto.id)) == 3
    assert ruta_xml is not None
    assert ruta_xml.exists()
    assert "nginx" in ruta_xml.read_text(encoding="utf-8")
    assert resultado.puertos[0].puerto == 22


def test_ejecutar_nmap_sin_guardar_evidencia(tmp_path, monkeypatch):
    (tmp_path / "datos").mkdir()
    monkeypatch.setenv("EST_HOME", str(tmp_path / "datos"))
    _instalar_nmap_falso(monkeypatch)

    base_datos = BaseDatos(tmp_path / "datos" / "est.db")
    proyecto = crear_proyecto(base_datos, "nmap-sin-evidencia")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")

    _resultado, _guardados, ruta_xml = ejecutar_nmap(
        base_datos, proyecto, "127.0.0.1", "80", guardar_evidencia=False
    )
    assert ruta_xml is None


# ---------------------------------------------------------------------------
# CLI: est nmap version / est nmap descubrir
# ---------------------------------------------------------------------------


def test_cli_nmap_version_no_instalado(runner, monkeypatch):
    from eurabyte_security.cli.app import app

    monkeypatch.setattr(AdaptadorNmap, "esta_instalado", lambda self: False)
    monkeypatch.setattr(AdaptadorNmap, "ruta_binario", lambda self: None)

    resultado = runner.invoke(app, ["nmap", "version"])
    assert resultado.exit_code == 0
    assert "no esta instalado" in resultado.stdout


def test_cli_nmap_descubrir_fuera_de_alcance_falla(runner):
    from eurabyte_security.cli.app import app

    runner.invoke(app, ["proyecto", "crear", "cli-nmap"])
    resultado = runner.invoke(app, ["nmap", "descubrir", "127.0.0.1", "--puertos", "80"])
    assert resultado.exit_code != 0


def test_cli_nmap_descubrir_dentro_de_alcance(runner, monkeypatch):
    from eurabyte_security.cli.app import app

    _instalar_nmap_falso(monkeypatch)
    runner.invoke(app, ["proyecto", "crear", "cli-nmap-ok"])
    runner.invoke(app, ["alcance", "agregar", "127.0.0.1/32"])

    resultado = runner.invoke(app, ["nmap", "descubrir", "127.0.0.1", "--puertos", "22,80,443"])
    assert resultado.exit_code == 0
    assert "22" in resultado.stdout
    assert "Evidencia XML guardada en" in resultado.stdout
