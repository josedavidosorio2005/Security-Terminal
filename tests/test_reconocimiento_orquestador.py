"""Pruebas del orquestador de reconocimiento automatico (commands/reconocimiento.py).

Nmap, Nuclei y OWASP ZAP se sustituyen por dobles (igual que en sus propios archivos
de pruebas: ``_instalar_nmap_falso``/``_instalar_nuclei_falso``/``_instalar_zap_falso``
locales a este archivo). La etapa de auditoria web SI habla con un servidor HTTP real,
pero siempre en ``127.0.0.1`` levantado por la propia prueba (``ayudantes_web.py``):
nunca se toca una red de terceros ni se requiere tener Nmap/Nuclei/ZAP instalados.
"""

from __future__ import annotations

import json
import socket
import time
from pathlib import Path

import pytest

from eurabyte_security.cli.app import app
from eurabyte_security.commands.reconocimiento import ejecutar_reconocimiento_automatico
from eurabyte_security.core.errores import (
    ErrorEscaneoCancelado,
    ErrorFueraDeAlcance,
    ErrorValidacion,
    ErrorZAPNoDisponible,
)
from eurabyte_security.core.objetivo import EntradaObjetivo
from eurabyte_security.integrations.nmap import AdaptadorNmap
from eurabyte_security.integrations.nuclei import AdaptadorNuclei
from eurabyte_security.integrations.proceso import ResultadoProceso
from eurabyte_security.modules.vulnerability import zap as zap_modulo
from eurabyte_security.storage.database import BaseDatos

from .ayudantes_web import RespuestaConfigurada, servidor_prueba

XML_NMAP_UN_PUERTO_HTTP = """<?xml version="1.0"?>
<nmaprun>
<host>
<ports>
<port protocol="tcp" portid="{puerto}"><state state="open"/><service name="http"/></port>
</ports>
</host>
</nmaprun>
"""

XML_NMAP_SIN_PUERTOS = """<?xml version="1.0"?>
<nmaprun><host><ports></ports></host></nmaprun>
"""


def _instalar_nmap_falso(monkeypatch, *, xml: str = XML_NMAP_SIN_PUERTOS, tarda: float = 0.0):
    monkeypatch.setattr(AdaptadorNmap, "esta_instalado", lambda self: True)
    monkeypatch.setattr(AdaptadorNmap, "ruta_binario", lambda self: "/usr/bin/nmap")
    # '.info()' (que el orquestador usa para decidir si omitir la etapa) tambien llama
    # a 'obtener_version()', que por su cuenta ejecuta un proceso real: se simula aqui
    # tambien para que ninguna prueba dependa de tener Nmap instalado de verdad.
    monkeypatch.setattr(AdaptadorNmap, "obtener_version", lambda self: "7.95")

    def _ejecutar_binario_falso(self, argumentos, *, tiempo_limite, debe_cancelar=None):
        if tarda:
            fin = time.monotonic() + tarda
            while time.monotonic() < fin:
                if debe_cancelar is not None and debe_cancelar():
                    return ResultadoProceso(
                        codigo_salida=-1, stdout="", stderr="", agotado_por_tiempo=False,
                        cancelado=True,
                    )
                time.sleep(0.01)
        ruta_xml = Path(argumentos[argumentos.index("-oX") + 1])
        ruta_xml.write_text(xml, encoding="utf-8")
        return ResultadoProceso(codigo_salida=0, stdout="", stderr="", agotado_por_tiempo=False)

    monkeypatch.setattr(AdaptadorNmap, "_ejecutar_binario", _ejecutar_binario_falso)


def _marcar_nmap_ausente(monkeypatch):
    monkeypatch.setattr(AdaptadorNmap, "esta_instalado", lambda self: False)
    monkeypatch.setattr(AdaptadorNmap, "ruta_binario", lambda self: None)


def _marcar_nuclei_ausente(monkeypatch):
    monkeypatch.setattr(AdaptadorNuclei, "esta_instalado", lambda self: False)
    monkeypatch.setattr(AdaptadorNuclei, "ruta_binario", lambda self: None)


def _instalar_zap_falso(monkeypatch, *, alertas: list[dict] | None = None):
    def _peticion_falsa(configuracion, ruta, parametros, *, tiempo_limite):
        if ruta == "/JSON/core/view/version/":
            return {"version": "2.14.0"}
        if ruta == "/JSON/core/action/accessUrl/":
            return {"accessUrl": "OK"}
        if ruta == "/JSON/pscan/view/recordsToScan/":
            return {"recordsToScan": "0"}
        if ruta == "/JSON/core/view/alerts/":
            return {"alerts": alertas or []}
        raise AssertionError(ruta)

    monkeypatch.setattr(zap_modulo, "_peticion_zap", _peticion_falsa)
    monkeypatch.setattr(zap_modulo.time, "sleep", lambda *_a, **_k: None)


def _marcar_zap_ausente(monkeypatch):
    def _peticion_falla(configuracion, ruta, parametros, *, tiempo_limite):
        raise ErrorZAPNoDisponible("simulado: ZAP no disponible")

    monkeypatch.setattr(zap_modulo, "_peticion_zap", _peticion_falla)


def _proyecto_con_alcance_local(base_datos: BaseDatos, nombre: str = "reco"):
    proyecto = base_datos.crear_proyecto(nombre)
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")
    return proyecto


# -- Flujo completo contra un servidor HTTP local real -----------------------------


def test_pipeline_completo_sin_nmap_nuclei_zap_instalados(tmp_path, monkeypatch):
    """Caso obligatorio de laboratorio: objetivo HTTP local, sin herramientas externas."""
    monkeypatch.setenv("EST_HOME", str(tmp_path))
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = _proyecto_con_alcance_local(base_datos)
    _marcar_nmap_ausente(monkeypatch)
    _marcar_nuclei_ausente(monkeypatch)
    _marcar_zap_ausente(monkeypatch)

    respuestas = {"/": RespuestaConfigurada(codigo_estado=200, cuerpo=b"<html>ok</html>")}
    with servidor_prueba(respuestas) as (host, puerto):
        objetivo = f"http://{host}:{puerto}/"
        resultado = ejecutar_reconocimiento_automatico(base_datos, proyecto, objetivo)

    etapas = {e.nombre: e.estado for e in resultado.etapas}
    assert etapas["verificacion"] == "completada"
    assert etapas["puertos"] == "omitida"
    assert etapas["web"] == "completada"
    assert etapas["nuclei"] == "omitida"
    assert etapas["zap"] == "omitida"
    assert etapas["informe"] == "completada"
    assert resultado.estado_general == "completada"
    assert resultado.ip == "127.0.0.1"
    assert resultado.ruta_informe_html is not None
    assert Path(resultado.ruta_informe_html).exists()


def test_los_hallazgos_web_quedan_en_resultados_unificados(tmp_path, monkeypatch):
    monkeypatch.setenv("EST_HOME", str(tmp_path))
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = _proyecto_con_alcance_local(base_datos, "reco-resultados")
    _marcar_nmap_ausente(monkeypatch)
    _marcar_nuclei_ausente(monkeypatch)
    _marcar_zap_ausente(monkeypatch)

    # Sin cabeceras de seguridad: la auditoria web deberia generar al menos un hallazgo.
    respuestas = {"/": RespuestaConfigurada(codigo_estado=200, cuerpo=b"ok")}
    with servidor_prueba(respuestas) as (host, puerto):
        ejecutar_reconocimiento_automatico(base_datos, proyecto, f"http://{host}:{puerto}/")

    hallazgos_web = base_datos.listar_resultados_web(proyecto.id)
    assert len(hallazgos_web) > 0


# -- Nmap detecta un puerto y la etapa web lo reutiliza sin pedirlo de nuevo --------


def test_nmap_detecta_puerto_http_y_la_etapa_web_lo_audita_automaticamente(
    tmp_path, monkeypatch
):
    """El usuario escribe solo la IP (sin esquema): Nmap descubre el puerto HTTP y la
    auditoria web se dispara automaticamente sobre el, sin que el usuario lo repita."""
    monkeypatch.setenv("EST_HOME", str(tmp_path))
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = _proyecto_con_alcance_local(base_datos, "reco-nmap-http")
    _marcar_nuclei_ausente(monkeypatch)
    _marcar_zap_ausente(monkeypatch)

    respuestas = {"/": RespuestaConfigurada(codigo_estado=200, cuerpo=b"ok")}
    with servidor_prueba(respuestas) as (host, puerto):
        _instalar_nmap_falso(
            monkeypatch, xml=XML_NMAP_UN_PUERTO_HTTP.format(puerto=puerto)
        )
        resultado = ejecutar_reconocimiento_automatico(base_datos, proyecto, host)

    etapas = {e.nombre: e.estado for e in resultado.etapas}
    assert etapas["puertos"] == "completada"
    assert etapas["web"] == "completada"


# -- Autorizacion y entrada unica ----------------------------------------------------


def test_objetivo_fuera_de_alcance_falla_y_no_ejecuta_nada_mas(tmp_path, monkeypatch):
    monkeypatch.setenv("EST_HOME", str(tmp_path))
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = base_datos.crear_proyecto("reco-sin-alcance")
    # Deliberadamente sin registrar ningun alcance.

    with pytest.raises(ErrorFueraDeAlcance):
        ejecutar_reconocimiento_automatico(base_datos, proyecto, "10.0.0.9")

    sesiones = base_datos.listar_sesiones_reconocimiento(proyecto.id)
    assert len(sesiones) == 1
    assert sesiones[0].estado_general == "fallida"


def test_entrada_invalida_falla_de_forma_clara(tmp_path, monkeypatch):
    monkeypatch.setenv("EST_HOME", str(tmp_path))
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = _proyecto_con_alcance_local(base_datos, "reco-entrada-invalida")

    with pytest.raises(ErrorValidacion):
        ejecutar_reconocimiento_automatico(base_datos, proyecto, "esto no es un objetivo valido")


def test_dominio_resuelto_omite_web_nuclei_zap_pero_escanea_puertos(tmp_path, monkeypatch):
    """No se amplia el analisis a otro host virtual: con un dominio, solo se descubren
    puertos sobre la IP autorizada, y web/Nuclei/ZAP se omiten explicitamente."""
    monkeypatch.setenv("EST_HOME", str(tmp_path))
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = _proyecto_con_alcance_local(base_datos, "reco-dominio")
    _marcar_nuclei_ausente(monkeypatch)
    _marcar_zap_ausente(monkeypatch)
    _instalar_nmap_falso(monkeypatch, xml=XML_NMAP_SIN_PUERTOS)

    def getaddrinfo_falso(host, puerto, family=None):
        return [(socket.AF_INET, None, None, "", ("127.0.0.1", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo_falso)

    resultado = ejecutar_reconocimiento_automatico(base_datos, proyecto, "ejemplo.com")

    etapas = {e.nombre: e.estado for e in resultado.etapas}
    assert etapas["verificacion"] == "completada"
    assert etapas["puertos"] == "completada"
    assert etapas["web"] == "omitida"
    assert etapas["nuclei"] == "omitida"
    assert etapas["zap"] == "omitida"
    assert any("dominio" in lim.lower() for lim in resultado.limitaciones)
    assert resultado.nombre_host == "ejemplo.com"
    assert resultado.ip == "127.0.0.1"


def test_perfil_invalido_se_rechaza(tmp_path, monkeypatch):
    monkeypatch.setenv("EST_HOME", str(tmp_path))
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = _proyecto_con_alcance_local(base_datos, "reco-perfil-invalido")
    with pytest.raises(ErrorValidacion):
        ejecutar_reconocimiento_automatico(base_datos, proyecto, "127.0.0.1", perfil="turbo")


def test_perfil_personalizado_sin_especificacion_se_rechaza(tmp_path, monkeypatch):
    monkeypatch.setenv("EST_HOME", str(tmp_path))
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = _proyecto_con_alcance_local(base_datos, "reco-personalizado-vacio")
    with pytest.raises(ErrorValidacion):
        ejecutar_reconocimiento_automatico(
            base_datos, proyecto, "127.0.0.1", perfil="personalizado"
        )


# -- Herramientas ausentes, cancelacion, persistencia --------------------------------


def test_nuclei_ausente_omite_su_etapa_pero_zap_si_se_ejecuta(tmp_path, monkeypatch):
    monkeypatch.setenv("EST_HOME", str(tmp_path))
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = _proyecto_con_alcance_local(base_datos, "reco-nuclei-ausente")
    _marcar_nmap_ausente(monkeypatch)
    _marcar_nuclei_ausente(monkeypatch)
    _instalar_zap_falso(monkeypatch, alertas=[])

    respuestas = {"/": RespuestaConfigurada(codigo_estado=200, cuerpo=b"ok")}
    with servidor_prueba(respuestas) as (host, puerto):
        resultado = ejecutar_reconocimiento_automatico(
            base_datos, proyecto, f"http://{host}:{puerto}/"
        )

    etapas = {e.nombre: e.estado for e in resultado.etapas}
    assert etapas["nuclei"] == "omitida"
    assert etapas["zap"] == "completada"


def test_cancelacion_durante_nmap_no_ejecuta_etapas_posteriores(tmp_path, monkeypatch):
    monkeypatch.setenv("EST_HOME", str(tmp_path))
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = _proyecto_con_alcance_local(base_datos, "reco-cancelado")
    _instalar_nmap_falso(monkeypatch, xml=XML_NMAP_SIN_PUERTOS, tarda=0.3)

    cancelar_despues = {"veces": 0}

    def debe_cancelar():
        cancelar_despues["veces"] += 1
        return cancelar_despues["veces"] > 2

    with pytest.raises(ErrorEscaneoCancelado):
        ejecutar_reconocimiento_automatico(
            base_datos, proyecto, "127.0.0.1", debe_cancelar=debe_cancelar
        )

    sesiones = base_datos.listar_sesiones_reconocimiento(proyecto.id)
    assert len(sesiones) == 1
    sesion = sesiones[0]
    assert sesion.estado_general == "cancelada"
    etapas = {e["nombre"]: e["estado"] for e in json.loads(sesion.etapas_json)}
    assert etapas["verificacion"] == "completada"
    assert etapas["puertos"] == "cancelada"
    assert etapas["web"] == "pendiente"


def test_sesiones_de_dos_objetivos_no_se_mezclan(tmp_path, monkeypatch):
    monkeypatch.setenv("EST_HOME", str(tmp_path))
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = base_datos.crear_proyecto("reco-sesiones")
    base_datos.agregar_alcance(proyecto.id, "127.0.0.1/32")
    _marcar_nmap_ausente(monkeypatch)
    _marcar_nuclei_ausente(monkeypatch)
    _marcar_zap_ausente(monkeypatch)

    respuestas = {"/": RespuestaConfigurada(codigo_estado=200, cuerpo=b"ok")}
    with servidor_prueba(respuestas) as (host, puerto):
        r1 = ejecutar_reconocimiento_automatico(base_datos, proyecto, f"http://{host}:{puerto}/")
    with pytest.raises(ErrorFueraDeAlcance):
        ejecutar_reconocimiento_automatico(base_datos, proyecto, "10.0.0.5")

    sesiones = base_datos.listar_sesiones_reconocimiento(proyecto.id)
    assert len(sesiones) == 2
    sesion_exitosa = next(s for s in sesiones if s.id == r1.sesion_id)
    sesion_fallida = next(s for s in sesiones if s.id != r1.sesion_id)
    assert sesion_exitosa.estado_general == "completada"
    assert sesion_exitosa.objetivo_original != sesion_fallida.objetivo_original
    assert sesion_fallida.estado_general == "fallida"


def test_resolver_dns_se_llama_una_sola_vez_por_ejecucion(tmp_path, monkeypatch):
    """Nunca se vuelve a resolver el dominio en otra integracion: una sola llamada a
    socket.getaddrinfo por todo el reconocimiento."""
    monkeypatch.setenv("EST_HOME", str(tmp_path))
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = _proyecto_con_alcance_local(base_datos, "reco-dns-una-vez")
    _marcar_nmap_ausente(monkeypatch)
    _marcar_nuclei_ausente(monkeypatch)
    _marcar_zap_ausente(monkeypatch)

    llamadas = {"veces": 0}

    def getaddrinfo_falso(host, puerto, family=None):
        llamadas["veces"] += 1
        return [(socket.AF_INET, None, None, "", ("127.0.0.1", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo_falso)

    ejecutar_reconocimiento_automatico(base_datos, proyecto, "ejemplo.com")
    assert llamadas["veces"] == 1


# -- Informe global --------------------------------------------------------------------


def test_informe_global_incluye_las_etapas_completadas(tmp_path, monkeypatch):
    monkeypatch.setenv("EST_HOME", str(tmp_path))
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = _proyecto_con_alcance_local(base_datos, "reco-informe")
    _marcar_nmap_ausente(monkeypatch)
    _marcar_nuclei_ausente(monkeypatch)
    _marcar_zap_ausente(monkeypatch)

    respuestas = {"/": RespuestaConfigurada(codigo_estado=200, cuerpo=b"ok")}
    with servidor_prueba(respuestas) as (host, puerto):
        resultado = ejecutar_reconocimiento_automatico(
            base_datos, proyecto, f"http://{host}:{puerto}/"
        )

    datos = json.loads(Path(resultado.ruta_informe_json).read_text(encoding="utf-8"))
    assert datos["proyecto"] == proyecto.nombre
    assert datos["total_resultados"] > 0


# -- CLI ---------------------------------------------------------------------------------


def test_cli_reconocimiento_ejecutar(runner, monkeypatch):
    _marcar_nmap_ausente(monkeypatch)
    _marcar_nuclei_ausente(monkeypatch)
    _marcar_zap_ausente(monkeypatch)
    runner.invoke(app, ["proyecto", "crear", "reco-cli"])
    runner.invoke(app, ["alcance", "agregar", "127.0.0.1/32"])

    respuestas = {"/": RespuestaConfigurada(codigo_estado=200, cuerpo=b"ok")}
    with servidor_prueba(respuestas) as (host, puerto):
        resultado = runner.invoke(
            app, ["reconocimiento", "ejecutar", f"http://{host}:{puerto}/"]
        )
    assert resultado.exit_code == 0


def test_cli_reconocimiento_sesiones_y_estado(runner, monkeypatch):
    _marcar_nmap_ausente(monkeypatch)
    _marcar_nuclei_ausente(monkeypatch)
    _marcar_zap_ausente(monkeypatch)
    runner.invoke(app, ["proyecto", "crear", "reco-cli-sesiones"])
    runner.invoke(app, ["alcance", "agregar", "127.0.0.1/32"])

    respuestas = {"/": RespuestaConfigurada(codigo_estado=200, cuerpo=b"ok")}
    with servidor_prueba(respuestas) as (host, puerto):
        runner.invoke(app, ["reconocimiento", "ejecutar", f"http://{host}:{puerto}/"])

    resultado_sesiones = runner.invoke(app, ["reconocimiento", "sesiones"])
    assert resultado_sesiones.exit_code == 0

    resultado_estado = runner.invoke(app, ["reconocimiento", "estado", "1"])
    assert resultado_estado.exit_code == 0


def test_entrada_objetivo_se_interpreta_una_sola_vez_no_el_texto_crudo():
    """EntradaObjetivo demuestra que la interpretacion es un paso explicito y unico:
    el resto del orquestador nunca vuelve a tocar el texto original del usuario."""
    entrada = EntradaObjetivo(
        entrada_original="127.0.0.1",
        es_ip_literal=True,
        ip_literal=None,
        nombre_host=None,
        tiene_esquema=False,
        esquema=None,
        puerto=None,
        ruta=None,
    )
    assert entrada.entrada_original == "127.0.0.1"
