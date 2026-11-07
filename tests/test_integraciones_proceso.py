"""Pruebas de integrations/proceso.py: ejecucion real de un proceso externo.

Usa el propio interprete de Python (``sys.executable``) como "binario
externo" de prueba: esta siempre disponible, es multiplataforma y evita
depender de que alguna herramienta de pentesting este instalada.
"""

from __future__ import annotations

import sys
import threading
import time

from eurabyte_security.integrations.proceso import ejecutar_proceso


def test_ejecutar_proceso_captura_stdout_y_codigo_de_salida():
    resultado = ejecutar_proceso(
        [sys.executable, "-c", "print('hola')"], tiempo_limite=5.0
    )
    assert resultado.codigo_salida == 0
    assert resultado.stdout.strip() == "hola"
    assert not resultado.agotado_por_tiempo
    assert not resultado.cancelado


def test_ejecutar_proceso_captura_stderr_y_codigo_distinto_de_cero():
    resultado = ejecutar_proceso(
        [sys.executable, "-c", "import sys; sys.stderr.write('error'); sys.exit(2)"],
        tiempo_limite=5.0,
    )
    assert resultado.codigo_salida == 2
    assert "error" in resultado.stderr


def test_ejecutar_proceso_agota_el_tiempo():
    resultado = ejecutar_proceso(
        [sys.executable, "-c", "import time; time.sleep(5)"], tiempo_limite=0.3
    )
    assert resultado.agotado_por_tiempo
    assert not resultado.cancelado


def test_ejecutar_proceso_se_puede_cancelar_mientras_esta_en_curso():
    cancelar = threading.Event()

    def cancelar_pronto():
        time.sleep(0.2)
        cancelar.set()

    threading.Thread(target=cancelar_pronto).start()

    inicio = time.monotonic()
    resultado = ejecutar_proceso(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        tiempo_limite=10.0,
        debe_cancelar=cancelar.is_set,
    )
    duracion = time.monotonic() - inicio

    assert resultado.cancelado
    assert not resultado.agotado_por_tiempo
    # Se cancelo mucho antes del limite de tiempo (10s) y antes de que el
    # proceso simulado terminara por si mismo (tambien 10s).
    assert duracion < 5.0


def test_ejecutar_proceso_no_usa_shell_un_argumento_con_caracteres_de_shell_es_literal():
    # Si esto se ejecutara con shell=True, "; echo inyectado" se interpretaria
    # como un segundo comando. Al pasarlo como un unico argumento de lista,
    # Python se lo entrega tal cual al script, como texto literal.
    resultado = ejecutar_proceso(
        [
            sys.executable,
            "-c",
            "import sys; print(sys.argv[1])",
            "127.0.0.1; echo inyectado",
        ],
        tiempo_limite=5.0,
    )
    lineas = resultado.stdout.splitlines()
    # Una sola linea con el argumento completo e intacto: si se hubiera
    # interpretado con un shell, habria dos lineas (el eco real del shell
    # imprimiria "inyectado" por separado).
    assert lineas == ["127.0.0.1; echo inyectado"]
