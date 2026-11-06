from __future__ import annotations

import socket

from eurabyte_security.modules.network.tcp_scanner import ABIERTO, CERRADO, escanear_puertos_tcp


def _puerto_libre() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_detecta_puerto_abierto():
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.bind(("127.0.0.1", 0))
    servidor.listen(1)
    puerto = servidor.getsockname()[1]
    try:
        resultados = escanear_puertos_tcp("127.0.0.1", [puerto], tiempo_espera=1.0)
        assert resultados == [resultados[0]]
        assert resultados[0].puerto == puerto
        assert resultados[0].estado == ABIERTO
    finally:
        servidor.close()


def test_detecta_puerto_cerrado():
    puerto = _puerto_libre()
    resultados = escanear_puertos_tcp("127.0.0.1", [puerto], tiempo_espera=0.5)
    assert resultados[0].estado == CERRADO


def test_resultados_ordenados_por_puerto():
    puerto_a = _puerto_libre()
    puerto_b = _puerto_libre()
    resultados = escanear_puertos_tcp(
        "127.0.0.1", [max(puerto_a, puerto_b), min(puerto_a, puerto_b)], tiempo_espera=0.5
    )
    assert [r.puerto for r in resultados] == sorted([puerto_a, puerto_b])
