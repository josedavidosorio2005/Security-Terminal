"""Paso 0 de la Fase 3: persistencia atomica y limites de concurrencia reales."""

from __future__ import annotations

import threading

import pytest

import eurabyte_security.storage.database as modulo_bd
from eurabyte_security.commands.proyecto import crear_proyecto
from eurabyte_security.modules.network import tcp_scanner
from eurabyte_security.modules.network.tcp_scanner import ResultadoPuerto, escanear_puertos_tcp
from eurabyte_security.storage.database import BaseDatos

# ---------------------------------------------------------------------------
# Persistencia atomica: una escritura que falla a mitad de camino no deja
# resultados parciales.
# ---------------------------------------------------------------------------


def test_agregar_resultados_es_atomico_todo_o_nada(tmp_path, monkeypatch):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "atomico")

    original_ahora = modulo_bd._ahora
    contador = {"n": 0}

    def ahora_que_falla_a_mitad_de_camino() -> str:
        contador["n"] += 1
        if contador["n"] > 2:  # ya se habrian insertado 2 de 5 filas sin el rollback
            raise RuntimeError("fallo simulado durante la escritura")
        return original_ahora()

    monkeypatch.setattr(modulo_bd, "_ahora", ahora_que_falla_a_mitad_de_camino)

    resultados = [(10 + i, "cerrado") for i in range(5)]
    with pytest.raises(RuntimeError):
        base_datos.agregar_resultados(proyecto.id, "127.0.0.1", resultados)

    assert base_datos.listar_resultados(proyecto.id) == []


def test_agregar_resultados_sin_fallo_persiste_todo(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "normal")

    resultados = [(22, "abierto"), (80, "cerrado"), (443, "abierto")]
    guardados = base_datos.agregar_resultados(proyecto.id, "127.0.0.1", resultados)

    assert len(guardados) == 3
    assert len(base_datos.listar_resultados(proyecto.id)) == 3


def test_agregar_resultados_lista_vacia_no_falla(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto = crear_proyecto(base_datos, "vacio")

    assert base_datos.agregar_resultados(proyecto.id, "127.0.0.1", []) == []
    assert base_datos.listar_resultados(proyecto.id) == []


# ---------------------------------------------------------------------------
# Limite de concurrencia: tras detectar cancelacion, no se inician mas
# conexiones de las que la concurrencia ya habia permitido empezar.
# ---------------------------------------------------------------------------


def test_cancelar_detiene_la_programacion_de_nuevas_conexiones(monkeypatch):
    CONCURRENCIA = 3
    TOTAL_PUERTOS = 30

    llamadas = {"n": 0}
    lock = threading.Lock()
    liberar = threading.Event()

    def comprobar_puerto_falso(objetivo, puerto, tiempo_espera):
        with lock:
            llamadas["n"] += 1
        # Las primeras tareas se quedan bloqueadas hasta que el test las libera,
        # simulando trabajo en curso mientras se decide cancelar.
        liberar.wait(timeout=2.0)
        return ResultadoPuerto(puerto=puerto, estado="cerrado")

    monkeypatch.setattr(tcp_scanner, "_comprobar_puerto", comprobar_puerto_falso)

    def debe_cancelar() -> bool:
        return True  # cancela desde la primera comprobacion posible

    resultado_hilo: dict[str, object] = {}

    def ejecutar():
        resultado_hilo["valor"] = escanear_puertos_tcp(
            "127.0.0.1",
            list(range(1, TOTAL_PUERTOS + 1)),
            tiempo_espera=1.0,
            concurrencia=CONCURRENCIA,
            debe_cancelar=debe_cancelar,
        )

    hilo = threading.Thread(target=ejecutar)
    hilo.start()

    # Da tiempo a que el pool arranque como maximo CONCURRENCIA tareas (las
    # unicas que pueden haberse "programado" antes de que exista la
    # oportunidad de cancelar: el resto sigue en la cola interna del
    # ThreadPoolExecutor, nunca llega a ejecutarse).
    for _ in range(100):
        with lock:
            if llamadas["n"] >= CONCURRENCIA:
                break
        hilo.join(timeout=0.02)

    liberar.set()
    hilo.join(timeout=5)
    assert not hilo.is_alive()

    assert resultado_hilo["valor"] == []
    # Nunca se programan mas conexiones que el limite de concurrencia, aunque
    # el escaneo pedia 30 puertos.
    assert llamadas["n"] <= CONCURRENCIA


def test_sin_cancelar_se_respeta_la_concurrencia_pero_se_completan_todos(monkeypatch):
    CONCURRENCIA = 2
    maximo_simultaneo = {"actual": 0, "maximo": 0}
    lock = threading.Lock()

    def comprobar_puerto_falso(objetivo, puerto, tiempo_espera):
        with lock:
            maximo_simultaneo["actual"] += 1
            maximo_simultaneo["maximo"] = max(
                maximo_simultaneo["maximo"], maximo_simultaneo["actual"]
            )
        import time

        time.sleep(0.03)
        with lock:
            maximo_simultaneo["actual"] -= 1
        return ResultadoPuerto(puerto=puerto, estado="cerrado")

    monkeypatch.setattr(tcp_scanner, "_comprobar_puerto", comprobar_puerto_falso)

    resultados = escanear_puertos_tcp(
        "127.0.0.1", list(range(1, 11)), tiempo_espera=1.0, concurrencia=CONCURRENCIA
    )

    assert len(resultados) == 10
    assert maximo_simultaneo["maximo"] <= CONCURRENCIA


# ---------------------------------------------------------------------------
# Operaciones simultaneas: dos escrituras concurrentes a la misma base de
# datos no se pierden ni se corrompen entre si.
# ---------------------------------------------------------------------------


def test_escrituras_concurrentes_no_pierden_resultados(tmp_path):
    base_datos = BaseDatos(tmp_path / "est.db")
    proyecto_a = crear_proyecto(base_datos, "concurrente-a")
    proyecto_b = crear_proyecto(base_datos, "concurrente-b")

    lote_a = [(1000 + i, "abierto") for i in range(25)]
    lote_b = [(2000 + i, "cerrado") for i in range(25)]
    errores: list[Exception] = []

    def escribir(proyecto_id: int, objetivo: str, lote: list[tuple[int, str]]) -> None:
        try:
            base_datos.agregar_resultados(proyecto_id, objetivo, lote)
        except Exception as exc:  # noqa: BLE001 - se reporta en el hilo principal
            errores.append(exc)

    hilo_a = threading.Thread(target=escribir, args=(proyecto_a.id, "10.0.0.1", lote_a))
    hilo_b = threading.Thread(target=escribir, args=(proyecto_b.id, "10.0.0.2", lote_b))
    hilo_a.start()
    hilo_b.start()
    hilo_a.join(timeout=10)
    hilo_b.join(timeout=10)

    assert not errores, f"Errores durante escritura concurrente: {errores}"
    assert len(base_datos.listar_resultados(proyecto_a.id)) == 25
    assert len(base_datos.listar_resultados(proyecto_b.id)) == 25
    # Cada lote queda intacto en su propio proyecto, sin mezclarse con el otro.
    puertos_a = {r.puerto for r in base_datos.listar_resultados(proyecto_a.id)}
    puertos_b = {r.puerto for r in base_datos.listar_resultados(proyecto_b.id)}
    assert puertos_a == {p for p, _ in lote_a}
    assert puertos_b == {p for p, _ in lote_b}
