"""Orquestacion de una auditoria web: una peticion, varios tipos de hallazgos.

``ejecutar_auditoria_web`` es la unica funcion de este paquete que ``commands/web.py``
necesita llamar. Hace exactamente una peticion HTTP(S) (mas, opcionalmente, una peticion
adicional por cada salto de redireccion explicitamente autorizado) y, a partir de esa
misma respuesta, calcula los hallazgos de las categorias pedidas en ``tipos``.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass

from eurabyte_security.core.errores import ErrorAuditoriaWeb, ErrorFueraDeAlcance
from eurabyte_security.core.validation import ComponentesURL
from eurabyte_security.modules.web.cabeceras import evaluar_cabeceras
from eurabyte_security.modules.web.cliente import RespuestaWeb, realizar_peticion
from eurabyte_security.modules.web.cookies import evaluar_cookies
from eurabyte_security.modules.web.modelos import Hallazgo
from eurabyte_security.modules.web.redirecciones import (
    evaluar_redireccion,
    resolver_siguiente_salto,
)
from eurabyte_security.modules.web.tls import evaluar_tls

TIPOS_VALIDOS = frozenset({"cabeceras", "tls", "cookies", "redirecciones"})
MAXIMO_SALTOS = 5


@dataclass(frozen=True, slots=True)
class ResultadoAuditoriaWeb:
    componentes_inicial: ComponentesURL
    componentes_final: ComponentesURL
    codigo_estado: int
    saltos_seguidos: tuple[str, ...]
    hallazgos: list[Hallazgo]


def _verificar_alcance(host: ipaddress.IPv4Address, redes_autorizadas: list, url: str) -> None:
    if not any(host in red for red in redes_autorizadas):
        raise ErrorFueraDeAlcance(
            f"El objetivo '{url}' no esta dentro del alcance autorizado del proyecto. "
            "Registralo primero con 'est alcance agregar'."
        )


def ejecutar_auditoria_web(
    componentes: ComponentesURL,
    *,
    redes_autorizadas: list[ipaddress.IPv4Network],
    tipos: frozenset[str] = TIPOS_VALIDOS,
    tiempo_limite: float = 10.0,
    seguir_redirecciones: bool = False,
    debe_cancelar: Callable[[], bool] | None = None,
) -> ResultadoAuditoriaWeb:
    """Audita ``componentes`` y devuelve los hallazgos de las categorias pedidas en ``tipos``.

    La verificacion de alcance ocurre antes de cada peticion (la inicial y, si se sigue
    una redireccion autorizada, tambien la del salto siguiente): ningun objetivo fuera
    del alcance autorizado llega a recibir una sola peticion.
    """
    tipos_invalidos = tipos - TIPOS_VALIDOS
    if tipos_invalidos:
        raise ValueError(f"Tipos de auditoria desconocidos: {sorted(tipos_invalidos)}")

    _verificar_alcance(componentes.host, redes_autorizadas, componentes.url_original)

    componentes_actuales = componentes
    saltos_seguidos: list[str] = []
    respuesta: RespuestaWeb | None = None
    todos_los_hallazgos: list[Hallazgo] = []

    for _ in range(MAXIMO_SALTOS + 1):
        respuesta = realizar_peticion(
            componentes_actuales, tiempo_limite=tiempo_limite, debe_cancelar=debe_cancelar
        )

        if "redirecciones" in tipos:
            todos_los_hallazgos.extend(
                evaluar_redireccion(
                    respuesta,
                    redes_autorizadas=redes_autorizadas,
                    se_siguio=False,  # se corrige abajo si realmente se sigue este salto
                )
            )

        if not (seguir_redirecciones and respuesta.ubicacion_redireccion):
            break

        try:
            siguiente = resolver_siguiente_salto(respuesta, redes_autorizadas=redes_autorizadas)
        except (ErrorAuditoriaWeb, ErrorFueraDeAlcance):
            # No se puede seguir con seguridad: el hallazgo ya explica por que, nos detenemos.
            break

        if len(saltos_seguidos) >= MAXIMO_SALTOS:
            break
        saltos_seguidos.append(siguiente.url_original)
        componentes_actuales = siguiente

    assert respuesta is not None  # el bucle siempre ejecuta al menos una iteracion

    if "cabeceras" in tipos:
        todos_los_hallazgos.extend(
            evaluar_cabeceras(respuesta.cabeceras, esquema=componentes_actuales.esquema)
        )
    if "tls" in tipos:
        todos_los_hallazgos.extend(
            evaluar_tls(respuesta.tls, esquema=componentes_actuales.esquema)
        )
    if "cookies" in tipos:
        todos_los_hallazgos.extend(evaluar_cookies(respuesta.cabeceras))

    return ResultadoAuditoriaWeb(
        componentes_inicial=componentes,
        componentes_final=componentes_actuales,
        codigo_estado=respuesta.codigo_estado,
        saltos_seguidos=tuple(saltos_seguidos),
        hallazgos=todos_los_hallazgos,
    )
