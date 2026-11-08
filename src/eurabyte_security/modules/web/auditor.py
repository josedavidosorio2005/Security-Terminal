"""Orquestacion de una auditoria web: una peticion, varios tipos de hallazgos.

``ejecutar_auditoria_web`` es la unica funcion de este paquete que ``commands/web.py``
necesita llamar. Hace exactamente una peticion HTTP(S) (mas, opcionalmente, una peticion
adicional por cada salto de redireccion explicitamente autorizado) y, a partir de esa
misma respuesta, calcula los hallazgos de las categorias pedidas en ``tipos``.
"""

from __future__ import annotations

import ipaddress
import time
from collections.abc import Callable
from dataclasses import dataclass

from eurabyte_security.core.errores import ErrorAuditoriaWeb, ErrorFueraDeAlcance
from eurabyte_security.core.redaccion import redactar_url
from eurabyte_security.core.validation import ComponentesURL
from eurabyte_security.modules.web.cabeceras import evaluar_cabeceras
from eurabyte_security.modules.web.cliente import realizar_peticion
from eurabyte_security.modules.web.cookies import evaluar_cookies
from eurabyte_security.modules.web.modelos import Hallazgo
from eurabyte_security.modules.web.redirecciones import (
    evaluar_redireccion,
    resolver_siguiente_salto,
)
from eurabyte_security.modules.web.tls import evaluar_tls

TIPOS_VALIDOS = frozenset({"cabeceras", "tls", "cookies", "redirecciones"})
MAXIMO_SALTOS = 5

# Presupuesto de tiempo TOTAL de una auditoria completa (todas las peticiones que haga
# falta hacer al seguir redirecciones autorizadas), distinto de ``tiempo_limite`` -- que
# acota UNA sola peticion (ver core/validation.py:TIEMPO_LIMITE_WEB_MAXIMO, 1-30s). Es un
# presupuesto COOPERATIVO, no una garantia estricta: antes de cada peticion (incluida la
# primera) se calcula cuanto queda de este presupuesto y se usa como tope del tiempo
# limite de ESA peticion especifica (nunca mas de lo que el usuario pidio con
# ``tiempo_limite``, pero tampoco mas de lo que queda del total). Eso acota lo que una
# peticion lenta puede consumir, pero no puede evitar una pequena demora adicional fuera
# del control de AST (resolucion de la conexion, negociacion TLS, el propio planificador
# del sistema operativo); por eso no se documenta como un limite de pared estricto.
TIEMPO_LIMITE_TOTAL_MAXIMO = 60.0


@dataclass(frozen=True, slots=True)
class ResultadoAuditoriaWeb:
    componentes_inicial: ComponentesURL
    componentes_final: ComponentesURL
    codigo_estado: int | None
    saltos_seguidos: tuple[str, ...]
    hallazgos: list[Hallazgo]


def _verificar_alcance(host: ipaddress.IPv4Address, redes_autorizadas: list, url: str) -> None:
    if not any(host in red for red in redes_autorizadas):
        raise ErrorFueraDeAlcance(
            f"El objetivo '{redactar_url(url)}' no esta dentro del alcance autorizado "
            "del proyecto. Registralo primero con 'est alcance agregar'."
        )


def _hallazgo_http_incompleto(error_http: str) -> Hallazgo:
    return Hallazgo(
        categoria="http",
        id_="http-incompleto",
        nombre="Peticion HTTP",
        significado="Si se pudo completar una peticion HTTP real contra el objetivo.",
        proposito=(
            "Evaluar cabeceras, cookies y redirecciones requiere una respuesta HTTP real; "
            "sin ella, esos hallazgos no se generan (no se inventan ni se asumen)."
        ),
        valor_detectado=error_http,
        severidad="info",
        estado="No completada",
        riesgo=(
            "No se evaluaron cabeceras, cookies ni redirecciones porque la peticion no "
            "se completo. Revisa el hallazgo de TLS para el detalle del problema de "
            "confianza."
        ),
        recomendacion="Corrige el problema de confianza TLS del objetivo y repite la auditoria.",
        referencia="https://developer.mozilla.org/docs/Web/Security/Transport_Layer_Security",
    )


def _hallazgo_tiempo_total_agotado() -> Hallazgo:
    return Hallazgo(
        categoria="redireccion",
        id_="redireccion-tiempo-total-agotado",
        nombre="Presupuesto de tiempo total de la auditoria",
        significado=(
            "El tiempo limite por peticion (--tiempo-limite) acota UNA peticion; este "
            f"otro presupuesto ({TIEMPO_LIMITE_TOTAL_MAXIMO:g}s) acota la suma de todas "
            "las peticiones de una misma auditoria. Es cooperativo (reduce el tiempo "
            "limite de la siguiente peticion), no una garantia estricta de pared."
        ),
        proposito="Evitar que seguir varias redirecciones alargue la auditoria indefinidamente.",
        valor_detectado=f"{TIEMPO_LIMITE_TOTAL_MAXIMO:g} segundos",
        severidad="info",
        estado="Saltos restantes no seguidos",
        riesgo="Ninguno: AST deja de seguir redirecciones nuevas, pero conserva lo ya auditado.",
        recomendacion=(
            "Si necesitas auditar el destino restante, repite el analisis apuntando "
            "directamente a esa URL."
        ),
        referencia="https://developer.mozilla.org/docs/Web/HTTP/Redirections",
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
    del alcance autorizado llega a recibir una sola peticion. El tiempo total de todas
    las peticiones combinadas (al seguir redirecciones) esta acotado por un presupuesto
    cooperativo de ``TIEMPO_LIMITE_TOTAL_MAXIMO`` segundos (ver esa constante): antes de
    cada peticion se reduce su propio ``tiempo_limite`` a lo que quede de ese presupuesto,
    para que una sola peticion lenta no pueda consumirlo entero por si misma. No es una
    garantia estricta de pared (ver el comentario de la constante).
    """
    tipos_invalidos = tipos - TIPOS_VALIDOS
    if tipos_invalidos:
        raise ValueError(f"Tipos de auditoria desconocidos: {sorted(tipos_invalidos)}")

    _verificar_alcance(componentes.host, redes_autorizadas, componentes.url_original)

    componentes_actuales = componentes
    saltos_seguidos: list[str] = []
    todos_los_hallazgos: list[Hallazgo] = []
    inicio = time.monotonic()

    # La primera peticion siempre se intenta con el tiempo_limite pedido (al empezar, el
    # presupuesto total todavia esta completo). Las siguientes, si las hay, reciben el
    # tiempo_limite recortado calculado al final de la iteracion anterior.
    tiempo_limite_este_salto = tiempo_limite
    respuesta = realizar_peticion(
        componentes_actuales, tiempo_limite=tiempo_limite_este_salto, debe_cancelar=debe_cancelar
    )

    for _indice_salto in range(MAXIMO_SALTOS):
        if respuesta.error_http is not None:
            todos_los_hallazgos.append(_hallazgo_http_incompleto(respuesta.error_http))
            break

        # Se decide AHORA, con el presupuesto restante ya medido en este mismo instante,
        # si este salto se sigue -- y, si se sigue, con cuanto tiempo limite -- para que
        # "se_siguio" en el hallazgo de abajo describa lo que realmente va a pasar a
        # continuacion (la siguiente peticion, sin otra comprobacion de tiempo de por
        # medio que pueda contradecirlo) y no una intencion que luego no se cumple.
        presupuesto_restante = TIEMPO_LIMITE_TOTAL_MAXIMO - (time.monotonic() - inicio)
        siguiente: ComponentesURL | None = None
        se_siguio_este_salto = False
        hay_redireccion_pendiente = seguir_redirecciones and bool(respuesta.ubicacion_redireccion)
        saltos_disponibles = len(saltos_seguidos) < MAXIMO_SALTOS

        if hay_redireccion_pendiente and saltos_disponibles:
            if presupuesto_restante <= 0:
                # Habia margen de saltos, pero el presupuesto de tiempo total se agoto
                # justo antes de intentar esta peticion: no se abrio ninguna conexion de
                # mas, y este salto se registra como no seguido (no como seguido y luego
                # incompleto).
                todos_los_hallazgos.append(_hallazgo_tiempo_total_agotado())
            else:
                try:
                    siguiente = resolver_siguiente_salto(
                        respuesta, redes_autorizadas=redes_autorizadas
                    )
                    se_siguio_este_salto = True
                except (ErrorAuditoriaWeb, ErrorFueraDeAlcance):
                    # No se puede seguir con seguridad: el hallazgo ya explica por que.
                    siguiente = None

        if "redirecciones" in tipos:
            todos_los_hallazgos.extend(
                evaluar_redireccion(
                    respuesta,
                    redes_autorizadas=redes_autorizadas,
                    se_siguio=se_siguio_este_salto,
                )
            )

        if not se_siguio_este_salto:
            break

        assert siguiente is not None
        saltos_seguidos.append(siguiente.url_original)
        componentes_actuales = siguiente
        # Tope cooperativo: esta siguiente peticion nunca recibe mas tiempo del que
        # pidio el usuario, ni mas del que queda del presupuesto total ya medido arriba.
        tiempo_limite_este_salto = max(0.001, min(tiempo_limite, presupuesto_restante))
        respuesta = realizar_peticion(
            componentes_actuales,
            tiempo_limite=tiempo_limite_este_salto,
            debe_cancelar=debe_cancelar,
        )
    else:
        # El for se agoto sin "break": se alcanzo MAXIMO_SALTOS saltos ya seguidos y la
        # ultima respuesta (con otra redireccion pendiente) todavia no se evaluo.
        if respuesta.error_http is not None:
            todos_los_hallazgos.append(_hallazgo_http_incompleto(respuesta.error_http))
        elif "redirecciones" in tipos:
            todos_los_hallazgos.extend(
                evaluar_redireccion(respuesta, redes_autorizadas=redes_autorizadas, se_siguio=False)
            )

    if respuesta.error_http is None:
        if "cabeceras" in tipos:
            todos_los_hallazgos.extend(
                evaluar_cabeceras(respuesta.cabeceras, esquema=componentes_actuales.esquema)
            )
        if "cookies" in tipos:
            todos_los_hallazgos.extend(evaluar_cookies(respuesta.cabeceras))

    if "tls" in tipos:
        todos_los_hallazgos.extend(
            evaluar_tls(respuesta.tls, esquema=componentes_actuales.esquema)
        )

    return ResultadoAuditoriaWeb(
        componentes_inicial=componentes,
        componentes_final=componentes_actuales,
        codigo_estado=respuesta.codigo_estado,
        saltos_seguidos=tuple(saltos_seguidos),
        hallazgos=todos_los_hallazgos,
    )
