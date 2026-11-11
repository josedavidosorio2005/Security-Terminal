"""Excepciones propias de EST.

Se usan en lugar de ``sys.exit`` dentro de la capa de logica de negocio para que
los modulos de ``core`` y ``modules`` permanezcan faciles de probar de forma
aislada. La capa de CLI (``commands``) es responsable de capturarlas y
mostrarlas en espanol con el formato adecuado.
"""

from __future__ import annotations


class ErrorEST(Exception):
    """Error base de la aplicacion."""


class ErrorValidacion(ErrorEST):
    """Un dato proporcionado por el usuario no es valido."""


class ErrorProyectoNoEncontrado(ErrorEST):
    """El proyecto solicitado no existe."""


class ErrorProyectoDuplicado(ErrorEST):
    """Ya existe un proyecto con ese nombre."""


class ErrorFueraDeAlcance(ErrorEST):
    """El objetivo indicado no esta dentro del alcance autorizado del proyecto."""


class ErrorSinProyectoActivo(ErrorEST):
    """No se especifico un proyecto y tampoco hay un proyecto activo."""


class ErrorEscaneoCancelado(ErrorEST):
    """El escaneo se cancelo antes de completarse; no se guardo ningun resultado."""


class ErrorHerramientaNoDisponible(ErrorEST):
    """La herramienta externa no esta instalada o no se encuentra en el PATH."""


class ErrorParametrosIntegracion(ErrorEST):
    """Los parametros indicados para una integracion externa no son validos."""


class ErrorIntegracion(ErrorEST):
    """Fallo al ejecutar una integracion externa (tiempo agotado, salida invalida...)."""


class ErrorAuditoriaWeb(ErrorEST):
    """Fallo de red al auditar un objetivo web (tiempo agotado, conexion rechazada,
    respuesta demasiado grande, redireccion fuera de alcance...).
    """


class ErrorZAPNoDisponible(ErrorEST):
    """La API de OWASP ZAP no responde en el endpoint configurado, o rechazo la API key."""


class ErrorResolucionDNS(ErrorEST):
    """Un dominio no se pudo resolver, o se resolvio sin ninguna direccion IPv4 util."""


class ErrorSesionReconocimientoNoEncontrada(ErrorEST):
    """No existe una sesion de reconocimiento automatico con el id indicado."""


class ErrorAutorizacionOSINTRequerida(ErrorEST):
    """Falta la confirmacion explicita de autorizacion para investigar datos personales."""


class ErrorFuenteOSINTNoDisponible(ErrorEST):
    """La fuente OSINT no esta configurada o no admite el tipo de objetivo indicado."""


class ErrorFuenteOSINTError(ErrorEST):
    """Fallo al consultar una fuente OSINT (tiempo agotado, respuesta invalida, limite de
    tasa agotado tras los reintentos, etc.)."""


class ErrorInvestigacionOSINTCancelada(ErrorEST):
    """La investigacion OSINT se cancelo antes de completarse; la fuente en curso en ese
    momento no persistio ningun hallazgo."""


class ErrorInvestigacionOSINTNoEncontrada(ErrorEST):
    """No existe una investigacion OSINT con el id indicado."""
