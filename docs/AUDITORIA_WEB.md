# Auditoria web no intrusiva (Fase 3, Paso 3)

AST incluye una auditoria web no intrusiva: no hace *crawling*, no envia payloads de ataque y
no modifica nada en el objetivo. Hace una unica peticion HTTP(S) de solo lectura (`GET`) y
analiza la respuesta: cabeceras de seguridad, certificado/TLS, cookies y redirecciones.

## Arquitectura

```text
src/eurabyte_security/modules/web/
├── modelos.py        Hallazgo: estructura comun de cada resultado (ver mas abajo).
├── cliente.py        realizar_peticion(): unica peticion HTTP(S), sin seguir redirecciones.
├── tls.py            obtener_info_tls()/evaluar_tls(): certificado, version y cifrado TLS.
├── cabeceras.py       evaluar_cabeceras(): cabeceras de seguridad HTTP.
├── cookies.py         evaluar_cookies(): atributos de Set-Cookie (nunca el valor).
├── redirecciones.py   evaluar_redireccion()/resolver_siguiente_salto(): SSRF y alcance.
└── auditor.py         ejecutar_auditoria_web(): orquesta todo lo anterior.
```

`commands/web.py` es la unica capa que conoce proyectos/alcance/base de datos: valida la URL
(`core/validation.py:validar_url_web`), comprueba el alcance autorizado **antes** de cualquier
peticion (igual que `escanear tcp` y `nmap`) y persiste los hallazgos. `modules/web/` no sabe
nada de proyectos ni de SQLite, igual que `modules/network/tcp_scanner.py`.

## Cada hallazgo (`Hallazgo` en `modules/web/modelos.py`)

Todo hallazgo -- de cabeceras, TLS, cookies o redirecciones -- tiene la misma forma:

| Campo | Que es |
|---|---|
| `significado` | Que es/representa la comprobacion. |
| `proposito` | Para que sirve (que ataque o riesgo mitiga). |
| `valor_detectado` | El valor real encontrado (o `None`/redactado si no aplica). |
| `severidad` | `info`, `baja`, `media` o `alta` -- **nunca** se asigna automaticamente la
  severidad mas alta solo por ausencia; cada comprobacion evalua su propio contexto (ver
  ejemplos abajo). |
| `estado` | Texto corto del resultado (`Presente`, `Ausente`, `Vencido`...). |
| `riesgo` | Que puede salir mal si el hallazgo no se corrige. |
| `recomendacion` | Como solucionarlo. |
| `referencia` | Enlace a documentacion tecnica (MDN, etc.). |

## Cabeceras HTTP evaluadas

`Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`,
`X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, y de forma condicional
`Cache-Control` (solo si la respuesta tiene cookies: en una pagina sin estado no hay nada
sensible que cachear), ademas de dos hallazgos adicionales utiles: divulgacion de version del
servidor (`Server`/`X-Powered-By`) y CORS permisivo (`Access-Control-Allow-Origin: *`).

Ejemplos de evaluacion contextual (no todo lo ausente es lo mismo):

- `Strict-Transport-Security` ausente sobre **HTTP** se marca `info`/"No aplica": HSTS no
  tiene sentido sin TLS. El mismo hallazgo sobre **HTTPS** sin la cabecera es `media`.
- `X-Frame-Options` ausente es `media`, salvo que la `Content-Security-Policy` ya incluya
  `frame-ancestors` (entonces la proteccion equivalente ya existe y el hallazgo baja a `info`).
- `Content-Security-Policy` ausente es `media`; presente pero con `unsafe-inline`/`unsafe-eval`/
  `*` es `baja` (mejor que nada, pero debilitada).

## HTTPS/TLS

`modules/web/tls.py` **nunca desactiva la validacion TLS para fingir un resultado exitoso**.
Intenta primero una conexion completamente verificada (cadena de confianza + nombre de host
contra la IP auditada). Si falla, abre una segunda conexion *solo para leer los bytes reales
del certificado* (necesarios para mostrar fecha de vencimiento, emisor, sujeto...), pero el
resultado queda marcado explicitamente como no confiable, con el motivo exacto del fallo de
confianza. Los metadatos leidos por esa segunda via siempre vienen del certificado real
presentado por el servidor: nunca se inventan ni se asumen, y el informe distingue "metadatos
confirmados" (verificacion exitosa) de "metadatos leidos sin verificar la cadena de confianza".

Se evaluan: version de TLS negociada (TLS 1.0/1.1/SSLv3 se marcan `alta`), suite de cifrado
(informativo), confianza del certificado, fecha de vencimiento (vencido o a menos de 15 dias:
`alta`; a menos de 30 dias: `media`), y coincidencia del nombre de host con los nombres
alternativos (SAN) del certificado.

Como esta version de AST solo admite direcciones IPv4 literales como objetivo (ver mas abajo),
la verificacion de nombre de host compara la IP auditada contra las entradas `IPAddress` del
SAN del certificado, no contra un nombre de dominio.

## Cookies

`modules/web/cookies.py` evalua `Secure`, `HttpOnly`, `SameSite` y expiracion de cada cookie
de la respuesta (`Set-Cookie`, puede haber varias). **El valor real de la cookie nunca se
muestra ni se guarda**: todo hallazgo, log, informe o evidencia solo incluye el nombre de la
cookie y sus atributos (`nombre=<redactado>; Secure; HttpOnly; SameSite=Lax`).

Una cookie cuyo nombre sugiere autenticacion/sesion (`sess`, `auth`, `token`, `sid`, `csrf`,
`login`, `jwt`) escala la severidad de `Secure`/`HttpOnly` ausentes a `alta`; en cualquier otra
cookie, a `media`. `SameSite` ausente es siempre `media` (riesgo de CSRF); `SameSite=None` sin
`Secure` se marca como configuracion invalida (los navegadores actuales la descartan). Una
cookie sin `Expires`/`Max-Age` es simplemente informativa (`info`): es el comportamiento
esperado de una cookie de sesion.

## Redirecciones y seguridad del alcance (SSRF)

Este es el punto mas sensible de todo el modulo:

1. **`modules/web/cliente.py` nunca sigue una redireccion automaticamente.** Usa `http.client`
   directamente (no `urllib.request` ni una libreria de terceros) precisamente porque no lee
   `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` del entorno y no sigue redirecciones por si mismo.
2. Si la respuesta es una redireccion (`Location`), AST la reporta siempre como un hallazgo
   (categoria `redireccion`), pero **solo la sigue si se pide explicitamente** con
   `--seguir-redirecciones`, y unicamente si el destino:
   - Es una URL con un host IPv4 literal (no un nombre de dominio: seguir un nombre de
     dominio implicaria una resolucion DNS fuera del control explicito del usuario, la via
     clasica de SSRF mediante respuestas DNS manipuladas).
   - Esta dentro del alcance autorizado del proyecto.
3. Si cualquiera de esas dos condiciones falla, AST **se detiene** y lo reporta como hallazgo
   (`alta` si es una IP fuera de alcance, `media` si no se puede evaluar con seguridad): nunca
   hace una peticion fuera del alcance acordado, con o sin `--seguir-redirecciones`.
4. Como limite adicional, solo se siguen hasta 5 saltos de redireccion por auditoria.

## Objetivos admitidos (IPv4 literal, por ahora)

Igual que `escanear tcp` y `nmap`, **esta entrega solo admite URL con direcciones IPv4
literales como host** (`https://127.0.0.1:8443/panel`), no nombres de dominio. La razon es la
misma: resolver un nombre implicaria una consulta DNS fuera del control explicito del usuario
y abre la puerta a SSRF. Soportar dominios en una iteracion futura requeriria fijar la
conexion a una IP ya autorizada (pinning) conservando la validacion de `Host`, SNI y
certificado -- sin relajar ninguna de las comprobaciones actuales.

## Comandos

```bash
est web cabeceras URL [--proyecto NOMBRE] [--tiempo-limite 10] [--seguir-redirecciones] [--detallado]
est web tls URL [...]
est web cookies URL [...]
est web auditar URL [...]            # las cuatro categorias a la vez
est web reporte --formato html|json [--proyecto NOMBRE] [--salida RUTA]
```

| Parametro | Descripcion |
|---|---|
| `URL` | `http://` o `https://` con un host IPv4 literal autorizado en el alcance del proyecto. |
| `--tiempo-limite` | Segundos maximos de espera por peticion (1 a 30, por defecto 10). |
| `--seguir-redirecciones` | Si el destino es una redireccion autorizada (ver arriba), tambien la audita. |
| `--detallado` | Imprime la explicacion completa (significado, proposito, riesgo, recomendacion, referencia) de cada hallazgo. |

Tambien disponible desde la interfaz visual (`est interfaz`, seccion "Analisis web") y desde la
Terminal AST integrada (`web cabeceras|tls|cookies|auditar URL ...`).

## Resultados y evidencias

Cada hallazgo se guarda en la tabla `resultados_web` (ver `storage/database.py`), con el
proyecto, el objetivo, el tipo de analisis que lo origino, la categoria del hallazgo, su
severidad, estado, valor detectado (ya saneado/redactado), riesgo, recomendacion, referencia y
fecha. La persistencia es atomica: todos los hallazgos de una auditoria se guardan en una sola
transaccion, igual que `escanear tcp`/`nmap`; una auditoria cancelada no deja nada guardado.

`est web reporte` exporta los hallazgos guardados a HTML o JSON, reutilizando el mismo
esqueleto (CSS, cabecera) que `est reporte generar` -- ver `modules/reporting/generador.py` --
en vez de duplicar la generacion de informes.

## Limitaciones conocidas

- Solo se admiten objetivos con IP IPv4 literal; no hay resolucion de nombres de dominio.
- `est web reporte` es un informe separado del de `est escanear tcp`/`nmap`, igual que los
  resultados de Nmap: la integracion de los tres tipos de resultados en un unico informe
  general queda pendiente para una iteracion posterior (ver docs/ROADMAP.md).
- La cancelacion detiene la lectura del cuerpo de la respuesta entre fragmentos (hasta 8 KiB a
  la vez); una conexion que se queda sin enviar nada permanece bloqueada hasta `--tiempo-limite`
  antes de poder cancelarse (misma limitacion de E/S bloqueante que `escanear tcp`).
- El cuerpo de la respuesta se limita a 2 MiB; una respuesta mayor se trunca (no afecta a las
  cabeceras, TLS ni cookies, que se leen antes del cuerpo).
- Solo se siguen hasta 5 saltos de redireccion por auditoria.
