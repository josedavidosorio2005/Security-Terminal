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
├── redaccion.py       redactar_url(): oculta parametros sensibles en URLs mostradas/guardadas.
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

### Que pasa con la peticion HTTP si el certificado no es confiable

`modules/web/cliente.py:realizar_peticion()` sigue usando SIEMPRE una conexion HTTPS con
validacion completa para la peticion real (nunca se desactiva en silencio para poder leer el
cuerpo de la respuesta). Si esa conexion falla por confianza (autofirmado, vencido, nombre
equivocado...), la peticion HTTP queda marcada como no completada
(`RespuestaWeb.error_http`/`ResultadoAuditoriaWeb.codigo_estado is None`), pero los hallazgos de
TLS que ya se diagnosticaron **se devuelven igualmente** -- `est web tls` nunca termina en un
error generico sin mostrar nada; muestra el hallazgo de TLS (con su severidad `alta` y el
motivo exacto) y un hallazgo informativo adicional ("Peticion HTTP: No completada") explicando
por que no hay cabeceras, cookies ni redirecciones que evaluar en ese caso.

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
4. Cada redireccion se registra con su estado real: "seguida" solo si AST efectivamente hizo
   la peticion siguiente (destino autorizado y dentro del limite de saltos), "no seguida" en
   cualquier otro caso (incluyendo cuando el usuario no pidio `--seguir-redirecciones`).
5. Como limite adicional, solo se siguen hasta 5 saltos de redireccion por auditoria.

## Objetivos admitidos (IPv4 literal, por ahora)

Igual que `escanear tcp` y `nmap`, **esta entrega solo admite URL con direcciones IPv4
literales como host** (`https://127.0.0.1:8443/panel`), no nombres de dominio. La razon es la
misma: resolver un nombre implicaria una consulta DNS fuera del control explicito del usuario
y abre la puerta a SSRF. Soportar dominios en una iteracion futura requeriria fijar la
conexion a una IP ya autorizada (pinning) conservando la validacion de `Host`, SNI y
certificado -- sin relajar ninguna de las comprobaciones actuales.

## Proteccion de datos sensibles

Ningun valor de cookie se registra ni se muestra nunca (ver arriba). Para URLs (el objetivo
auditado, el destino de una redireccion, mensajes de error), AST usa una estrategia distinta:
la peticion real se hace siempre contra la URL completa que el usuario indico -- nunca se
modifica para poder ejecutar la peticion autorizada --, pero `modules/web/redaccion.py:
redactar_url()` oculta el *valor* de los parametros de consulta cuyo nombre sugiere un secreto
(`token`, `password`, `api_key`, `session_id`, `code`, etc., insensible a mayusculas) antes de:

- Guardarla en `resultados_web` (columna `objetivo`).
- Mostrarla en la salida de la CLI, la Terminal AST o la interfaz visual.
- Incluirla en un hallazgo de redireccion (el destino de un `Location`).
- Incluirla en un mensaje de error (objetivo fuera de alcance, tiempo agotado...).
- Incluirla en un informe HTML/JSON exportado.

Por ejemplo, `https://127.0.0.1/reset?token=abc123&usuario=ana` se muestra y se guarda como
`https://127.0.0.1/reset?token=%3Credactado%3E&usuario=ana`. Un parametro que no esta en la
lista de nombres sensibles conocidos (ver `redaccion.py:PARAMETROS_SENSIBLES`) se conserva tal
cual: esta redaccion es una mitigacion adicional, no un sustituto de manejar las URLs con
secretos con cuidado (evita, por ejemplo, pegarlas en un chat o un ticket sin redactar).

## Limites de tiempo: por peticion vs. total de la auditoria

- **`--tiempo-limite`** (1 a 30 segundos, validado en `core/validation.py:
  validar_tiempo_limite_web`) acota **una sola peticion** HTTP(S).
- **El tiempo total de toda la auditoria** (la suma de todas las peticiones, cuando se siguen
  redirecciones con `--seguir-redirecciones`) tiene su propio limite independiente, fijo en 60
  segundos (`modules/web/auditor.py:TIEMPO_LIMITE_TOTAL_MAXIMO`), para que encadenar varias
  redirecciones con el tiempo limite por peticion mas alto permitido no pueda alargar una sola
  auditoria varios minutos. Si se agota, AST deja de seguir redirecciones nuevas (lo reporta
  como hallazgo informativo) pero conserva todo lo ya auditado hasta ese punto.
- **Cancelacion durante una peticion bloqueante**: `debe_cancelar` se sondea antes de conectar,
  justo despues de conectar y entre cada fragmento de 8 KiB leido del cuerpo de la respuesta.
  Una conexion que nunca llega a enviar nada (o un chunk de hasta 8 KiB que tarda en llegar)
  permanece bloqueada en esa espera hasta su propio `--tiempo-limite`: es la misma limitacion
  de E/S bloqueante que ya existe en `escanear tcp` (los hilos de Python no se pueden
  interrumpir de forma forzosa mientras esperan en una llamada de red).

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
proyecto, el objetivo (ya redactado, ver arriba), el tipo de analisis que lo origino, la
categoria del hallazgo, su severidad, estado, valor detectado (ya saneado/redactado), riesgo,
recomendacion, referencia y fecha. La persistencia es atomica: todos los hallazgos de una
auditoria se guardan en una sola transaccion, igual que `escanear tcp`/`nmap`. `debe_cancelar`
se comprueba dos veces: durante la auditoria (dentro de cada peticion de red) y otra vez justo
antes de abrir esa transaccion -- si la cancelacion se detecta en ese segundo chequeo (p. ej.
porque el usuario cancelo justo cuando la red ya habia terminado), tampoco se guarda nada.

`est web reporte` exporta los hallazgos guardados a HTML o JSON, reutilizando el mismo
esqueleto (CSS, cabecera) que `est reporte generar` -- ver `modules/reporting/generador.py` --
en vez de duplicar la generacion de informes.

## Limitaciones conocidas

- Solo se admiten objetivos con IP IPv4 literal; no hay resolucion de nombres de dominio.
- `est web reporte` es un informe separado del de `est escanear tcp`/`nmap`, igual que los
  resultados de Nmap: la integracion de los tres tipos de resultados en un unico informe
  general queda pendiente para una iteracion posterior (ver docs/ROADMAP.md).
- Cancelacion durante una peticion bloqueante (ver "Limites de tiempo" arriba): una conexion
  que nunca envia nada permanece bloqueada hasta su propio `--tiempo-limite` antes de poder
  cancelarse de verdad (misma limitacion de E/S bloqueante que `escanear tcp`).
- El cuerpo de la respuesta se limita a 2 MiB; una respuesta mayor se trunca (no afecta a las
  cabeceras, TLS ni cookies, que se leen antes del cuerpo).
- Solo se siguen hasta 5 saltos de redireccion por auditoria, y el tiempo total de todos esos
  saltos combinados esta acotado a 60 segundos (independiente de `--tiempo-limite`, ver arriba).
- La redaccion de parametros sensibles en URLs (ver arriba) cubre una lista conocida de nombres
  de parametro (`token`, `password`, `api_key`...); un secreto transportado en un parametro con
  un nombre no reconocido no se redacta automaticamente.
- Cuando el certificado TLS no es confiable, la peticion HTTP no se completa (por diseno: AST
  nunca ignora la validacion para forzarla) y por lo tanto no hay hallazgos de cabeceras,
  cookies ni redirecciones para ese objetivo -- solo los de TLS.
