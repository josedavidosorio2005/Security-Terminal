# OWASP ZAP: analisis pasivo unicamente (Fase 3, Paso 5)

OWASP ZAP es, por diseno, una herramienta de pentesting muy potente: puede hacer active scan
(ataques activos contra el objetivo), spider y AJAX spider (exploracion automatica de todo un
sitio), fuzzing, importacion masiva de URLs y mucho mas. **AST no expone nada de eso.** Solo
ofrece analisis pasivo: una unica peticion GET de solo lectura, seguida de la lectura de las
alertas que ZAP genero a partir de esa peticion.

## Por que "solo pasivo" no es una limitacion temporal, es la politica

El analisis pasivo de ZAP no envia ningun trafico propio hacia el objetivo: se limita a
examinar el trafico que ya paso por el (via su proxy, o por una peticion que el mismo hizo a
peticion de AST) y a avisar de problemas que esa inspeccion detecta (cabeceras de seguridad
ausentes, cookies sin atributos adecuados, divulgacion de informacion en la respuesta...).
Nunca envia payloads de ataque ni intenta explotar nada. Por eso AST solo expone esto:

1. **Nunca active scan (`ascan`).** No existe ninguna opcion en `est zap` que lo active, ni en
   la CLI ni en la interfaz visual.
2. **Nunca spider ni AJAX spider.** AST nunca le pide a ZAP que explore un sitio por su cuenta:
   el unico recurso que ZAP visita es el que el usuario indico explicitamente.
3. **Nunca fuzzing.** No se usa ningun endpoint de la API de ZAP relacionado con fuzzing.
4. **Una unica peticion GET controlada.** Para alimentar el analizador pasivo sin usar spider,
   AST llama a `core/action/accessUrl` de la propia API de ZAP (nunca a traves de un proxy
   configurado aparte) con `followRedirects=false`: ZAP hace esa unica peticion, la registra en
   su historial y la pasa por su analizador pasivo. AST no puede controlar que ZAP, por su
   propia implementacion, decida registrar la URL completa en su historial compartido; lo que
   AST si garantiza es que nunca le pide una segunda peticion, ni una exploracion.
5. **Nunca importacion ni exploracion masiva.** No se usa `importurls`, `openapi`, `soap` ni
   ningun otro mecanismo de importacion masiva de la API de ZAP.

## ZAP no lo instala AST

A diferencia de Nmap y Nuclei, ZAP **no es un binario que AST ejecute como subproceso**. Debes
tener tu propia instancia de ZAP ya corriendo (con su interfaz grafica, o como daemon
`zap.sh -daemon`) antes de usar `est zap`. AST nunca lo descarga, instala ni actualiza.

### Instalar OWASP ZAP

- **Windows**: descarga el instalador desde
  [zaproxy.org/download](https://www.zaproxy.org/download/). Arrancalo normalmente, o como
  daemon desde la consola: `zap.bat -daemon -port 8080 -config api.key=TU_CLAVE`.
- **Linux (Debian/Ubuntu)**: `sudo apt install zaproxy`, o descarga el paquete oficial. Como
  daemon: `zap.sh -daemon -port 8080 -config api.key=TU_CLAVE`.
- **Linux (Fedora/RHEL)**: paquete `zaproxy` si esta disponible en tus repositorios, o el
  instalador oficial.

Verifica que la API responde con `est zap estado`.

### Configurar el endpoint y la API key

AST se conecta a la API REST de ZAP mediante dos variables de entorno:

| Variable | Descripcion | Por defecto |
|---|---|---|
| `EST_ZAP_URL` | Endpoint de la API de ZAP. **Debe ser loopback HTTP literal.** | `http://127.0.0.1:8080` |
| `EST_ZAP_API_KEY` | API key configurada en ZAP (`-config api.key=...`). Opcional si ZAP no tiene una configurada. | (ninguna) |

```bash
export EST_ZAP_URL="http://127.0.0.1:8080"
export EST_ZAP_API_KEY="tu-clave-de-zap"
est zap estado
```

**La API key nunca se muestra en pantalla, en logs ni en informes.** Se lee una sola vez de la
variable de entorno y solo se usa como parametro de la peticion HTTP hacia ZAP; si ZAP la
rechaza, el mensaje de error nunca interpola el valor configurado.

### Por que el endpoint debe ser loopback literal

AST rechaza explicitamente:

- Cualquier host que no sea exactamente `127.0.0.1` -- incluido `localhost` (su resolucion
  depende del archivo `hosts` del sistema operativo, no es una garantia equivalente a la IP
  literal) y cualquier IP remota.
- Cualquier esquema distinto de `http` (ZAP no suele exponer su API en HTTPS por defecto en
  loopback, y forzarlo no aporta seguridad real para una conexion que nunca sale de la propia
  maquina).

Esto significa que AST **nunca administra una instancia de ZAP remota**: si tu ZAP corre en
otra maquina, tendrias que reenviar su puerto a loopback (p. ej. con un tunel SSH) antes de
usar `est zap`, nunca apuntar `EST_ZAP_URL` directamente a esa maquina.

## Comandos

```bash
est zap estado
est zap pasivo URL [--proyecto NOMBRE] [--tiempo-limite 60]
est zap resultados [--proyecto NOMBRE] [--limite 50]
est zap revisar ID --estado nuevo|confirmado|falso_positivo
est zap reporte --formato html|json [--proyecto NOMBRE] [--salida RUTA]
```

| Parametro | Descripcion |
|---|---|
| `URL` | Debe ser una IPv4 literal ya autorizada en el alcance del proyecto (misma regla que `est web auditar`: esquema `http`/`https`, sin credenciales en la URL, sin nombres de dominio). |
| `--tiempo-limite` | Segundos maximos de espera para que el analizador pasivo termine (5 a 300). |
| `--estado` (en `revisar`) | `nuevo` (valor inicial al guardarse), `confirmado` o `falso_positivo`. |

Al igual que `escanear tcp`/`nmap`/`nuclei`, `est zap pasivo` rechaza cualquier objetivo que no
este en el alcance autorizado del proyecto, **antes** de llamar a la API de ZAP (ni siquiera
la unica peticion GET controlada llega a un objetivo fuera de alcance).

## El motor: `integrations/zap.py` + `modules/vulnerability/zap.py`

```text
integrations/
└── zap.py                      AdaptadorZAP: fachada de diagnostico y analisis pasivo.
modules/vulnerability/
└── zap.py                      Logica real: validacion del endpoint, cliente HTTP de la
                                 API de ZAP, analisis pasivo, redaccion de resultados.
```

A diferencia de Nmap/Nuclei, `AdaptadorZAP` **no hereda** de
`integrations/base.py:AdaptadorExterno`: ese contrato esta pensado para binarios resueltos
con `shutil.which` y ejecutados sin shell (`_ejecutar_binario`, `ruta_binario`...), y ZAP no es
un binario que AST invoque, sino un servicio HTTP ya en marcha. La logica de conexion vive en
`modules/vulnerability/zap.py`, con el mismo patron que `modules/web/cliente.py` usa para
hablar con el objetivo auditado: `http.client` directo (nunca `urllib.request` ni una
libreria de terceros), sin leer `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` del entorno.

### Flujo de `est zap pasivo`

1. **`commands/zap.py:ejecutar_zap_pasivo()`** valida la URL (reutiliza
   `core/validation.py:validar_url_web`, la misma validacion que la auditoria web) y comprueba
   el alcance autorizado **antes** de llamar a la API de ZAP.
2. **Diagnostico**: comprueba que la API de ZAP responde (`core/view/version`); si no, se
   rechaza con un mensaje claro sin intentar nada mas.
3. **`core/action/accessUrl`** (`followRedirects=false`): la unica peticion GET que llega al
   objetivo, hecha por la propia API de ZAP, nunca por AST directamente.
4. **Espera activa** a que el analizador pasivo termine (`pscan/view/recordsToScan` hasta que
   llegue a 0, sondeando con un intervalo corto), respetando el `--tiempo-limite` y la
   cancelacion.
5. **`core/view/alerts`**, filtrado por `baseurl=<objetivo>`: solo las alertas de ESE
   objetivo, nunca las de otras auditorias que pudiera tener la misma instancia de ZAP.
6. **`commands/zap.py`** persiste los hallazgos atomicamente en `resultados_zap` (ver
   `storage/database.py`), igual que el resto de comandos.

## Resultados y evidencias

Cada hallazgo se guarda en la tabla `resultados_zap` (persistencia atomica, igual que
`resultados_nuclei`/`resultados_web`): proyecto, objetivo, identificador de la regla de ZAP
(`pluginId`), nombre, riesgo, confianza, descripcion, evidencia saneada, solucion, referencia
y estado de revision (`nuevo` al guardarse).

**Que nunca se guarda ni se muestra**: ZAP no incluye peticiones/respuestas HTTP completas en
sus alertas (a diferencia de Nuclei, cuyo JSONL si las trae y que AST descarta
explicitamente), pero sus campos de texto libre (`description`, `evidence`, `solution`,
`reference`) y la URL de cada alerta se tratan igualmente como no confiables: se pasan por
`core/redaccion.py:redactar_url`/`redactar_texto_libre` (el mismo mecanismo compartido con
Nuclei y la auditoria web) y se acotan en longitud antes de guardarse o mostrarse.

`est zap reporte` exporta los hallazgos guardados a HTML o JSON, reutilizando el mismo
esqueleto (CSS, cabecera) que el resto de informes de AST.

## Interfaz visual: seccion "OWASP ZAP"

El panel muestra si la API de ZAP responde (y su version), el proyecto activo y una nota
explicita de que solo se ofrece analisis pasivo. Escribe la URL autorizada, un tiempo limite
opcional y marca la casilla **"Confirmo que el objetivo esta autorizado"** -- el boton
"Analizar" no hace nada sin esa confirmacion explicita. "Cancelar" detiene la espera del
analisis (ZAP, al ser un servicio independiente, sigue corriendo por su cuenta; lo que AST
garantiza es que no se guarda ningun hallazgo de un analisis cancelado). Selecciona una fila
de la tabla de alertas para ver su detalle completo (riesgo, confianza, descripcion, evidencia
saneada, solucion y referencia) y marcarla como "confirmado" o "falso positivo" -- como con
cualquier escaner automatico, revisa la evidencia antes de confirmar un hallazgo.

## Limitaciones conocidas

- **El analisis pasivo no se ha podido validar contra una instancia de ZAP real en este
  entorno de desarrollo.** Todas las pruebas automatizadas (`tests/test_integraciones_zap.py`,
  `tests/test_tui_zap.py`) sustituyen las llamadas a la API de ZAP por dobles deterministas
  con la forma documentada de la API oficial (<https://www.zaproxy.org/docs/api/>); ninguna
  ejecuta ZAP de verdad. Antes de depender de esto en una auditoria real, valida manualmente
  con una instancia de ZAP real en un laboratorio local autorizado.
- Los resultados de ZAP tienen su propia tabla (`resultados_zap`) y todavia no aparecen en
  `est resultados` ni en `est reporte generar` (solo los de `escanear tcp`).
- La garantia de aislamiento es sobre el contenido de la peticion (solo GET, sin seguir
  redirecciones, filtrado de alertas por objetivo), no una sandbox de red a nivel de sistema
  operativo: AST no puede impedir que ZAP, por su propia implementacion, registre la peticion
  en un historial compartido con otras auditorias que usen la misma instancia.
- Si la instancia de ZAP esta corriendo en Windows y el puerto loopback configurado no esta en
  uso, el intento de conexion puede tardar un poco mas de lo habitual en reportarse como "no
  disponible" (variable segun el sistema); la comprobacion automatica del panel
  "Herramientas" usa un limite de tiempo corto especificamente para no bloquear el arranque de
  la interfaz visual por este motivo.
- Requiere tener OWASP ZAP instalado y corriendo por tu cuenta (`est zap estado` indica si AST
  detecta su API). AST nunca lo instala ni lo arranca por ti.
