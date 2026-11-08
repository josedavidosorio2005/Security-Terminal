# Nuclei: plantillas HTTP aprobadas de bajo impacto (Fase 3, Paso 4)

Nuclei es, por diseno, una herramienta de proposito muy general: una plantilla puede
hacer practicamente cualquier cosa (peticiones HTTP, DNS, acceso a archivos locales,
ejecucion de JavaScript/headless, workflows que encadenan varios pasos, pruebas
OAST/Interactsh contra un servidor de terceros...). AST **no expone esa generalidad**.
Solo permite ejecutar un catalogo reducido de plantillas HTTP de bajo impacto, escritas
y revisadas por el propio equipo de AURABYTE y distribuidas junto con el paquete.

## Por que un catalogo cerrado, no las plantillas de la comunidad

El repositorio publico de plantillas de Nuclei (`nuclei-templates`) tiene miles de
plantillas con todo tipo de proposito y riesgo, y AST no puede revisarlas todas de
forma individual ni mantenerse al dia con sus cambios. En vez de confiar en que una
plantilla es segura porque viene "firmada" o porque Nuclei la clasifica de una forma
concreta, AST solo ejecuta plantillas que:

1. **Escribio AURABYTE**, no una plantilla descargada de internet.
2. **Se vuelven a validar estructuralmente en cada ejecucion** (no solo al revisarlas
   una vez): ver `integrations/nuclei.py:validar_plantilla_estructura()`. Se rechaza
   cualquier plantilla que declare un bloque de protocolo distinto de `http`
   (`dns`, `file`, `network`, `headless`, `code`, `ssl`, `workflows`, `javascript`),
   que use un metodo distinto de `GET`, que intente seguir redirecciones
   (`redirects: true`/`follow-redirects: true`), o que mencione Interactsh/OAST en
   cualquier forma. Si el archivo cambiara despues de instalar AST (por error o a
   proposito), esta comprobacion lo detecta y rechaza la ejecucion.
3. **El usuario no puede indicar una ruta de plantilla propia.** `est nuclei analizar`
   solo acepta identificadores del catalogo (`--plantillas id1,id2`); no existe ninguna
   opcion para pasar un archivo `.yaml` arbitrario.

## Lo que esto NO puede garantizar

Aunque cada plantilla aprobada hace, segun su propio codigo, una unica peticion GET de
solo lectura contra `{{BaseURL}}` (el objetivo auditado), Nuclei sigue siendo un binario
externo independiente: AST no tiene una forma de interceptar o verificar, a nivel de
red, que el proceso de Nuclei no haga ninguna otra conexion mientras corre. La garantia
real que ofrece este diseno es: *cada plantilla, leida linea por linea, no contiene
ningun codigo que le pida a Nuclei conectarse a otro sitio* -- no una garantia de
aislamiento de red a nivel de sistema operativo. Por eso:

- El catalogo se mantiene deliberadamente pequeno (5 plantillas en esta entrega) para
  que cada una pueda revisarse a mano con confianza.
- Se desactiva explicitamente Interactsh/OAST (`-ni`) y la comprobacion de
  actualizaciones (`-duc`) al invocar Nuclei, como medida adicional (no solo la
  comprobacion estatica de la propia plantilla).
- Si en el futuro se quisiera ampliar el catalogo con plantillas de la comunidad, habria
  que revisarlas de la misma forma (a mano, una por una) antes de anadirlas -- nunca
  importar un directorio completo de golpe confiando en su clasificacion oficial.

## Catalogo de plantillas aprobadas

| Id | Severidad esperada | Que comprueba |
|---|---|---|
| `exposed-env-file` | alta | `.env` (variables de entorno/credenciales) accesible publicamente. |
| `exposed-git-config` | alta | `.git/config` accesible publicamente. |
| `directory-listing` | baja | Listado de directorio habilitado en la raiz. |
| `server-version-disclosure` | info | La cabecera `Server` revela una version especifica. |
| `exposed-phpinfo` | media | Script de diagnostico `phpinfo()` accesible publicamente. |

Cada plantilla vive en `src/eurabyte_security/integrations/plantillas_nuclei/<id>.yaml`
y su metadato en Python (`integrations/nuclei.py:PLANTILLAS_APROBADAS`) incluye, ademas,
una recomendacion de mitigacion en espanol. **Nota**: estas plantillas se escribieron
siguiendo la sintaxis documentada de Nuclei pero no se han podido validar contra un
binario de Nuclei real en este entorno de desarrollo; antes de depender de ellas en una
auditoria real, valida cada una con `nuclei -validate -t <archivo>` (con Nuclei
instalado) y ajusta si la version instalada difiere en algun detalle de sintaxis.

## El motor (reutiliza `integrations/base.py` y `integrations/proceso.py`)

```text
integrations/
├── base.py     AdaptadorExterno: contrato comun (deteccion, version, validacion...).
├── proceso.py  ejecutar_proceso(): unico punto de ejecucion real de un binario externo.
├── nuclei.py   AdaptadorNuclei + catalogo + validacion estructural de plantillas.
└── plantillas_nuclei/*.yaml   Las plantillas aprobadas (ver arriba).
```

`AdaptadorNuclei` anade, sobre el contrato comun:

1. **`verificar_opciones_compatibles()`**: ejecuta `nuclei -h` y comprueba que la
   version instalada reconoce todas las opciones que AST necesita pasarle
   (`-target`, `-t`, `-jsonl`, `-timeout`, `-rate-limit`, `-duc`, `-ni`, `-silent`,
   `-nc`). Si falta alguna, se rechaza la ejecucion con un mensaje claro en vez de
   construir un comando que la version instalada no entenderia.
2. **Validacion de parametros**: objetivo (IPv4 literal, sin ruta -- ver
   `core/validation.py:validar_objetivo_nuclei`), al menos una plantilla del catalogo,
   tiempo limite entre 5 y 120 segundos.
3. **Ejecucion sin shell**: `-target <ip> -t <plantilla1> -t <plantilla2> ... -jsonl
   -o <archivo temporal> -timeout 10 -rate-limit 10 -duc -ni -silent -nc`, siempre a
   traves de `integrations/proceso.py:ejecutar_proceso()` (sin `shell=True`, con limite
   de tiempo y cancelacion real via `Popen.kill()`).
4. **Lectura de resultados JSONL**: cada linea es un hallazgo independiente; una linea
   que no es JSON valido, o a la que le faltan los campos minimos (`template-id`,
   `info.name`), se descarta sin interrumpir el analisis del resto (se informa cuantas
   lineas se descartaron).

## Comandos

```bash
est nuclei version
est nuclei plantillas
est nuclei analizar OBJETIVO --plantillas id1,id2 [--proyecto NOMBRE] [--tiempo-limite 60]
est nuclei resultados [--proyecto NOMBRE] [--limite 50]
est nuclei revisar ID --estado nuevo|confirmado|falso_positivo
est nuclei reporte --formato html|json [--proyecto NOMBRE] [--salida RUTA]
```

| Parametro | Descripcion |
|---|---|
| `OBJETIVO` | IP, o `esquema://IP[:puerto]`, sin ruta ni parametros de consulta (las rutas las define cada plantilla, nunca el usuario). |
| `--plantillas` | Identificadores del catalogo aprobado (ver `est nuclei plantillas`); cualquier otro valor se rechaza. |
| `--tiempo-limite` | Segundos maximos de espera para la ejecucion completa (5 a 120). |
| `--estado` (en `revisar`) | `nuevo` (valor inicial al guardarse), `confirmado` o `falso_positivo`. |

Al igual que `escanear tcp`/`nmap`, `est nuclei analizar` rechaza cualquier objetivo que
no este en el alcance autorizado del proyecto, **antes** de comprobar siquiera si Nuclei
esta instalado.

## Interfaz visual: seccion "Vulnerabilidades"

El panel muestra el proyecto activo, si Nuclei esta instalado (y su version), la lista
de plantillas aprobadas (con su severidad esperada y descripcion corta) para marcar las
que se quieran ejecutar, el objetivo, el tiempo limite y una casilla de confirmacion
explicita ("Confirmo que el objetivo esta autorizado") que debe marcarse antes de poder
analizar -- un clic accidental en "Analizar" nunca dispara un analisis real. El boton
"Cancelar" detiene el proceso de Nuclei de verdad (`Popen.kill()`), sin guardar ningun
hallazgo parcial. Al seleccionar una fila de la tabla de hallazgos se muestra su detalle
completo (severidad, descripcion, evidencia saneada y recomendacion de mitigacion), y
dos botones permiten marcarla como "confirmado" o "falso positivo" -- Nuclei, como
cualquier escaner automatico, puede producir falsos positivos; revisar la evidencia
antes de confirmar un hallazgo es responsabilidad de quien audita, no algo que AST
pueda decidir por si solo.

## Resultados y evidencias

Cada hallazgo se guarda en la tabla `resultados_nuclei` (persistencia atomica, igual que
`resultados`/`resultados_nmap`): proyecto, objetivo, identificador y version (propia de
AST, ver abajo) de la plantilla, nombre del hallazgo, severidad, descripcion, evidencia
ya saneada y estado de revision (`nuevo` al guardarse).

**Que nunca se guarda ni se muestra**: el `request`/`response`/`curl-command` completos
que Nuclei incluye en cada linea JSONL (podrian contener cabeceras de autenticacion o
cookies de sesion) se descartan explicitamente al interpretar la salida -- la evidencia
guardada es un resumen propio (donde se detecto el hallazgo y que matcher lo activo),
nunca el trafico HTTP completo. Ver `integrations/nuclei.py:_analizar_jsonl_nuclei()`.

**Version de la plantilla**: el formato de plantilla de Nuclei no tiene un campo de
version oficial, asi que `plantilla_version` es una convencion propia de AST
(`InfoPlantillaNuclei.version` en el catalogo, incrementada a mano cuando se edita una
plantilla): permite saber, mas adelante, con que revision del catalogo se genero un
hallazgo ya guardado.

`est nuclei reporte` exporta los hallazgos guardados a HTML o JSON, reutilizando el
mismo esqueleto (CSS, cabecera) que `est reporte generar` -- ver
`modules/reporting/generador.py` -- en vez de duplicar la generacion de informes.

## Instalar Nuclei

- **Windows**: descarga el binario desde las releases de
  [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) (no se incluye
  con AST). Verifica con `est nuclei version`.
- **Linux**: `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`
  (requiere Go), o el paquete de tu distribucion si esta disponible.

AST **nunca** instala ni actualiza Nuclei ni sus plantillas por si mismo (`-duc`
desactiva explicitamente la comprobacion de actualizaciones de la propia herramienta).

## Limitaciones conocidas

- El catalogo aprobado es deliberadamente pequeno (5 plantillas); ampliarlo requiere
  escribir y revisar cada plantilla nueva a mano, nunca importar un conjunto externo.
- Las plantillas no se han validado contra un binario de Nuclei real en este entorno de
  desarrollo (ver nota en "Catalogo de plantillas aprobadas").
- La garantia de aislamiento es a nivel de contenido de la plantilla (sin bloques de
  protocolo no-HTTP, sin redirecciones, sin OAST), no una sandbox de red a nivel de
  sistema operativo: sigue siendo responsabilidad del operador confirmar que el
  objetivo esta autorizado antes de analizar.
- `est nuclei reporte` es un informe separado del de `escanear tcp`/`nmap`/auditoria
  web, igual que las demas integraciones de la Fase 3: la unificacion de todos los
  tipos de resultados en un unico informe general queda pendiente para una iteracion
  posterior (ver docs/ROADMAP.md).
- Como con cualquier escaner automatico, un hallazgo puede ser un falso positivo: el
  estado de revision (`nuevo`/`confirmado`/`falso_positivo`) existe precisamente para
  que quien audita lo confirme despues de revisar la evidencia, no AST por si solo.
