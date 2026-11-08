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
2. **Se vuelven a validar estructuralmente en cada ejecucion, con una lista blanca
   estricta** (no solo al revisarlas una vez, y no solo una lista negra de lo
   prohibido): ver `integrations/nuclei.py:validar_plantilla_estructura()`. Solo se
   acepta la forma exacta que ya tienen las 5 plantillas aprobadas -- campos de nivel
   superior conocidos (`id`, `info`, `http`), un unico bloque `http` con metodo `GET`,
   como maximo 4 rutas, rutas exclusivamente relativas a `{{BaseURL}}` (nunca una URL
   absoluta a otro host ni otra variable de plantilla), y matchers de tipo `status`,
   `word` o `regex` sin campos adicionales -- y se rechaza cualquier campo que AST no
   reconozca, aunque no aparezca en ninguna lista negra concreta. Como defensa
   adicional, tambien se rechaza explicitamente cualquier bloque de protocolo distinto
   de `http` (`dns`, `file`, `network`, `headless`, `code`, `ssl`, `workflows`,
   `javascript`) y cualquier mencion a Interactsh/OAST o a seguir redirecciones.
3. **Cada plantilla aprobada tiene un hash SHA-256 fijado** en el catalogo
   (`InfoPlantillaNuclei.sha256`): si el archivo instalado no coincide con ese hash
   exacto, la ejecucion se rechaza, aunque el YAML siga siendo estructuralmente valido.
   Actualizar ese hash es, en si mismo, una decision que exige revisar de nuevo todo el
   contenido de la plantilla -- nunca se recalcula automaticamente. Si cualquiera de
   estas comprobaciones falla (hash, id, estructura), AST rechaza la ejecucion con un
   error claro en vez de asumir que la plantilla sigue siendo segura.
4. **Nunca se le pasa a Nuclei la ruta original instalada con el paquete.** Para evitar
   una ventana entre "se valido este archivo" y "se ejecuto este archivo" (TOCTOU), AST
   lee el contenido una sola vez, lo valida, y escribe una copia nueva en un directorio
   temporal exclusivo de esa ejecucion (borrado al terminar); es esa copia la que se le
   pasa a Nuclei con `-t`, nunca el archivo original de `plantillas_nuclei/`.
5. **El usuario no puede indicar una ruta de plantilla propia.** `est nuclei analizar`
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
   construir un comando que la version instalada no entenderia. El mismo texto de
   ayuda se reutiliza para decidir, sin volver a invocar `nuclei -h`, cuales de las
   opciones de aislamiento opcionales (ver mas abajo) tambien estan disponibles --
   nunca se asume que una opcion existe sin comprobarlo antes.
2. **Validacion de parametros**: objetivo (IPv4 literal, sin ruta -- ver
   `core/validation.py:validar_objetivo_nuclei`), al menos una plantilla del catalogo,
   tiempo limite entre 5 y 120 segundos.
3. **Configuracion y entorno aislados**: Nuclei busca su configuracion y cache de
   plantillas en un directorio del sistema operativo (`HOME`/`.config` en Linux/macOS,
   `%AppData%` en Windows) y respeta variables de proxy del entorno (`HTTP_PROXY`,
   etc.). AST invoca el proceso con un entorno propio (`_variables_entorno_aisladas()`)
   que elimina esas variables de proxy y cualquier `NUCLEI_*`, y redirige `HOME`/
   `XDG_CONFIG_HOME`/`APPDATA`/`USERPROFILE` a un directorio vacio y nuevo dentro del
   directorio temporal de esa misma ejecucion -- una configuracion, proxy o perfil que
   el usuario ya tuviera guardado en su sistema nunca se aplica silenciosamente. Si la
   version instalada reconoce opciones adicionales de aislamiento (`-config`, `-dr`/
   `-disable-redirects`, `-nh`, `-no-stdin`), tambien se agregan al comando; si no las
   reconoce, el analisis sigue igual (son defensa en profundidad adicional, no la unica
   proteccion).
4. **Ejecucion sin shell y sin binary planting**: `-target <ip> -t <copia validada 1>
   -t <copia validada 2> ... -jsonl -o <archivo temporal> -timeout 10 -rate-limit 10
   -duc -ni -silent -nc`, siempre a traves de `integrations/proceso.py:ejecutar_proceso()`
   (sin `shell=True`, con la ruta absoluta del binario ya resuelta -- ver
   `integrations/base.py` -- con limite de tiempo y cancelacion real via `Popen.kill()`).
   Un codigo de salida distinto de cero (error de argumentos, fallo al cargar una
   plantilla, etc.) se trata siempre como un fallo real, nunca como "analisis exitoso
   sin hallazgos"; no se usa ningun resultado parcial que Nuclei hubiera escrito antes
   de fallar.
5. **Lectura de resultados JSONL, tratada como no confiable**: cada linea es un
   hallazgo independiente; se descarta sin interrumpir el analisis del resto cualquier
   linea que no sea JSON valido, le falten los campos minimos (`template-id`,
   `info.name`), supere un tamano maximo por linea, o reporte un `template-id` que no
   sea exactamente uno de los que AST le pidio ejecutar en esa misma invocacion (nunca
   "cualquier id del catalogo", sino solo los que de verdad se ejecutaron esta vez). La
   salida completa tambien tiene un tamano maximo total (10 MiB); si se supera, se
   rechaza entera y no se guarda nada. Los campos que si se guardan (nombre, severidad,
   descripcion, evidencia) tienen una longitud maxima acotada, para que un valor
   manipulado o inesperadamente largo no pueda romper la tabla de la CLI/TUI (que
   ademas siempre escapa su contenido con `ui/consola.py:texto_seguro` antes de
   mostrarlo).

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
- La garantia de aislamiento es a nivel de contenido de la plantilla (lista blanca
  estricta de campos y rutas, hash SHA-256 aprobado, sin bloques de protocolo no-HTTP,
  sin redirecciones, sin OAST) y de entorno de proceso (configuracion/proxy aislados,
  ruta absoluta del binario), no una sandbox de red a nivel de sistema operativo:
  sigue siendo responsabilidad del operador confirmar que el objetivo esta autorizado
  antes de analizar.
- Las opciones de aislamiento opcionales (`-config`, `-dr`/`-disable-redirects`, `-nh`,
  `-no-stdin`) solo se agregan si `nuclei -h` las reconoce; en una version de Nuclei
  que no las tenga, ese refuerzo puntual no esta disponible (el aislamiento real -- el
  entorno de proceso propio y la validacion de plantillas -- sigue aplicandose igual).
  Ninguna de estas comprobaciones se ha podido ejecutar contra un binario de Nuclei
  real en este entorno de desarrollo (ver tambien la nota en "Catalogo de plantillas
  aprobadas"); antes de depender de ellas en una auditoria real, revisa con `nuclei -h`
  y `nuclei -version` que la version instalada se comporta como se documenta aqui.
- `est nuclei reporte` es un informe separado del de `escanear tcp`/`nmap`/auditoria
  web, igual que las demas integraciones de la Fase 3: la unificacion de todos los
  tipos de resultados en un unico informe general queda pendiente para una iteracion
  posterior (ver docs/ROADMAP.md).
- Como con cualquier escaner automatico, un hallazgo puede ser un falso positivo: el
  estado de revision (`nuevo`/`confirmado`/`falso_positivo`) existe precisamente para
  que quien audita lo confirme despues de revisar la evidencia, no AST por si solo.
