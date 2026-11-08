# Arquitectura de AST

Este documento describe la organizacion del codigo de AURABYTE Security Terminal (AST) y la
responsabilidad de cada paquete. El objetivo es mantener una separacion clara entre interfaz,
logica de negocio e integraciones externas, para que el proyecto siga siendo facil de ampliar.

> El paquete Python sigue llamandose `eurabyte_security` por compatibilidad con instalaciones
> de la Fase 1 (ver CLAUDE.md). La identidad de marca (AURABYTE / AST) vive en
> `eurabyte_security/marca.py`.

## Estructura de paquetes

```text
src/eurabyte_security/
├── marca.py        Identidad de marca (nombre, logo, banner ASCII).
├── cli/            Ensamblaje de la aplicacion Typer (comando `est`).
├── commands/       Logica de cada comando + su exposicion como subcomando Typer.
├── core/           Configuracion (rutas, proyecto activo), validaciones, errores comunes y
│                   redaccion.py (oculta secretos en URLs mostradas/guardadas/en errores).
├── modules/
│   ├── network/    Comprobaciones de red (Fase 1: escaneo TCP basico).
│   ├── web/        Auditoria web (Fase 3, Paso 3): cabeceras HTTP, TLS, cookies,
│   │               redirecciones. Detalle en docs/AUDITORIA_WEB.md.
│   ├── vulnerability/  Analisis de vulnerabilidades que no son un binario invocado como
│   │               subproceso. Nuclei (subproceso) vive en integrations/, no aqui; ZAP
│   │               (servicio HTTP ya en marcha, nunca un subproceso) si vive aqui --
│   │               ver vulnerability/zap.py y docs/OWASP_ZAP.md.
│   └── reporting/  Construccion de informes (HTML/JSON) a partir de resultados.
├── integrations/   Motor de integraciones (Fase 3). Detalle en docs/INTEGRACIONES.md.
│   ├── base.py     AdaptadorExterno: contrato comun (deteccion, version, validacion...).
│   ├── proceso.py  Unico punto de ejecucion real de un binario externo (sin shell, con
│   │               limite de tiempo y cancelacion mediante Popen.kill()).
│   ├── deteccion.py  Deteccion/version de las herramientas (nunca las ejecuta de verdad).
│   ├── nmap.py     Primer adaptador concreto: descubrimiento de puertos y servicios.
│   ├── nuclei.py   Segundo adaptador: solo plantillas HTTP aprobadas (ver docs/NUCLEI.md).
│   ├── plantillas_nuclei/*.yaml   Catalogo de plantillas que nuclei.py puede ejecutar.
│   └── zap.py      Fachada de OWASP ZAP (ver docs/OWASP_ZAP.md): a diferencia de los
│                    anteriores, no hereda de AdaptadorExterno -- ZAP no es un binario
│                    que AST invoque, sino un servicio HTTP que el usuario ya tiene
│                    corriendo; la logica real vive en modules/vulnerability/zap.py.
├── assistant/      Contrato base del futuro asistente de IA. Fase 4.
├── storage/        Repositorio SQLite (proyectos, alcances, resultados).
└── ui/
    ├── consola.py  Consola enriquecida (Rich) compartida por la CLI.
    ├── repl.py     Terminal interactiva de linea de comandos (`est interactivo`).
    └── tui/        Interfaz visual Textual (`est interfaz`, Fase 2). Ver mas abajo.
```

## La interfaz visual (`ui/tui/`, Fase 2)

```text
ui/tui/
├── app.py              AuraByteApp: layout, navegacion y eventos globales.
├── estilos.tcss        Paleta y estilos (Textual CSS).
├── estado.py           Snapshot de estado (proyecto activo, conteos) para la UI.
├── motor_comandos.py   Interprete de la Terminal AST: despacha texto a commands/*.
└── widgets/
    ├── navegacion.py   Encabezado, barra lateral y barra de estado.
    ├── terminal.py     Entrada con historial/autocompletado y panel de ayuda contextual.
    └── paneles.py      Un panel por seccion (Proyectos, Alcance, Redes, Resultados...).
```

`AuraByteApp` reutiliza exactamente la misma logica que la CLI: `motor_comandos.py` y los
paneles importan las funciones puras de `commands/*.py` (las mismas que usa `cli/app.py`), no
una copia. Las operaciones de red (escaneo TCP) se ejecutan en workers de Textual
(`@work(thread=True)`) para no bloquear la interfaz.

## Flujo de una operacion (ejemplo: `est escanear tcp`)

1. **`cli/app.py`** registra el sub-comando `escanear` (definido en `commands/escanear.py`) en
   la aplicacion Typer raiz.
2. **`commands/escanear.py`** valida la entrada (`core/validation.py`), resuelve el proyecto
   activo (`commands/_comun.py`), comprueba que el objetivo esta dentro del alcance autorizado
   (`storage/database.py`) y delega la comprobacion real al modulo de red.
3. **`modules/network/tcp_scanner.py`** ejecuta la comprobacion TCP con concurrencia y tiempo de
   espera acotados, sin conocer nada sobre proyectos, CLI ni base de datos.
4. El resultado se persiste en SQLite a traves de **`storage/database.py`** y se muestra en
   pantalla con Rich (**`ui/consola.py`**).

## Cancelacion de un escaneo (panel "Redes" de la TUI)

`escanear_tcp` y `escanear_puertos_tcp` aceptan un parametro opcional `debe_cancelar` (un
callable sin argumentos que devuelve `bool`). El panel "Redes" lo conecta a
`worker.is_cancelled` del worker de Textual que ejecuta el escaneo:

1. **Durante el escaneo**, `escanear_puertos_tcp` sondea `debe_cancelar()` cada 50ms
   (`concurrent.futures.wait(..., timeout=0.05)`), **no solo cuando un puerto termina**: si
   todos los puertos en curso estuvieran bloqueados (un objetivo que no responde, por ejemplo),
   la cancelacion se detecta igual, en ese plazo. Al detectarla, cancela las conexiones que
   todavia no se habian iniciado (no abre mas sockets, nunca mas de lo que el limite de
   concurrencia ya habia permitido empezar) y deja de esperar resultados.
2. **Justo antes de persistir**, `escanear_tcp` vuelve a consultar `debe_cancelar()`. Si es
   verdadero, lanza `ErrorEscaneoCancelado` (`core/errores.py`) **sin escribir nada** en la
   base de datos: la semantica es todo-o-nada, nunca un guardado parcial.
3. **En la interfaz**, cada escaneo que se inicia desde el panel "Redes" (o desde
   "Reconocimiento", para Nmap) recibe un numero de secuencia propio (`_secuencia`); solo el
   resultado del escaneo con el numero de secuencia mas reciente puede actualizar la tabla
   (`_mostrar_resultados`), lo que impide que dos escaneos solapados mezclen sus resultados en
   pantalla, incluso si el mas antiguo termina despues del mas nuevo (los hilos no se pueden
   interrumpir de forma forzosa en Python).

Quien use `escanear_tcp`/`escanear_puertos_tcp` sin pasar `debe_cancelar` (la CLI, el REPL y
`motor_comandos.py`) conserva el comportamiento anterior sin cambios: el parametro es
estrictamente opcional.

## Persistencia atomica

`storage/database.py:BaseDatos.agregar_resultados()` (y su equivalente
`agregar_resultados_nmap()`) escriben **todos** los resultados de un escaneo en una sola
transaccion: una unica conexion SQLite, un unico `commit()` al final. Si algo falla a mitad de
camino (una excepcion, una cancelacion detectada tarde...), la conexion se cierra sin llegar a
ese `commit()` y SQLite descarta toda la transaccion -- no queda ningun resultado parcial. Ver
`tests/test_fase3_robustez.py` para la prueba que fuerza un fallo a mitad de la escritura y
comprueba que no queda nada guardado.

## Integraciones externas: flujo (ejemplo: `est nmap descubrir`)

1. **`cli/app.py`** registra `nmap` (`commands/nmap.py`) junto a los demas comandos.
2. **`commands/nmap.py:ejecutar_nmap()`** valida el objetivo y comprueba el alcance autorizado
   **antes** de tocar nada (igual que `escanear_tcp`): ningun objetivo fuera de alcance llega a
   invocar Nmap.
3. **`integrations/nmap.py:AdaptadorNmap`** construye los argumentos (`-sT -Pn -p ... -oX ...`,
   mas `-sV` si se autorizo explicitamente) y delega la ejecucion real a
   **`integrations/proceso.py:ejecutar_proceso()`** (el unico punto de la app que invoca un
   proceso externo, sin shell, con limite de tiempo y cancelacion real via `Popen.kill()`).
4. El adaptador lee el XML resultante con `defusedxml` y lo convierte en `PuertoNmap`
   (dataclasses propias de AST, no la salida cruda de Nmap).
5. `commands/nmap.py` persiste los resultados (atomicamente, ver arriba) y guarda el XML
   original como evidencia en `core/config.py:ruta_evidencias("nmap")`.

Nuclei y OWASP ZAP siguen el mismo patron: adaptador en `integrations/`, comando/orquestacion
en `commands/` (donde vive la verificacion de alcance), nunca al reves.

## Auditoria web: flujo (ejemplo: `est web auditar`)

La auditoria web (`modules/web/`) no invoca ningun binario externo -- es trafico HTTP(S) hecho
por la propia aplicacion con `http.client` -- por lo que no pasa por `integrations/`, pero
sigue la misma separacion: la verificacion de alcance vive en `commands/web.py`, nunca en
`modules/web/`.

1. **`commands/web.py:auditar_web()`** valida la URL (`core/validation.py:validar_url_web` --
   solo IPv4 literal, esquemas `http`/`https`) y comprueba el alcance autorizado **antes** de
   cualquier peticion.
2. **`modules/web/auditor.py:ejecutar_auditoria_web()`** hace una unica peticion
   (`modules/web/cliente.py:realizar_peticion()`, sin seguir redirecciones ni leer proxies del
   entorno) y, a partir de esa misma respuesta, evalua cabeceras (`cabeceras.py`), TLS
   (`tls.py`) y cookies (`cookies.py`). Si hay una redireccion y se pidio seguirla
   explicitamente, `redirecciones.py` valida que el destino sea una IP autorizada antes de
   hacer una segunda peticion (maximo 5 saltos); si no lo es, se detiene y lo reporta como
   hallazgo en vez de seguirla (proteccion contra SSRF).
3. `commands/web.py` persiste los hallazgos atomicamente en `resultados_web` (ver
   `storage/database.py`), igual que el resto de comandos.

Detalle completo (que evalua cada categoria, por que la severidad nunca es automatica, como se
protege contra SSRF) en [docs/AUDITORIA_WEB.md](AUDITORIA_WEB.md).

## Nuclei: una capa extra de validacion sobre el mismo patron

`integrations/nuclei.py:AdaptadorNuclei` sigue el mismo flujo que Nmap, con una diferencia
importante: Nuclei puede ejecutar practicamente cualquier cosa segun la plantilla que se le
indique, asi que AST nunca acepta una ruta de plantilla del usuario. Solo permite elegir, por
identificador, entre un catalogo reducido (`PLANTILLAS_APROBADAS`) de plantillas que AURABYTE
escribio y distribuye con el paquete (`integrations/plantillas_nuclei/*.yaml`). Antes de cada
ejecucion, `validar_plantilla_estructura()` vuelve a leer el archivo y rechaza cualquier
plantilla que declare un protocolo distinto de `http`, que siga redirecciones o que mencione
Interactsh/OAST -- una comprobacion en tiempo de ejecucion, no solo una revision manual que se
hizo una vez. Ver [docs/NUCLEI.md](NUCLEI.md) para el detalle completo.

## OWASP ZAP: un servicio HTTP ya en marcha, no un subproceso

`integrations/zap.py:AdaptadorZAP` tiene una forma similar a los demas adaptadores
(`info()`, `validar_parametros()`, `ejecutar()`), pero no hereda de
`integrations/base.py:AdaptadorExterno`: ZAP no es un binario que AST resuelva con
`shutil.which` y ejecute sin shell, sino un servicio HTTP que el usuario ya tiene corriendo
por su cuenta, con su API REST expuesta en loopback. La logica real (validacion del
endpoint, llamadas HTTP, analisis pasivo) vive en `modules/vulnerability/zap.py`, que habla
con esa API con `http.client` directo -- el mismo patron que `modules/web/cliente.py` usa
para hablar con el objetivo auditado, sin `urllib.request` ni variables de entorno de
proxy. Esta integracion nunca usa `active scan`, `spider`, `ajaxSpider` ni fuzzing: la unica
peticion que llega al objetivo es la que la propia API de ZAP hace a traves de
`core/action/accessUrl` (`followRedirects=false`), que alimenta su analizador pasivo sin
explorar nada mas. Ver [docs/OWASP_ZAP.md](OWASP_ZAP.md) para el detalle completo.

## Texto seguro frente al marcado Rich

Cualquier texto que pueda contener lo que el usuario escribio (un objetivo invalido, un tema
desconocido, una ruta...) debe pasar por `ui/consola.py:texto_seguro` antes de mostrarse con
Rich/Textual (`markup` habilitado), tanto en la CLI (`mostrar_error`/`mostrar_exito`/
`mostrar_aviso`) como en la TUI (`RichLog.write`, `Static.update`, celdas de `DataTable`). Sin
este escape, un corchete sin cerrar en la entrada del usuario puede lanzar
`rich.errors.MarkupError` (ver `tests/test_tui_cancelacion_robustez.py`), y una secuencia de
corchetes balanceada puede interpretarse como una etiqueta de estilo real.

Este mismo patron (validar -> resolver proyecto -> ejecutar logica de modulo -> persistir ->
mostrar) se repite en los demas comandos (`proyecto`, `alcance`, `resultados`, `reporte`).

## Por que esta separacion

- **Testabilidad**: `core/validation.py`, `storage/database.py` y
  `modules/network/tcp_scanner.py` no dependen de Typer ni de Rich, por lo que se prueban con
  pytest de forma aislada y rapida (ver `tests/`).
- **Reutilizacion entre interfaces**: la terminal interactiva (`ui/repl.py`) reutiliza el mismo
  arbol de comandos Click/Typer que la CLI no interactiva, por lo que la logica de negocio nunca
  se duplica.
- **Errores controlados**: toda la logica de negocio lanza excepciones de `core/errores.py`
  (`ErrorEST` y subclases) en lugar de llamar a `sys.exit`. Solo `cli/app.py` y `ui/repl.py`
  deciden como mostrar esos errores al usuario.
- **Puntos de extension explicitos**: `integrations/base.py` y `assistant/base.py` documentan el
  contrato que deberan cumplir las futuras integraciones (Fase 3) y el asistente de IA (Fase 4),
  sin necesidad de tocar el resto del codigo cuando se implementen.

## Persistencia

Toda la informacion vive en SQLite, en un unico archivo bajo el directorio de datos del usuario
(`~/.eurabyte_security/est.db` por defecto, o `$EST_HOME/est.db` si se define esa variable de
entorno). El esquema tiene las tablas `proyectos`, `alcances`, `resultados` (escaneo TCP),
`resultados_nmap`, `resultados_web`, `resultados_nuclei` y `resultados_zap` (ver
`storage/database.py`). Cada herramienta sigue siendo propietaria de su propia tabla y de su
propio metodo `agregar_resultados*`/`listar_resultados*`: `BaseDatos.listar_resultados_unificados()`
no crea ninguna tabla nueva, es una proyeccion de solo lectura que combina las cinco en
`ResultadoUnificado` (ver `commands/resultados.py` y `commands/reporte.py`, que la usan para
`est resultados` y el informe global de `est reporte generar` respectivamente, documentado en
[docs/COMANDOS.md](COMANDOS.md) y [docs/SEGURIDAD.md](SEGURIDAD.md)).
