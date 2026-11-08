# Modelo de seguridad y autorizacion de AST

AST es una herramienta de pentesting. Esta diseñada para minimizar el riesgo de que alguien la
use, por error o a proposito, contra un sistema que no tiene autorizacion para auditar.

## Principios

1. **Todo objetivo debe estar registrado explicitamente.** Antes de poder escanear una IP o red,
   hay que agregarla al alcance de un proyecto con `est alcance agregar`. El comando
   `est escanear tcp` comprueba el alcance **antes** de abrir ninguna conexion y rechaza
   cualquier objetivo que no este autorizado (`ErrorFueraDeAlcance`).
2. **Las comprobaciones de red son controladas, no masivas.**
   - Solo se aceptan direcciones IPv4 literales como objetivo (no nombres de dominio), para que
     el usuario sepa exactamente que IP se va a tocar.
   - Un escaneo admite como maximo 1024 puertos.
   - El tiempo de espera por puerto esta acotado entre 0.1 y 10 segundos.
   - La concurrencia esta acotada entre 1 y 200 conexiones simultaneas.
   - Estos limites existen para evitar que un error de tipeo (por ejemplo, olvidar `--puertos`
     o escribir un rango enorme) genere trafico de red descontrolado.
3. **Ninguna prueba de las pruebas automatizadas toca redes de terceros.** Los tests usan
   siempre `127.0.0.1` con sockets locales abiertos por la propia suite.
4. **El asistente de IA (Fase 4) nunca ejecuta comandos por si mismo.** Toda sugerencia de
   comando que proponga debe mostrarse al usuario para su revision y aprobacion explicita antes
   de ejecutarse (ver `assistant/base.py`, `SugerenciaAsistente.requiere_autorizacion`).
5. **No se incluyen credenciales ni secretos en el repositorio.** La configuracion local de AST
   (proyecto activo, historial, base de datos) vive en el directorio de datos del usuario
   (`~/.eurabyte_security` o `$EST_HOME`), nunca en el repositorio ni en el control de versiones.
6. **La interfaz visual (`est interfaz`) no ejecuta comandos mediante un shell del sistema.**
   La Terminal AST integrada interpreta el texto escrito y llama directamente a la misma logica
   interna que la CLI; no hay invocacion de `subprocess`/`os.system` sobre lo que el usuario
   escribe. Las mismas comprobaciones de alcance y los mismos limites de la Fase 1 se aplican
   sin cambios.
7. **Las integraciones externas (Nmap y las que sigan) tampoco usan un shell.**
   `integrations/proceso.py:ejecutar_proceso()` es el unico punto de la aplicacion que invoca un
   binario externo, siempre con `subprocess.Popen(..., shell=False)` y una lista de argumentos
   ya validados -- nunca una cadena construida por interpolacion. Cada ejecucion tiene limite de
   tiempo y puede cancelarse de verdad (`Popen.kill()`), y el alcance autorizado se comprueba
   **antes** de invocar la herramienta, igual que con `escanear tcp`. La ruta del binario se
   resuelve una sola vez (ruta absoluta) y es esa misma ruta la que se ejecuta, para no dejar una
   segunda busqueda de PATH en manos del sistema operativo al lanzar el proceso; en Windows,
   ademas, se desactiva explicitamente que esa busqueda incluya el directorio de trabajo actual
   (mitiga "binary planting": que alguien coloque un ejecutable con el mismo nombre en esa
   carpeta para que se ejecute en vez del binario real).
8. **Cualquier texto que pueda venir del objetivo auditado (no solo del usuario) se escapa
   antes de mostrarse.** Los campos que una integracion externa obtiene del sistema escaneado
   (p. ej. el nombre de servicio o la version que Nmap identifica en el objetivo) pasan por
   `ui/consola.py:texto_seguro` antes de mostrarse con marcado Rich, igual que el texto que
   escribe el propio usuario: un objetivo auditado no deja de ser una fuente no confiable.
9. **Ninguna integracion activa esta habilitada por defecto mas alla de lo minimo.** La
   deteccion de servicios/version de Nmap (`-sV`) requiere activarla explicitamente
   (`--deteccion-version`); el motor esta preparado para que las futuras integraciones
   (OWASP ZAP) sigan el mismo principio: nunca plantillas intrusivas ni ataques activos
   por defecto.
10. **La auditoria web (`est web ...`) comprueba el alcance antes de cualquier peticion y nunca
   sigue una redireccion sin verificarla primero.** `modules/web/cliente.py` usa `http.client`
   directamente (nunca `urllib.request` ni una libreria de terceros) precisamente para no
   seguir redirecciones automaticamente ni leer `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` del
   entorno. Una redireccion solo se sigue si se pide explicitamente
   (`--seguir-redirecciones`) y su destino es, a la vez, una IP IPv4 literal (nunca un nombre
   de dominio, que implicaria una resolucion DNS fuera del control del usuario) y esta dentro
   del alcance autorizado del proyecto; en cualquier otro caso AST se detiene y lo reporta como
   hallazgo en vez de arriesgarse a un SSRF. Por la misma razon, esta version solo admite
   direcciones IPv4 literales como objetivo (ver `core/validation.py:validar_url_web`), no
   nombres de dominio.
11. **La auditoria TLS nunca desactiva la validacion para fingir un resultado exitoso.**
    `modules/web/tls.py` intenta siempre una conexion con verificacion completa primero; si
    falla, solo abre una segunda conexion para leer los metadatos reales del certificado
    (fecha de vencimiento, emisor...), y el resultado deja explicito que la confianza no se
    pudo verificar y por que, distinguiendo esos metadatos de los que si fueron verificados.
12. **Los valores de las cookies nunca se registran.** `modules/web/cookies.py` solo guarda y
    muestra el nombre de cada cookie y sus atributos (`Secure`, `HttpOnly`, `SameSite`...); el
    valor real jamas aparece en un hallazgo, en un log ni en un informe exportado.
13. **Las URLs que suelen llevar un secreto (credenciales en el host, token/contrasena/API key
    en la cadena de consulta o en el fragmento) se ocultan antes de mostrarse o guardarse.**
    `core/redaccion.py:redactar_url()` elimina las credenciales del host y oculta el valor de
    los parametros sensibles (por coincidencia de subcadena del nombre, no solo una lista
    exacta) tanto en la cadena de consulta como en el fragmento, en la URL del objetivo, en el
    destino de una redireccion y en **cualquier** mensaje de error que la interpole --
    incluidos los que lanza la propia validacion de entrada
    (`core/validation.py:validar_url_web`: esquema no admitido, credenciales en la URL, puerto
    invalido, host vacio, URL no interpretable) -- en la CLI/TUI, en lo que se persiste en
    `resultados_web` y en los informes exportados. La peticion real contra el objetivo siempre
    usa la URL completa sin modificar (la redaccion es solo para lo que se muestra/guarda,
    nunca para lo que se envia por la red). `redactar_url()` vive en `core/` (no en
    `modules/web/`) para que `core/validation.py` -- el punto de control de seguridad comun a
    toda la aplicacion -- pueda reutilizarla sin que `core/` termine dependiendo de `modules/`.
14. **Los limites se documentan segun lo que realmente garantizan.** El tiempo limite de una
    peticion de auditoria web (`--tiempo-limite`) es estricto (lo impone el `timeout` del
    socket); el presupuesto de tiempo total de toda una auditoria (al seguir redirecciones,
    `modules/web/auditor.py:TIEMPO_LIMITE_TOTAL_MAXIMO`) es deliberadamente un presupuesto
    cooperativo, documentado como tal: reduce el limite de la siguiente peticion a lo que
    queda del presupuesto, pero no puede evitar una pequena demora adicional fuera del control
    de AST (resolucion de la conexion, negociacion TLS, el planificador del sistema operativo).
15. **Nuclei solo ejecuta un catalogo cerrado de plantillas HTTP de bajo impacto, escritas por
   AURABYTE, nunca una ruta de plantilla que indique el usuario.** `est nuclei analizar` solo
   acepta identificadores del catalogo aprobado (`integrations/nuclei.py:PLANTILLAS_APROBADAS`);
   no existe ninguna opcion para pasar un archivo `.yaml` arbitrario ni para usar las plantillas
   publicas de la comunidad. Cada plantilla se vuelve a validar estructuralmente en **cada
   ejecucion** (`validar_plantilla_estructura()`), no solo cuando se escribio, con una **lista
   blanca estricta** (campos de nivel superior/de `info`/de bloque HTTP/de matcher conocidos,
   metodo `GET`, como maximo 4 rutas exclusivamente relativas a `{{BaseURL}}`, nunca una URL
   absoluta a otro host): se rechaza cualquier campo que AST no reconozca, no solo los que estan
   en una lista negra concreta. Ademas, cada plantilla aprobada tiene un **hash SHA-256 fijado**
   (`InfoPlantillaNuclei.sha256`): si el archivo instalado no coincide, se rechaza la ejecucion;
   cambiar ese hash exige revisar de nuevo todo el contenido a mano. Para evitar una ventana
   entre "se valido este archivo" y "se ejecuto este archivo" (TOCTOU), AST nunca le pasa a
   Nuclei la ruta original instalada: lee el contenido una vez, lo valida, y ejecuta una copia
   nueva en un directorio temporal exclusivo de esa ejecucion. Se desactivan ademas
   explicitamente Interactsh/OAST (`-ni`) y la comprobacion de actualizaciones (`-duc`) al
   invocar el binario, y el proceso se invoca con un entorno aislado (sin variables de proxy ni
   `NUCLEI_*`, con `HOME`/`XDG_CONFIG_HOME`/`APPDATA` redirigidos a un directorio vacio) para que
   una configuracion, proxy o perfil que el usuario ya tuviera guardado en su sistema nunca se
   aplique silenciosamente. Un codigo de salida de Nuclei distinto de cero se trata siempre como
   un fallo real, nunca como "analisis exitoso sin hallazgos", y nunca deja un resultado parcial
   guardado. Ver [docs/NUCLEI.md](NUCLEI.md) para el detalle completo, incluidas las garantias
   que este diseno **no** puede ofrecer (no es una sandbox de red a nivel de sistema operativo).
16. **Nuclei nunca guarda el trafico HTTP completo ni cabeceras de autenticacion/cookies, y
    trata toda su salida JSONL como no confiable.** El `request`/`response`/`curl-command` que
    Nuclei incluye en su salida se descartan explicitamente al interpretarla
    (`integrations/nuclei.py:_analizar_jsonl_nuclei()`); lo que se guarda es un resumen propio
    (donde se detecto el hallazgo, que matcher lo activo), nunca el trafico original, con una
    longitud maxima por campo. Solo se acepta un `template-id` que pertenezca exactamente al
    conjunto de plantillas que AST le pidio ejecutar en esa misma invocacion (nunca "cualquier
    id del catalogo"); una linea mas larga de lo esperado, o una salida JSONL completa por
    encima de un tamano maximo, se descarta o se rechaza sin usarla. Los campos `matched-at`/
    `host`/`description`/`matcher-name`, y el detalle de un error de proceso, se **redactan**
    (no solo se truncan) con el mismo mecanismo que usa la auditoria web
    (`core/redaccion.py:redactar_url`) o con un redactor de texto libre propio para los campos
    que no son una URL.
17. **OWASP ZAP solo ofrece analisis pasivo: nunca active scan, spider, ajaxSpider ni
    fuzzing.** `integrations/zap.py`/`modules/vulnerability/zap.py` no exponen ninguna
    opcion para activar esas funciones; la unica peticion que llega al objetivo es la que
    la propia API de ZAP hace a traves de `core/action/accessUrl`
    (`followRedirects=false`), que alimenta el analizador pasivo sin explorar nada mas. El
    endpoint de administracion de ZAP debe ser loopback HTTP **literal**
    (`http://127.0.0.1:<puerto>`): se rechaza explicitamente `localhost` (su resolucion
    depende del archivo de hosts del sistema, no es una garantia), cualquier host remoto y
    cualquier esquema distinto de `http` -- AST nunca administra una instancia de ZAP
    remota. La API key se lee de la variable de entorno `EST_ZAP_API_KEY` (nunca de un
    archivo versionado ni de un argumento visible en el historial del shell) y nunca
    aparece en un mensaje de error, log o informe. Las alertas se consultan filtradas por
    el objetivo auditado (`baseurl`), nunca todas las de la sesion compartida de ZAP: una
    misma instancia puede tener alertas de otras auditorias en marcha, y AST nunca las
    mezcla con las propias ni borra sesiones o alertas ajenas. Toda la salida de ZAP se
    trata como no confiable: los campos de texto libre y la URL de cada alerta se
    redactan y se acotan en longitud, igual que la salida de Nuclei. Ver
    [docs/OWASP_ZAP.md](OWASP_ZAP.md) para el detalle completo, incluidas las garantias
    que este diseno **no** puede ofrecer (no es una sandbox de red a nivel de sistema
    operativo, y una instancia de ZAP compartida sigue acumulando esa unica peticion en su
    historial, aunque AST nunca la use para mezclar resultados).

## Que hacer si encuentras una vulnerabilidad en AST

Ver [SECURITY.md](../SECURITY.md).

## Buenas practicas para quien use AST

- Solicita autorizacion por escrito antes de auditar cualquier sistema que no sea de tu
  propiedad.
- Registra el alcance exacto que te autorizaron, ni mas ni menos.
- Guarda las evidencias (resultados, informes) en un lugar seguro y bórralas cuando ya no las
  necesites; AST no las cifra por defecto.
- No ejecutes integraciones externas (Nmap, Nuclei, OWASP ZAP) ni auditorias web contra
  objetivos fuera del alcance acordado con el cliente o la organizacion.
- Al usar `--deteccion-version` con Nmap, confirma primero que esa comprobacion en concreto
  esta autorizada; no es el comportamiento por defecto.
- Al usar `--seguir-redirecciones` en `est web`, recuerda que AST solo sigue el salto si el
  destino ya esta autorizado en el alcance; si necesitas auditar un destino nuevo, agregalo
  primero al alcance en vez de depender de que la redireccion lo cubra.
- Un hallazgo de Nuclei o de OWASP ZAP puede ser un falso positivo: revisa la evidencia antes
  de confirmarlo (`est nuclei revisar ID --estado ...` / `est zap revisar ID --estado ...`),
  no lo asumas como cierto solo porque el escaner lo reporto.
- Si usas OWASP ZAP con una instancia compartida con otras auditorias, recuerda que esa
  instancia sigue siendo responsabilidad de quien la administra: AST solo controla lo que
  el propio AST le pide, no la configuracion ni el estado previo de ZAP.
