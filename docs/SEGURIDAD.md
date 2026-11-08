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
   **antes** de invocar la herramienta, igual que con `escanear tcp`.
8. **Ninguna integracion activa esta habilitada por defecto mas alla de lo minimo.** La
   deteccion de servicios/version de Nmap (`-sV`) requiere activarla explicitamente
   (`--deteccion-version`); el motor esta preparado para que las futuras integraciones
   (OWASP ZAP) sigan el mismo principio: nunca plantillas intrusivas ni ataques activos por
   defecto.
9. **Nuclei solo ejecuta un catalogo cerrado de plantillas HTTP de bajo impacto, escritas por
   AURABYTE, nunca una ruta de plantilla que indique el usuario.** `est nuclei analizar` solo
   acepta identificadores del catalogo aprobado (`integrations/nuclei.py:PLANTILLAS_APROBADAS`);
   no existe ninguna opcion para pasar un archivo `.yaml` arbitrario ni para usar las plantillas
   publicas de la comunidad. Ademas, cada plantilla se vuelve a validar estructuralmente en
   **cada ejecucion** (`validar_plantilla_estructura()`), no solo cuando se escribio: se rechaza
   cualquier plantilla que declare un protocolo distinto de HTTP, que siga redirecciones o que
   mencione Interactsh/OAST, por si el archivo cambiara despues de instalar AST. Se desactivan
   ademas explicitamente Interactsh/OAST (`-ni`) y la comprobacion de actualizaciones (`-duc`)
   al invocar el binario. Ver [docs/NUCLEI.md](NUCLEI.md) para el detalle completo, incluidas
   las garantias que este diseno **no** puede ofrecer (no es una sandbox de red a nivel de
   sistema operativo).
10. **Nuclei nunca guarda el trafico HTTP completo ni cabeceras de autenticacion/cookies.** El
    `request`/`response`/`curl-command` que Nuclei incluye en su salida JSONL se descartan
    explicitamente al interpretarla (`integrations/nuclei.py:_analizar_jsonl_nuclei()`); lo que
    se guarda es un resumen propio (donde se detecto el hallazgo, que matcher lo activo), nunca
    el trafico original.

## Que hacer si encuentras una vulnerabilidad en AST

Ver [SECURITY.md](../SECURITY.md).

## Buenas practicas para quien use AST

- Solicita autorizacion por escrito antes de auditar cualquier sistema que no sea de tu
  propiedad.
- Registra el alcance exacto que te autorizaron, ni mas ni menos.
- Guarda las evidencias (resultados, informes) en un lugar seguro y bórralas cuando ya no las
  necesites; AST no las cifra por defecto.
- No ejecutes integraciones externas (Nmap, Nuclei y las que sigan: OWASP ZAP) contra objetivos
  fuera del alcance acordado con el cliente o la organizacion.
- Al usar `--deteccion-version` con Nmap, confirma primero que esa comprobacion en concreto
  esta autorizada; no es el comportamiento por defecto.
- Un hallazgo de Nuclei puede ser un falso positivo: revisa la evidencia antes de confirmarlo
  (`est nuclei revisar ID --estado confirmado|falso_positivo`), no lo asumas como cierto solo
  porque el escaner lo reporto.
