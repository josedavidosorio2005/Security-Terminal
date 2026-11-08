# Manual de la interfaz visual (`est interfaz`)

AST incluye, ademas de la terminal de linea de comandos clasica (`est interactivo`), una
interfaz visual completa construida con [Textual](https://github.com/Textualize/textual). Se
abre con:

```bash
est interfaz
```

Es una aplicacion real: usa la misma base de datos, el mismo alcance autorizado y la misma
logica de validacion que la CLI. No es una maqueta ni una demostracion visual.

![Panel de inicio](capturas/01-inicio.svg)

## Distribucion de la pantalla

- **Barra superior**: logo, nombre del producto, version, proyecto activo y sistema operativo.
  El logo es un escudo azul/cian con un simbolo de terminal (`>_`) dentro, sin mascotas ni
  robots. Mientras no exista el recurso grafico oficial, se muestra como texto ASCII (ver
  `eurabyte_security/marca.py`), compatible con cualquier terminal de Windows o Linux.
- **Barra lateral izquierda**: navegacion entre las 14 secciones (ver tabla abajo).
- **Zona central**: el contenido de la seccion seleccionada.
- **Panel derecho**: ayuda contextual del comando que estes escribiendo en la Terminal, datos
  del proyecto actual y el estado de las herramientas externas detectadas.
- **Barra inferior**: proyecto activo, objetivos autorizados, resultados guardados y estado de
  la base de datos.

## Secciones de la barra lateral

| Seccion | Estado | Que hace |
|---|---|---|
| Inicio | Implementada | Panel de bienvenida con un resumen del proyecto activo. |
| Terminal | Implementada | Terminal AST (ver abajo), mas las pestanas Resultados y Ayuda. |
| Proyectos | Implementada | Crear proyectos, listarlos y marcar uno como activo. |
| Alcance | Implementada | Registrar y consultar el alcance autorizado (IP/CIDR). |
| Modulos | Proximamente (Fase 3) | Punto de entrada futuro a los modulos de auditoria. |
| Reconocimiento | Implementada | Descubrimiento de puertos/servicios con Nmap, con boton de cancelar. |
| Analisis web | Implementada | Auditoria de cabeceras HTTP, TLS, cookies y redirecciones, con boton de cancelar. |
| Vulnerabilidades | Implementada | Nuclei: plantillas HTTP aprobadas de bajo impacto, con confirmacion y boton de cancelar. |
| Redes | Implementada | Formulario de comprobacion TCP, con boton de cancelar. |
| Herramientas | Implementada | Detecta si Nmap/Nuclei/OWASP ZAP/tshark estan instalados, y la version de Nmap/Nuclei (no los ejecuta). |
| Resultados | Implementada | Tabla de resultados guardados del proyecto activo. |
| Reportes | Implementada | Genera informes HTML o JSON del proyecto activo. |
| Aprendizaje | Proximamente (Fase 5) | Reservado para laboratorios y contenido educativo. |
| Configuracion | Implementada | Muestra las rutas de datos y permite cambiar el proyecto activo. |

Una seccion marcada como "Proximamente" lo dice explicitamente en pantalla: AST nunca simula
datos ni resultados en una funcionalidad que todavia no existe.

## La Terminal AST

Dentro de la seccion "Terminal" hay tres pestanas:

1. **Terminal AST**: una linea de comandos real, con los mismos comandos que `est interactivo`
   (`proyecto`, `alcance`, `escanear tcp`, `explicar`, `resultados`, `reporte`, `ayuda`).
2. **Resultados**: la misma tabla de resultados que la seccion "Resultados" de la barra lateral.
3. **Ayuda**: la documentacion de todos los comandos, siempre visible y desplazable.

![Terminal AST ejecutando un escaneo](capturas/04-terminal.svg)

### Atajos de teclado en la Terminal

| Tecla | Accion |
|---|---|
| `Tab` | Autocompleta el comando si solo hay una opcion posible (igual que una shell). |
| Mientras escribes | AST sugiere en gris la unica completion posible; `End`/flecha derecha la acepta. |
| `↑` / `↓` | Recorre el historial de comandos escritos en esta sesion. |
| `Enter` | Ejecuta el comando. |

### Atajos generales de la aplicacion

| Tecla | Accion |
|---|---|
| `Tab` / `Shift+Tab` | Mover el foco entre campos (fuera de la Terminal). |
| `↑` `↓` `Enter` | Navegar y seleccionar en la barra lateral y en las tablas. |
| `Ctrl+Q` | Salir de la interfaz visual. |

El raton funciona en toda la interfaz: clic en la barra lateral para navegar, clic en botones,
clic en una fila de una tabla para seleccionarla.

## Secciones con formulario

### Proyectos

Crea un proyecto con el campo de texto y el boton "Crear" (o `Enter`). La tabla muestra todos
los proyectos; el activo aparece marcado con `*`. Para activar otro, selecciona su fila (clic o
`Enter`) y pulsa "Marcar seleccionado como activo".

### Alcance

Registra una IP (`127.0.0.1`) o una red CIDR (`192.168.1.0/24`) autorizada para el proyecto
activo. **Ningun escaneo puede ejecutarse contra un objetivo que no este aqui.**

### Redes (comprobacion TCP)

Formulario con objetivo, puertos, timeout y concurrencia. El boton "Escanear" ejecuta la
comprobacion en segundo plano (no bloquea la interfaz); "Cancelar" detiene la espera del
resultado. Si el objetivo no esta en el alcance autorizado, se muestra un error claro y no se
guarda ningun resultado.

### Reconocimiento (Nmap)

Formulario con objetivo, puertos y una casilla para activar la deteccion de servicios/version
(`-sV`) -- dejala desmarcada salvo que esa comprobacion este explicitamente autorizada. El
boton "Ejecutar Nmap" corre el analisis en segundo plano; "Cancelar" detiene el proceso de
Nmap de verdad (no solo deja de esperar). Requiere tener Nmap instalado (comprueba el panel
"Herramientas"). Igual que "Redes", rechaza objetivos fuera del alcance autorizado y no guarda
nada si se cancela. Cada analisis completado guarda su XML original como evidencia; la ruta se
muestra junto al mensaje de "Analisis completo". Detalle de parametros y limitaciones en
[docs/INTEGRACIONES.md](INTEGRACIONES.md).

### Analisis web

Formulario con selector de proyecto (por defecto, el activo), selector de tipo de analisis
(cabeceras, TLS, cookies o auditoria completa), URL del objetivo, tiempo limite y una casilla
"Seguir redirecciones autorizadas". El boton "Analizar" corre la auditoria en segundo plano;
"Cancelar" detiene la peticion en curso sin guardar ningun hallazgo parcial. La URL debe usar
una direccion IPv4 autorizada en el alcance del proyecto elegido (no se admiten nombres de
dominio en esta entrega). Selecciona una fila de la tabla de hallazgos para ver su explicacion
completa (significado, proposito, riesgo, recomendacion y referencia) debajo. Detalle completo
en [docs/AUDITORIA_WEB.md](AUDITORIA_WEB.md).

### Vulnerabilidades (Nuclei)

Muestra si Nuclei esta instalado (y su version), el proyecto activo y el catalogo de
plantillas aprobadas por AST (cada una con su severidad esperada y una descripcion corta):
marca las que quieras ejecutar. Escribe el objetivo, un tiempo limite opcional y marca la
casilla **"Confirmo que el objetivo esta autorizado"** -- el boton "Analizar" no hace nada
sin esa confirmacion explicita, para que un clic accidental nunca dispare un analisis real.
"Cancelar" detiene el proceso de Nuclei de verdad. Selecciona una fila de la tabla de
hallazgos para ver su detalle completo (severidad, descripcion, evidencia saneada y
recomendacion de mitigacion) y marcarla como "confirmado" o "falso positivo" -- como con
cualquier escaner automatico, revisa la evidencia antes de confirmar un hallazgo. Igual que
"Reconocimiento", rechaza objetivos fuera del alcance autorizado y no guarda nada si se
cancela. Detalle completo (catalogo, limitaciones) en [docs/NUCLEI.md](NUCLEI.md).

### Herramientas

Muestra si Nmap, Nuclei, OWASP ZAP y tshark estan instalados en el sistema (`PATH`), y la
version detectada para Nmap y Nuclei. AST **nunca ejecuta un analisis automaticamente** desde
este panel: solo comprueba presencia/version, de solo lectura.

### Reportes

Elige el formato (HTML o JSON) y pulsa "Generar". El informe se guarda en el directorio de
datos de AST y la ruta exacta aparece en pantalla.

### Configuracion

Muestra las rutas locales (base de datos, historial, directorio de datos) y permite cambiar el
proyecto activo sin volver a la Terminal.

## Interfaz adaptable

Si reduces el tamano de la terminal, AST se adapta automaticamente:

- Por debajo de ~100 columnas, el panel de informacion (derecha) se oculta.
- Por debajo de ~70 columnas, la barra lateral se compacta.

En ningun caso se pierde acceso a una funcionalidad: lo que deja de verse en un panel lateral
siempre sigue disponible desde la Terminal AST (por ejemplo, `explicar tcp` cumple el mismo
papel que el panel de informacion).

![Interfaz adaptada a una terminal estrecha](capturas/06-responsivo-compacto.svg)

## Solucion de problemas comunes

**"No se pudo iniciar la terminal interactiva en esta consola"** (al usar `est interactivo`, no
`est interfaz`): ocurre cuando la entrada/salida esta redirigida o la consola no es compatible
con prompt_toolkit (por ejemplo, algunas configuraciones de Git Bash/MinTTY en Windows). Abre
`cmd.exe` o PowerShell directamente.

**La interfaz visual (`est interfaz`) se ve con colores o bordes raros**: suele ser una
terminal sin soporte de color verdadero (truecolor). Usa Windows Terminal, un emulador moderno
de Linux, o ajusta su configuracion de colores.

**Un escaneo no aparece en Resultados**: comprueba que el objetivo esta registrado en
"Alcance" para el proyecto activo (indicado en la barra superior e inferior); si no lo esta, el
escaneo se rechaza y no se guarda nada.

**Una seccion dice "Proximamente"**: es intencional. Esa funcionalidad todavia no esta
implementada (ver [docs/ROADMAP.md](ROADMAP.md)); no hay ningun dato real que mostrar ahi
todavia.

**Herramienta externa marcada como "No instalada"**: AST solo comprueba si el binario esta en
el `PATH` del sistema; instalala y vuelve a pulsar "Volver a detectar".

## Cancelacion de un escaneo o analisis: semantica exacta

Al pulsar "Cancelar" en el panel "Redes", "Reconocimiento", "Analisis web" o "Vulnerabilidades"
(o al iniciarse un escaneo/analisis nuevo mientras otro seguia en curso):

- La semantica es **todo o nada**: un escaneo o analisis cancelado no guarda ningun resultado
  en la base de datos, ni siquiera de los puertos/hallazgos que ya se habian comprobado antes
  de cancelar, ni evidencia alguna.
- **Redes (TCP)**: deja de abrir conexiones nuevas en cuanto detecta la cancelacion (sondeo
  cada 50ms, no solo cuando un puerto termina), pero las conexiones que ya se habian iniciado
  pueden completarse en segundo plano hasta su propio `--timeout` (limitacion de Python al
  cancelar hilos bloqueados en E/S): simplemente no se usa su resultado.
- **Reconocimiento (Nmap)** y **Vulnerabilidades (Nuclei)**: al cancelar, AST mata el proceso
  externo de verdad (`Popen.kill()`), no se limita a dejar de esperarlo.
- **Analisis web**: deja de leer el cuerpo de la respuesta en cuanto detecta la cancelacion;
  igual que las demas, no persiste ningun hallazgo del analisis cancelado.
- Si inicias un segundo escaneo/analisis antes de que termine el primero, el primero se
  cancela automaticamente y solo el resultado del mas reciente puede llegar a mostrarse en la
  tabla: la interfaz nunca mezcla los resultados de dos ejecuciones.

## Limitaciones conocidas

- `est interfaz` necesita una terminal real (no funciona con la entrada/salida completamente
  redirigida), igual que cualquier aplicacion Textual.
- Las secciones Modulos y Aprendizaje son marcadores de posicion para las Fases 3 y 5: no
  tienen funcionalidad todavia (Analisis web y Vulnerabilidades ya estan implementadas).
- El escudo de marca (barra superior y panel de Inicio) es una alternativa en texto ASCII
  mientras no exista el recurso grafico oficial (ver `eurabyte_security/marca.py`).
- Los resultados de Nmap y de Nuclei todavia no aparecen en `est resultados` ni en
  `est reporte generar` (solo los de `escanear tcp`); se consultan por ahora solo en el
  propio panel/comando de cada uno. Ver [docs/INTEGRACIONES.md](INTEGRACIONES.md) y
  [docs/NUCLEI.md](NUCLEI.md).
