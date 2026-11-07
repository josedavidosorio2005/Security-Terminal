# Referencia de comandos de AST

Esta referencia documenta los comandos realmente implementados en las Fases 1 y 2. Todos los
comandos aceptan `--ayuda` (o `--help`/`-h`) para mostrar su ayuda.

## `est --ayuda`

Muestra la ayuda general y la lista de comandos disponibles.

## `est --version`

Muestra la version instalada de AST.

## `est interfaz`

Abre la interfaz visual completa de AST (Fase 2), construida con Textual: barra lateral de
secciones, terminal integrada, formularios y tablas de resultados, con teclado y raton. Ver el
manual completo en [docs/INTERFAZ.md](INTERFAZ.md).

## `est interactivo`

Abre la terminal interactiva de linea de comandos (Fase 1): autocompletado con Tab, historial de
comandos (flechas arriba/abajo, persistido entre sesiones) y acceso a todos los comandos
descritos aqui sin el prefijo `est`. Para salir: `salir`, `exit`, `quit` o Ctrl+D.

> Requiere una consola real (cmd.exe, PowerShell o una terminal Linux interactiva). Si se
> ejecuta con la entrada/salida redirigida, AST lo detecta y muestra un mensaje explicando como
> ejecutarlo correctamente en lugar de fallar con un error tecnico.

## `est proyecto`

Gestiona proyectos de auditoria.

| Comando | Descripcion |
|---|---|
| `est proyecto crear NOMBRE` | Crea un proyecto y lo marca como activo. |
| `est proyecto listar` | Lista todos los proyectos (el activo se marca con `*`). |
| `est proyecto usar NOMBRE` | Cambia el proyecto activo. |

El nombre solo admite letras, numeros, puntos, guiones y guiones bajos (maximo 64 caracteres).

## `est alcance`

Gestiona el alcance autorizado (IP o red CIDR) de un proyecto. **Ningun escaneo puede ejecutarse
contra un objetivo que no este aqui registrado.**

| Comando | Descripcion |
|---|---|
| `est alcance agregar OBJETIVO [--proyecto NOMBRE]` | Registra una IP (`127.0.0.1`) o red CIDR (`192.168.1.0/24`) autorizada. |
| `est alcance listar [--proyecto NOMBRE]` | Lista el alcance autorizado de un proyecto. |

Si no se indica `--proyecto`, se usa el proyecto activo.

## `est escanear tcp`

Comprueba el estado de una lista de puertos TCP mediante conexion directa (`connect scan`).

```bash
est escanear tcp OBJETIVO --puertos 22,80,443 [--proyecto NOMBRE] [--timeout 1.0] [--concurrencia 50]
```

| Parametro | Descripcion |
|---|---|
| `OBJETIVO` | Direccion IPv4 (no se admiten nombres de dominio en la Fase 1). |
| `--puertos` | Lista separada por comas, maximo 1024 puertos, cada uno entre 1 y 65535. |
| `--proyecto` | Proyecto a usar (por defecto, el activo). |
| `--timeout` | Segundos de espera por puerto, entre 0.1 y 10 (por defecto 1.0). |
| `--concurrencia` | Conexiones simultaneas, entre 1 y 200 (por defecto 50). |

El comando rechaza el escaneo si el objetivo no esta dentro de una red registrada con
`est alcance agregar`. Los resultados (`abierto`, `cerrado` o `error`) se guardan automaticamente.

## `est nmap`

Integracion con Nmap (Fase 3): descubrimiento de puertos y, si se autoriza explicitamente,
identificacion de servicios/version. Detalle completo (parametros, resultados, evidencia,
limitaciones) en [docs/INTEGRACIONES.md](INTEGRACIONES.md).

```bash
est nmap version
est nmap descubrir OBJETIVO --puertos 22,80,443 [--proyecto NOMBRE] \
    [--deteccion-version] [--tiempo-limite 120]
```

| Comando | Descripcion |
|---|---|
| `est nmap version` | Muestra si Nmap esta instalado y su version. |
| `est nmap descubrir OBJETIVO --puertos ...` | Ejecuta Nmap dentro del alcance autorizado. |

Al igual que `escanear tcp`, rechaza cualquier objetivo que no este en el alcance autorizado del
proyecto. Requiere tener Nmap instalado.

## `est explicar TEMA`

Muestra una explicacion en espanol de un comando y sus parametros. Temas disponibles: `proyecto`,
`alcance`, `tcp`, `escanear`, `nmap`, `resultados`, `reporte`, `interactivo`, `interfaz`.

```bash
est explicar tcp
```

## `est resultados`

Muestra los resultados de escaneos guardados.

```bash
est resultados [--proyecto NOMBRE] [--limite 50]
```

## `est reporte generar`

Genera un informe a partir de los resultados guardados de un proyecto.

```bash
est reporte generar --formato html|json [--proyecto NOMBRE] [--salida RUTA]
```

Si no se indica `--salida`, el informe se guarda en el directorio de datos de EST
(`~/.eurabyte_security/reportes/`, o `$EST_HOME/reportes/`) con un nombre que incluye el
proyecto y la fecha/hora.
