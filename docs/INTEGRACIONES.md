# Integraciones externas (Fase 3)

AST integra herramientas de pentesting reales como procesos externos controlados, nunca como
simulaciones. Este documento describe el motor comun a todas las integraciones y, mas abajo,
cada herramienta concreta: sus parametros, el formato de sus resultados y sus limitaciones
conocidas.

## El motor de integraciones

Arquitectura en `src/eurabyte_security/integrations/`:

```text
integrations/
├── base.py       Clase AdaptadorExterno: contrato comun a cualquier integracion.
├── proceso.py    ejecutar_proceso(): unico punto de ejecucion real de un binario externo.
├── deteccion.py  Deteccion de version/presencia para el panel "Herramientas" (nunca ejecuta).
└── nmap.py       Primer adaptador concreto: AdaptadorNmap.
```

### Reglas que cumple cualquier adaptador

1. **Deteccion de la herramienta**: `AdaptadorExterno.esta_instalado()` comprueba el binario en
   el `PATH` (`shutil.which`); `obtener_version()` ejecuta `<comando> --version` (configurable)
   de forma segura y de solo lectura.
2. **Validacion de parametros**: cada adaptador implementa `validar_parametros(...)`, que
   reutiliza las mismas validaciones de `core/validation.py` que usa el resto de AST (objetivo
   IPv4, lista de puertos, limites de tiempo).
3. **Ejecucion controlada, sin shell**: `integrations/proceso.py:ejecutar_proceso()` es el
   **unico** punto de la aplicacion que invoca un proceso externo. Siempre recibe una lista de
   argumentos (`subprocess.Popen(comando, shell=False, ...)`), nunca una cadena construida por
   interpolacion: un argumento como `"127.0.0.1; rm -rf /"` llega al binario como un unico
   argumento literal, no se interpreta.
4. **Limites de tiempo y cancelacion real**: `ejecutar_proceso()` sondea cada 0.1s si se agoto
   el tiempo limite o si se solicito cancelar (`debe_cancelar`); en ambos casos mata el proceso
   (`Popen.kill()`) en vez de esperar a que termine por si mismo.
5. **Captura de stdout/stderr**: siempre capturados; nunca se descartan en caso de error, para
   poder mostrar un mensaje util.
6. **Normalizacion de resultados**: cada adaptador devuelve sus propias dataclasses (no la
   salida cruda de la herramienta) para que el resto de AST (CLI, TUI, informes) no necesite
   saber nada sobre el formato nativo de cada herramienta.
7. **Registro de evidencias**: la salida original (p. ej. el XML de Nmap) se guarda sin
   modificar en `~/.eurabyte_security/evidencias/<herramienta>/` (o `$EST_HOME/evidencias/...`).
8. **Explicaciones en espanol**: cada integracion tiene una entrada en `est explicar <tema>`.
9. **Herramienta no instalada**: `ErrorHerramientaNoDisponible` (ver `core/errores.py`) con un
   mensaje claro; nunca se intenta ejecutar nada si el binario no esta presente.

## Nmap

Primer adaptador implementado (`integrations/nmap.py`, `commands/nmap.py`).

### Que hace

- Descubrimiento de puertos TCP mediante `connect scan` (`-sT`, no requiere privilegios
  elevados, a diferencia de `-sS`).
- `-Pn`: no descarta el objetivo aunque no responda a ping (muchas redes bloquean ICMP).
- Identificacion de servicios y version (`-sV`) **solo si se activa explicitamente** con
  `--deteccion-version`: no es el comportamiento por defecto.
- Lee la salida en XML (`-oX`) con `defusedxml` (protegido frente a ataques XXE/billion-laughs,
  aunque el XML lo genera el propio Nmap que AST invoca).

### Comandos

```bash
est nmap version
est nmap descubrir OBJETIVO --puertos 22,80,443 [--proyecto NOMBRE] \
    [--deteccion-version] [--tiempo-limite 120]
```

| Parametro | Descripcion |
|---|---|
| `OBJETIVO` | Direccion IPv4 ya autorizada en el alcance del proyecto. |
| `--puertos` | Lista separada por comas (misma validacion que `escanear tcp`). |
| `--deteccion-version` | Activa `-sV`. Usalo solo si esa comprobacion esta autorizada. |
| `--tiempo-limite` | Segundos maximos de espera (5 a 600). Por defecto, 120. |

Tambien disponible desde la interfaz visual (`est interfaz`, seccion "Reconocimiento"): mismo
formulario, con boton de cancelar.

### Resultados

Cada puerto encontrado incluye: numero de puerto, protocolo, estado (vocabulario propio de
Nmap: `open`, `closed`, `filtered`...), servicio (si Nmap lo identifico) y version (solo con
`--deteccion-version`, formato `producto version`). Se guardan en una tabla propia
(`resultados_nmap`, separada de los resultados de `escanear tcp`) y se muestran con
`est resultados`... *(nota: por ahora `est resultados` solo lista los de `escanear tcp`; ver
"Limitaciones" mas abajo)*.

### Evidencia

Cada analisis guarda su XML original sin modificar en
`~/.eurabyte_security/evidencias/nmap/<proyecto>-<objetivo>-<fecha>.xml`.

### Cancelacion

Al cancelar un analisis en curso (boton "Cancelar" en la TUI), AST mata el proceso de Nmap
(`Popen.kill()`) en vez de esperar a que termine. Semantica todo-o-nada: un analisis cancelado
no persiste ningun resultado ni guarda evidencia.

### Limitaciones conocidas

- `est resultados` (CLI/TUI) todavia solo muestra los resultados de `escanear tcp`; los de
  Nmap se consultan por ahora solo a traves de la tabla que muestra el propio comando/panel de
  Nmap, no desde un listado unificado. Pendiente para una iteracion posterior.
- No se expone todavia `est reporte generar` para los resultados de Nmap (solo para
  `escanear tcp`).
- Los estados de puerto se muestran con el vocabulario nativo de Nmap (`open`/`closed`/
  `filtered`...) en vez de traducirse, para no introducir ambiguedad con los estados compuestos
  que Nmap puede devolver (`open|filtered`, etc.).
- Requiere tener Nmap instalado (`est nmap version` indica si AST lo detecta). AST nunca lo
  instala por ti.

## Instalar Nmap

- **Windows**: descarga el instalador desde [nmap.org](https://nmap.org/download.html) (incluye
  Npcap). Verifica con `est nmap version`.
- **Linux (Debian/Ubuntu)**: `sudo apt install nmap`.
- **Linux (Fedora/RHEL)**: `sudo dnf install nmap`.
- **macOS**: `brew install nmap`.

## Nuclei

Segundo adaptador implementado, en su propia PR independiente. Sigue el mismo motor descrito
arriba, con una capa extra de validacion (catalogo cerrado de plantillas, revalidadas
estructuralmente en cada ejecucion): ver [docs/NUCLEI.md](NUCLEI.md) para el detalle completo.

## OWASP ZAP

Tercer adaptador implementado. A diferencia de Nmap y Nuclei, ZAP **no es un binario que AST
ejecute como subproceso**: es un servicio HTTP que el usuario ya tiene corriendo por su cuenta
(con su interfaz grafica o como daemon), con su API REST expuesta en un endpoint local. Por
eso `integrations/zap.py:AdaptadorZAP` no hereda de `AdaptadorExterno` -- la pregunta no es
"esta instalado en el PATH" sino "responde su API en el endpoint configurado". Solo ofrece
analisis pasivo (nunca active scan, spider, ajaxSpider ni fuzzing) y restringe la conexion de
administracion a loopback. Ver [docs/OWASP_ZAP.md](OWASP_ZAP.md) para el detalle completo.

## Auditoria web no intrusiva

La auditoria web no intrusiva (cabeceras HTTP, TLS, cookies, redirecciones) **no pasa por
este motor de integraciones** (no invoca ningun binario externo ni un servicio aparte: es
trafico HTTP(S) hecho por la propia aplicacion con `http.client`). Ver
[AUDITORIA_WEB.md](AUDITORIA_WEB.md).
