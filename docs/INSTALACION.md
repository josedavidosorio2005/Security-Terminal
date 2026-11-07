# Instalacion de AST

AST requiere **Python 3.11 o superior** y funciona igual en Windows y Linux. `pip install`
instala tanto la CLI (Fase 1) como la interfaz visual Textual (Fase 2, `est interfaz`): no hay
un paso de instalacion separado para la interfaz.

## Linux / macOS

```bash
git clone https://github.com/josedavidosorio2005/Security-Terminal.git
cd Security-Terminal

python3 -m venv .venv
source .venv/bin/activate

pip install -e ".[dev]"

est --ayuda
```

## Windows (PowerShell)

```powershell
git clone https://github.com/josedavidosorio2005/Security-Terminal.git
cd Security-Terminal

python -m venv .venv
.venv\Scripts\Activate.ps1

pip install -e ".[dev]"

est --ayuda
```

> Si PowerShell bloquea la ejecucion de scripts, ejecuta primero (una sola vez, por sesion):
> `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`.

## Windows (cmd.exe)

```bat
git clone https://github.com/josedavidosorio2005/Security-Terminal.git
cd Security-Terminal

python -m venv .venv
.venv\Scripts\activate.bat

pip install -e ".[dev]"

est --ayuda
```

## Verificar la instalacion

```bash
est --version
est proyecto crear laboratorio
est alcance agregar 127.0.0.1/32
est escanear tcp 127.0.0.1 --puertos 22,80
```

## Terminal interactiva

`est interactivo` necesita una consola real (cmd.exe, PowerShell o una terminal Linux con TTY).
No funciona con la entrada/salida redirigida (por ejemplo, dentro de una tuberia o un script no
interactivo): en ese caso AST muestra un mensaje explicandolo en lugar de fallar sin informacion.

## Interfaz visual (`est interfaz`)

```bash
est interfaz
```

Tambien necesita una consola real. Para mejores resultados usa un emulador de terminal moderno
con soporte de color verdadero (Windows Terminal, la mayoria de terminales de Linux/macOS
actuales). Manual completo, atajos de teclado y solucion de problemas en
[docs/INTERFAZ.md](INTERFAZ.md).

## Integraciones externas (Fase 3)

`pip install` instala el motor de integraciones, pero cada herramienta externa se instala por
separado (AST nunca las instala por ti; `est nmap version` indica si la detecta):

- **Nmap**: Windows, [nmap.org/download.html](https://nmap.org/download.html); Debian/Ubuntu,
  `sudo apt install nmap`; Fedora/RHEL, `sudo dnf install nmap`; macOS, `brew install nmap`.

Detalle de parametros, resultados y limitaciones de cada integracion en
[docs/INTEGRACIONES.md](INTEGRACIONES.md).

## Ejecutar las pruebas

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

## Desinstalar

```bash
pip uninstall eurabyte-security
```
