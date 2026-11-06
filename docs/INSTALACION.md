# Instalacion de EST

EST requiere **Python 3.11 o superior** y funciona igual en Windows y Linux.

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
interactivo): en ese caso EST muestra un mensaje explicandolo en lugar de fallar sin informacion.

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
