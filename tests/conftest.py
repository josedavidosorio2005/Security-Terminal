from __future__ import annotations

import pytest
from typer.testing import CliRunner


@pytest.fixture(autouse=True)
def entorno_aislado(tmp_path, monkeypatch):
    """Aisla cada prueba con su propio directorio de datos (EST_HOME)."""
    monkeypatch.setenv("EST_HOME", str(tmp_path / "datos_est"))
    yield


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()
