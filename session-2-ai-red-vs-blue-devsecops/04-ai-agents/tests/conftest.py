"""Configuración común de los tests."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_model_by_default(monkeypatch):
    """Sin modelo salvo que el test lo pida: nada sale a la red ni lanza análisis en segundo
    plano. Los tests que prueban el modelo ponen LLM_PROVIDER y un modelo falso."""
    monkeypatch.setenv("LLM_PROVIDER", "none")
