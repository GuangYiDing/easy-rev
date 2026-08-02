"""Bundled Frida scripts for mobile reverse engineering."""

from __future__ import annotations

from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent


def list_scripts() -> list[str]:
    return sorted(p.name for p in SCRIPTS_DIR.glob("*.js"))


def script_path(name: str) -> Path:
    p = SCRIPTS_DIR / name
    if not p.is_file():
        alt = SCRIPTS_DIR / f"{name}.js"
        if alt.is_file():
            return alt
        raise FileNotFoundError(f"mobile script not found: {name}")
    return p


def load_script(name: str) -> str:
    return script_path(name).read_text(encoding="utf-8")
