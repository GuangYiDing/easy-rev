from __future__ import annotations

from pathlib import Path

from platformdirs import user_config_dir, user_data_dir

APP_NAME = "easy-rev"


def data_dir() -> Path:
    p = Path(user_data_dir(APP_NAME, appauthor=False))
    p.mkdir(parents=True, exist_ok=True)
    return p


def config_dir() -> Path:
    p = Path(user_config_dir(APP_NAME, appauthor=False))
    p.mkdir(parents=True, exist_ok=True)
    return p


def packs_dir() -> Path:
    p = data_dir() / "packs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def artifacts_dir() -> Path:
    p = data_dir() / "artifacts"
    p.mkdir(parents=True, exist_ok=True)
    return p


def sessions_dir() -> Path:
    p = data_dir() / "sessions"
    p.mkdir(parents=True, exist_ok=True)
    return p


def db_path() -> Path:
    return data_dir() / "easy-rev.db"
