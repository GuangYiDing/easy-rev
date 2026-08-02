from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from easy_rev.core.paths import config_dir, data_dir


class Settings(BaseSettings):
    """Global settings from env (EASY_REV_*) and optional .env."""

    model_config = SettingsConfigDict(
        env_prefix="EASY_REV_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    data_dir: Path = Field(default_factory=data_dir)
    # Web engine: auto | camoufox | mock | cdp | http
    engine: Literal["auto", "camoufox", "mock", "http", "protocol", "cdp"] = "auto"
    headless: bool = True
    # Proxies
    proxy: str | None = None
    proxy_list: str | None = None
    proxy_file: Path | None = None
    # Web RE defaults
    humanize_input: bool = True
    geoip: bool = True
    # Frida / device
    frida_host: str | None = None  # e.g. 127.0.0.1:27042
    adb_serial: str | None = None
    ios_udid: str | None = None
    # Extension bridge (Chrome)
    bridge_host: str = "127.0.0.1"
    bridge_port: int = 18766
    # Logging
    log_level: str = "INFO"
    # Session GC
    session_idle_ttl_s: int = 1800


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    global _settings
    _settings = None


def config_path() -> Path:
    return config_dir() / "config.env"
