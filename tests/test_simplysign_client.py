from __future__ import annotations

import importlib.util
import json
from pathlib import Path

CLIENT_PATH = (
    Path(__file__).resolve().parents[1]
    / "packs/simplysign-desktop/protocol/client.py"
)


def load_client_module():
    spec = importlib.util.spec_from_file_location("simplysign_protocol_client", CLIENT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_show_config_redacts_client_secret(monkeypatch, capsys):
    client = load_client_module()
    sentinel = "sentinel-client-value"
    monkeypatch.setattr(
        client,
        "load_xml_oauth",
        lambda: {
            "OAuth2ClientId": "public-client-id",
            "OAuth2ClientSecret": sentinel,
            "OAuth2AccessTokenUrl": "https://example.test/token",
        },
    )

    assert client.cmd_show_config(None) == 0
    output = capsys.readouterr().out
    config_text = output.split("\nsession_path", 1)[0]
    config = json.loads(config_text)

    assert sentinel not in output
    assert config["OAuth2ClientSecret"] == "<redacted>"
    assert config["OAuth2ClientId"] == "public-client-id"
