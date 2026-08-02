from __future__ import annotations

import asyncio
import json
import logging
import platform as py_platform
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from easy_rev import __version__
from easy_rev.ai.handlers import call_tool
from easy_rev.ai.playbook import playbook_text
from easy_rev.ai.tools import TOOL_SPECS, tool_schema, tools_catalog
from easy_rev.config import get_settings
from easy_rev.pack.template import init_pack

app = typer.Typer(
    name="easy-rev",
    help="Easy-Rev: commercial multi-platform reverse engineering (Web / Desktop / Mobile)",
    no_args_is_help=True,
    add_completion=False,
)
ai_app = typer.Typer(help="AI / Agent tool surface (JSON in / JSON out)", no_args_is_help=True)
pack_app = typer.Typer(help="Target Pack management", no_args_is_help=True)
web_app = typer.Typer(help="Web reverse engineering", no_args_is_help=True)
desktop_app = typer.Typer(help="Desktop reverse engineering (Windows/macOS)", no_args_is_help=True)
mobile_app = typer.Typer(help="Mobile reverse engineering (Android/iOS)", no_args_is_help=True)
re_app = typer.Typer(help="Web RE sessions & Chrome bridge (compat)", no_args_is_help=True)

app.add_typer(ai_app, name="ai")
app.add_typer(pack_app, name="pack")
app.add_typer(web_app, name="web")
app.add_typer(desktop_app, name="desktop")
app.add_typer(mobile_app, name="mobile")
app.add_typer(re_app, name="re")

console = Console()


def _run(coro):
    return asyncio.run(coro)


def _setup_logging() -> None:
    level = getattr(logging, get_settings().log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _print_result(result: Any, as_json: bool = True) -> None:
    if as_json:
        console.print_json(data=result)
    else:
        console.print(result)


@app.callback()
def main_callback(
    version: bool = typer.Option(False, "--version", help="Show version"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Debug logging"),
) -> None:
    if version:
        console.print(__version__)
        raise typer.Exit()
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        _setup_logging()


@app.command("doctor")
def doctor_cmd(
    platform: str = typer.Option("all", "--platform", "-p"),
    as_json: bool = typer.Option(True, "--json/--pretty"),
) -> None:
    """Check reverse-engineering toolchains for all platforms."""
    result = _run(call_tool("doctor", {"platform": platform}))
    _print_result(result, as_json)


@app.command("config")
def config_cmd() -> None:
    """Show effective settings."""
    s = get_settings()
    data = s.model_dump(mode="json")
    console.print_json(data=data)


@app.command("explore")
def explore_cmd(
    platform: str = typer.Option(..., "--platform", "-p", help="web|windows|macos|android|ios"),
    url: str | None = typer.Option(None, "--url"),
    binary: str | None = typer.Option(None, "--binary", "-b"),
    process: str | None = typer.Option(None, "--process"),
    package: str | None = typer.Option(None, "--package"),
    device: str | None = typer.Option(None, "--device", "-d"),
    duration: float = typer.Option(5.0, "--duration"),
    write_pack: bool = typer.Option(False, "--write-pack"),
    pack_id: str | None = typer.Option(None, "--pack-id"),
    no_attach: bool = typer.Option(False, "--no-attach"),
) -> None:
    """One-shot multi-platform reverse engineering explore."""
    args: dict[str, Any] = {
        "platform": platform,
        "duration_s": duration,
        "attach": not no_attach,
        "write_pack": write_pack,
    }
    if url:
        args["url"] = url
    if binary:
        args["binary"] = binary
    if process:
        args["process"] = process
    if package:
        args["package"] = package
    if device:
        args["device"] = device
    if pack_id:
        args["pack_id"] = pack_id
    result = _run(call_tool("explore", args))
    _print_result(result)


# ----- AI -----


@ai_app.command("tools")
def ai_tools() -> None:
    console.print_json(data=tools_catalog())


@ai_app.command("schema")
def ai_schema(
    name: str | None = typer.Argument(None),
) -> None:
    if name:
        schema = tool_schema(name)
        if not schema:
            console.print(f"unknown tool: {name}")
            raise typer.Exit(1)
        console.print_json(data=schema)
    else:
        console.print_json(data=TOOL_SPECS)


@ai_app.command("describe")
def ai_describe(name: str = typer.Argument(...)) -> None:
    schema = tool_schema(name)
    if not schema:
        raise typer.Exit(1)
    console.print_json(data=schema)


@ai_app.command("playbook")
def ai_playbook() -> None:
    console.print(playbook_text())


@ai_app.command("call")
def ai_call(
    tool: str = typer.Argument(..., help="Tool name"),
    input_json: str | None = typer.Option(None, "--input", "-i"),
    input_file: Path | None = typer.Option(None, "--file", "-f"),
) -> None:
    """Call a tool with JSON args."""
    args: dict[str, Any] = {}
    if input_file:
        args = json.loads(input_file.read_text(encoding="utf-8"))
    elif input_json:
        args = json.loads(input_json)
    result = _run(call_tool(tool, args))
    _print_result(result)


# ----- Pack -----


@pack_app.command("init")
def pack_init(
    pack_id: str = typer.Argument(...),
    dest: Path | None = typer.Option(None, "--dest"),
    platform: str = typer.Option("web", "--platform", "-p"),
    name: str | None = typer.Option(None, "--name"),
    with_hooks: bool = typer.Option(False, "--with-hooks"),
) -> None:
    path = init_pack(
        dest or Path(f"./packs/{pack_id}"),
        pack_id=pack_id,
        name=name,
        platform=platform,
        with_hooks=with_hooks,
    )
    console.print(f"Created pack at {path}")


@pack_app.command("list")
def pack_list() -> None:
    result = _run(call_tool("pack.list", {}))
    _print_result(result)


@pack_app.command("from-capture")
def pack_from_capture(
    capture_path: Path = typer.Argument(..., exists=True, dir_okay=False),
    pack_id: str | None = typer.Option(None, "--pack-id"),
    dest: Path | None = typer.Option(None, "--dest"),
    hybrid: bool = typer.Option(False, "--hybrid"),
) -> None:
    """Build web protocol Target Pack from a capture JSON."""
    args: dict[str, Any] = {"capture_path": str(capture_path), "hybrid": hybrid}
    if pack_id:
        args["pack_id"] = pack_id
    if dest:
        args["dest"] = str(dest)
    result = _run(call_tool("pack.from_capture", args))
    _print_result(result)


@pack_app.command("validate")
def pack_validate(
    path: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
) -> None:
    """Validate Target Pack structure (pack.yaml / playbook / hooks)."""
    result = _run(call_tool("pack.validate", {"path": str(path)}))
    _print_result(result)


@pack_app.command("run")
def pack_run(
    path: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    dry_run: bool = typer.Option(True, "--dry-run/--execute", help="Plan only (default) or execute"),
    max_steps: int = typer.Option(20, "--max-steps"),
) -> None:
    """Dry-run or execute a Target Pack playbook/flow."""
    result = _run(
        call_tool(
            "pack.run",
            {"path": str(path), "dry_run": dry_run, "max_steps": max_steps},
        )
    )
    _print_result(result)


@app.command("mcp")
def mcp_cmd() -> None:
    """Start MCP stdio server (requires easy-rev[mcp])."""
    from easy_rev.mcp_server import main as mcp_main

    mcp_main()


# ----- Web -----


@web_app.command("explore")
def web_explore(
    url: str = typer.Argument(...),
    write_pack: bool = typer.Option(False, "--write-pack"),
    pack_id: str | None = typer.Option(None, "--pack-id"),
    cdp: str | None = typer.Option(None, "--cdp"),
    submit: bool = typer.Option(False, "--submit"),
    auto_fill: bool = typer.Option(True, "--auto-fill/--no-auto-fill"),
) -> None:
    args: dict[str, Any] = {
        "url": url,
        "write_pack": write_pack,
        "auto_fill": auto_fill,
        "submit": submit,
    }
    if pack_id:
        args["pack_id"] = pack_id
    if cdp:
        args["cdp_url"] = cdp
    result = _run(call_tool("web.explore", args))
    _print_result(result)


@web_app.command("capture")
def web_capture(
    url: str = typer.Argument(...),
    cdp: str | None = typer.Option(None, "--cdp"),
    submit: bool = typer.Option(False, "--submit"),
) -> None:
    args: dict[str, Any] = {"url": url, "submit": submit}
    if cdp:
        args["cdp_url"] = cdp
    result = _run(call_tool("web.capture", args))
    _print_result(result)


@re_app.command("bridge")
def re_bridge(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(18766, "--port"),
) -> None:
    """Start Chrome extension bridge (foreground-friendly)."""
    result = _run(call_tool("web.bridge.start", {"host": host, "port": port}))
    _print_result(result)
    console.print(
        f"[green]Load extension from extensions/easy-rev-chrome "
        f"and point bridge to http://{host}:{port}[/green]"
    )


@re_app.command("bridge-status")
def re_bridge_status() -> None:
    result = _run(call_tool("web.bridge.status", {}))
    _print_result(result)


# ----- Desktop -----


@desktop_app.command("ps")
def desktop_ps(
    host: str | None = typer.Option(None, "--host"),
) -> None:
    result = _run(call_tool("desktop.ps", {"host": host} if host else {}))
    _print_result(result)


@desktop_app.command("explore")
def desktop_explore(
    binary: str | None = typer.Option(None, "--binary", "-b"),
    process: str | None = typer.Option(None, "--process"),
    platform: str | None = typer.Option(None, "--platform", "-p"),
    duration: float = typer.Option(5.0, "--duration"),
) -> None:
    plat = platform or ("macos" if py_platform.system() == "Darwin" else "windows")
    args: dict[str, Any] = {"platform": plat, "duration_s": duration}
    if binary:
        args["binary"] = binary
    if process:
        args["process"] = process
    result = _run(call_tool("desktop.explore", args))
    _print_result(result)


@desktop_app.command("analyze")
def desktop_analyze(
    binary: str = typer.Argument(...),
    platform: str | None = typer.Option(None, "--platform", "-p"),
) -> None:
    plat = platform or ("macos" if py_platform.system() == "Darwin" else "windows")
    result = _run(call_tool("analyze", {"platform": plat, "binary": binary}))
    _print_result(result)


@desktop_app.command("scripts")
def desktop_scripts(
    name: str | None = typer.Argument(None, help="Optional script name to print source"),
) -> None:
    args: dict[str, Any] = {}
    if name:
        args["name"] = name
    result = _run(call_tool("desktop.scripts", args))
    _print_result(result)


# ----- Mobile -----


@mobile_app.command("devices")
def mobile_devices(
    platform: str = typer.Option("android", "--platform", "-p"),
) -> None:
    result = _run(call_tool("mobile.devices", {"platform": platform}))
    _print_result(result)


@mobile_app.command("apps")
def mobile_apps(
    device: str | None = typer.Option(None, "--device", "-d"),
) -> None:
    args = {"device": device} if device else {}
    result = _run(call_tool("mobile.apps", args))
    _print_result(result)


@mobile_app.command("explore")
def mobile_explore(
    package: str | None = typer.Option(None, "--package"),
    binary: str | None = typer.Option(None, "--binary", "-b"),
    platform: str = typer.Option("android", "--platform", "-p"),
    device: str | None = typer.Option(None, "--device", "-d"),
    duration: float = typer.Option(5.0, "--duration"),
    no_spawn: bool = typer.Option(False, "--no-spawn"),
) -> None:
    args: dict[str, Any] = {
        "platform": platform,
        "duration_s": duration,
        "spawn": not no_spawn,
    }
    if package:
        args["package"] = package
    if binary:
        args["binary"] = binary
    if device:
        args["device"] = device
    result = _run(call_tool("mobile.explore", args))
    _print_result(result)


@mobile_app.command("analyze")
def mobile_analyze(
    binary: str = typer.Argument(...),
    platform: str = typer.Option("android", "--platform", "-p"),
) -> None:
    result = _run(call_tool("analyze", {"platform": platform, "binary": binary}))
    _print_result(result)


@mobile_app.command("scripts")
def mobile_scripts(
    name: str | None = typer.Argument(None, help="Optional script name to print source"),
) -> None:
    args: dict[str, Any] = {}
    if name:
        args["name"] = name
    result = _run(call_tool("mobile.scripts", args))
    _print_result(result)


if __name__ == "__main__":
    app()
