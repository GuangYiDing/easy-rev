"""Stable tool surface for AI agents (JSON schema)."""

from __future__ import annotations

from typing import Any

TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "doctor",
        "description": "Report environment health across web / desktop / mobile toolchains.",
        "input_schema": {
            "type": "object",
            "properties": {
                "platform": {
                    "type": "string",
                    "description": "Optional: web|windows|macos|android|ios|all",
                    "default": "all",
                }
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "explore",
        "description": "One-shot reverse engineering explore for any platform.",
        "input_schema": {
            "type": "object",
            "properties": {
                "platform": {
                    "type": "string",
                    "description": "web|windows|macos|android|ios",
                },
                "url": {"type": "string"},
                "binary": {"type": "string", "description": "PE/Mach-O/APK/IPA path"},
                "process": {"type": "string"},
                "package": {"type": "string"},
                "device": {"type": "string"},
                "write_pack": {"type": "boolean", "default": False},
                "pack_id": {"type": "string"},
                "attach": {"type": "boolean", "default": True},
                "duration_s": {"type": "number", "default": 5},
                "scripts": {"type": "array", "items": {"type": "string"}},
                "cdp_url": {"type": "string"},
                "auto_fill": {"type": "boolean"},
                "submit": {"type": "boolean"},
            },
            "required": ["platform"],
            "additionalProperties": True,
        },
    },
    {
        "name": "capture",
        "description": "Capture runtime traffic/hooks for a target.",
        "input_schema": {
            "type": "object",
            "properties": {
                "platform": {"type": "string"},
                "url": {"type": "string"},
                "process": {"type": "string"},
                "package": {"type": "string"},
                "device": {"type": "string"},
                "binary": {"type": "string"},
                "duration_s": {"type": "number"},
                "scripts": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["platform"],
            "additionalProperties": True,
        },
    },
    {
        "name": "analyze",
        "description": "Static analysis of binary/package or JS text.",
        "input_schema": {
            "type": "object",
            "properties": {
                "platform": {"type": "string"},
                "binary": {"type": "string"},
                "text": {"type": "string"},
                "url": {"type": "string"},
            },
            "required": ["platform"],
            "additionalProperties": True,
        },
    },
    {
        "name": "web.explore",
        "description": "Web one-shot RE: capture + sign + dependency graph + optional pack.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "write_pack": {"type": "boolean"},
                "pack_id": {"type": "string"},
                "cdp_url": {"type": "string"},
                "auto_fill": {"type": "boolean"},
                "submit": {"type": "boolean"},
                "scaffold_hooks": {"type": "boolean"},
            },
            "required": ["url"],
            "additionalProperties": True,
        },
    },
    {
        "name": "web.capture",
        "description": "Full web capture (network + runtime hooks + signing).",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "engine": {"type": "string"},
                "cdp_url": {"type": "string"},
                "auto_fill": {"type": "boolean"},
                "submit": {"type": "boolean"},
                "runtime_hooks": {"type": "boolean"},
            },
            "required": ["url"],
            "additionalProperties": True,
        },
    },
    {
        "name": "web.bridge.start",
        "description": "Start local Chrome extension bridge receiver.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "integer"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "web.bridge.status",
        "description": "Status of last Chrome extension capture.",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "web.analyze_js",
        "description": "Static JS signing/crypto risk analysis.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "text": {"type": "string"},
                "download": {"type": "boolean"},
            },
            "additionalProperties": True,
        },
    },
    {
        "name": "desktop.ps",
        "description": "List desktop processes (Frida).",
        "input_schema": {
            "type": "object",
            "properties": {"host": {"type": "string"}},
            "additionalProperties": False,
        },
    },
    {
        "name": "desktop.explore",
        "description": "Desktop static + Frida explore.",
        "input_schema": {
            "type": "object",
            "properties": {
                "platform": {"type": "string", "default": "macos"},
                "binary": {"type": "string"},
                "process": {"type": "string"},
                "duration_s": {"type": "number"},
                "scripts": {"type": "array", "items": {"type": "string"}},
            },
            "additionalProperties": True,
        },
    },
    {
        "name": "mobile.devices",
        "description": "List ADB / Frida / iOS devices.",
        "input_schema": {
            "type": "object",
            "properties": {"platform": {"type": "string", "default": "android"}},
            "additionalProperties": False,
        },
    },
    {
        "name": "mobile.apps",
        "description": "List apps on connected mobile device via Frida.",
        "input_schema": {
            "type": "object",
            "properties": {"device": {"type": "string"}},
            "additionalProperties": False,
        },
    },
    {
        "name": "mobile.explore",
        "description": "Mobile static (APK/IPA) + Frida explore.",
        "input_schema": {
            "type": "object",
            "properties": {
                "platform": {"type": "string", "default": "android"},
                "binary": {"type": "string"},
                "package": {"type": "string"},
                "device": {"type": "string"},
                "spawn": {"type": "boolean"},
                "duration_s": {"type": "number"},
                "scripts": {"type": "array", "items": {"type": "string"}},
            },
            "additionalProperties": True,
        },
    },
    {
        "name": "pack.init",
        "description": "Scaffold a Target Pack directory.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pack_id": {"type": "string"},
                "dest": {"type": "string"},
                "platform": {"type": "string", "default": "web"},
                "name": {"type": "string"},
                "description": {"type": "string"},
                "with_hooks": {"type": "boolean", "default": False},
            },
            "required": ["pack_id"],
        },
    },
    {
        "name": "pack.list",
        "description": "List packs under ./packs and data_dir/packs.",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "pack.from_capture",
        "description": "Build a web protocol Target Pack from a capture JSON (APIs + auto_sign).",
        "input_schema": {
            "type": "object",
            "properties": {
                "capture_path": {"type": "string"},
                "pack_id": {"type": "string"},
                "dest": {"type": "string"},
                "hybrid": {"type": "boolean"},
                "max_apis": {"type": "integer"},
                "min_score": {"type": "integer"},
            },
            "required": ["capture_path"],
            "additionalProperties": True,
        },
    },
    {
        "name": "web.dependency_graph",
        "description": "Build API dependency graph / suggested http steps from capture APIs list.",
        "input_schema": {
            "type": "object",
            "properties": {
                "capture_path": {"type": "string"},
                "apis": {"type": "array"},
                "min_score": {"type": "integer"},
            },
            "additionalProperties": True,
        },
    },
    {
        "name": "desktop.scripts",
        "description": "List or load bundled desktop Frida scripts.",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Optional script name to load source (e.g. module_enum.js)",
                }
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "mobile.scripts",
        "description": "List or load bundled mobile Frida scripts (Android + iOS).",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Optional script name to load source (e.g. ios_ssl.js)",
                }
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "web.sign_synth",
        "description": "Analyze crypto hook events and synthesize Python sign_request when recoverable.",
        "input_schema": {
            "type": "object",
            "properties": {
                "events": {
                    "type": "array",
                    "description": "Crypto hook events (api/key/message/result)",
                },
                "synthesize": {
                    "type": "boolean",
                    "default": True,
                    "description": "If true, emit Python sign_request source when possible",
                },
            },
            "required": ["events"],
            "additionalProperties": True,
        },
    },
    {
        "name": "web.diff_capture",
        "description": "Diff two capture JSON snapshots (APIs added/removed, body/header deltas).",
        "input_schema": {
            "type": "object",
            "properties": {
                "a": {"type": "string", "description": "Path or inline capture A"},
                "b": {"type": "string", "description": "Path or inline capture B"},
                "a_path": {"type": "string"},
                "b_path": {"type": "string"},
                "focus": {"type": "string"},
            },
            "additionalProperties": True,
        },
    },
    {
        "name": "web.offline_chain",
        "description": "Run offline RE chain: classify→dependency_graph→draft pack→optional sign_synth on one capture.",
        "input_schema": {
            "type": "object",
            "properties": {
                "capture_path": {"type": "string"},
                "capture": {"type": "object"},
                "pack_id": {"type": "string"},
                "dest": {"type": "string"},
                "min_score": {"type": "integer"},
                "write_pack": {"type": "boolean", "default": True},
            },
            "additionalProperties": True,
        },
    },
    {
        "name": "web.diagnose",
        "description": "Diagnose a capture JSON or job_id for protocol readiness / failure tips.",
        "input_schema": {
            "type": "object",
            "properties": {
                "capture_path": {"type": "string"},
                "job_id": {"type": "string"},
                "message": {"type": "string", "description": "Optional error message to tip against"},
                "status": {"type": "integer", "description": "Optional last HTTP status"},
            },
            "additionalProperties": True,
        },
    },
    {
        "name": "web.har_export",
        "description": "Convert capture JSON (apis[]) to HAR 1.2 file or document.",
        "input_schema": {
            "type": "object",
            "properties": {
                "capture_path": {"type": "string"},
                "dest": {"type": "string", "description": "Optional output .har path"},
                "title": {"type": "string"},
            },
            "required": ["capture_path"],
            "additionalProperties": True,
        },
    },
    {
        "name": "web.session.start",
        "description": "Start a persistent web RE session (browser subprocess). Needs web extras.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "engine": {"type": "string"},
                "headless": {"type": "boolean"},
                "cdp_url": {"type": "string"},
                "session_id": {"type": "string"},
            },
            "additionalProperties": True,
        },
    },
    {
        "name": "web.session.stop",
        "description": "Stop a web RE session by session_id.",
        "input_schema": {
            "type": "object",
            "properties": {"session_id": {"type": "string"}},
            "required": ["session_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "web.session.list",
        "description": "List active web RE sessions.",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "pack.validate",
        "description": "Validate a Target Pack directory (pack.yaml / playbook / hooks).",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "pack.run",
        "description": "Dry-run or execute a Target Pack playbook/flow (default dry_run=true).",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "dry_run": {"type": "boolean", "default": True},
                "vars": {"type": "object"},
                "max_steps": {"type": "integer"},
            },
            "required": ["path"],
            "additionalProperties": True,
        },
    },
    {
        "name": "frida.session.start",
        "description": "Start in-process Frida live session (desktop process or mobile package).",
        "input_schema": {
            "type": "object",
            "properties": {
                "kind": {"type": "string", "description": "desktop|mobile"},
                "platform": {"type": "string"},
                "target": {"type": "string", "description": "process name/pid or package id"},
                "scripts": {"type": "array", "items": {"type": "string"}},
                "spawn": {"type": "boolean"},
                "device": {"type": "string"},
                "host": {"type": "string"},
                "session_id": {"type": "string"},
            },
            "required": ["kind", "target"],
            "additionalProperties": True,
        },
    },
    {
        "name": "frida.session.stop",
        "description": "Stop a Frida live session.",
        "input_schema": {
            "type": "object",
            "properties": {"session_id": {"type": "string"}},
            "required": ["session_id"],
        },
    },
    {
        "name": "frida.session.list",
        "description": "List Frida live sessions.",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "frida.session.drain",
        "description": "Drain normalized messages from a Frida session.",
        "input_schema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "since": {"type": "integer", "default": 0},
                "limit": {"type": "integer", "default": 500},
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "frida.session.eval",
        "description": "Load extra JS into a Frida live session.",
        "input_schema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "source": {"type": "string"},
            },
            "required": ["session_id", "source"],
        },
    },
]


def tools_catalog() -> list[dict[str, Any]]:
    return [
        {"name": t["name"], "description": t["description"]}
        for t in TOOL_SPECS
    ]


def tool_schema(name: str) -> dict[str, Any] | None:
    for t in TOOL_SPECS:
        if t["name"] == name:
            return t
    return None
