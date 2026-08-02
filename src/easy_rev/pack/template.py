"""Scaffold Target Packs for web / desktop / mobile reverse engineering."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

PlatformKind = Literal["web", "desktop", "mobile", "windows", "macos", "android", "ios"]

PACK_YAML = """\
schema: easy-rev.pack/v1
id: {pack_id}
name: {name}
version: 0.1.0
description: "{description}"
platform: {platform}
os: {os}
author: ""
license: MIT
tags: []
min_easy_rev: ">=0.1.0"
target:
{target_block}
entry:
  kind: declarative
  playbook: playbook.yaml
  hooks: {hooks}
defaults: {{}}
scope:
  auth:
    status: pending
    basis: unknown
  network_profile: offline
  # full gate lives in scope.yaml after case.init / pack.init --with-ops
warnings:
  - "仅用于授权测试 / 自有业务场景；禁止未授权逆向"
  - "ACT 前需 scope.auth.status=granted（见 scope.yaml / case.guard）"
"""

PLAYBOOK_WEB = """\
schema: easy-rev.playbook/v1
platform: web
vars:
  target_url: https://example.com
steps:
  - id: explore
    action: web.explore
    url: "{{{{ vars.target_url }}}}"
    auto_fill: true
    submit: false
    write_pack: false

  - id: analyze_sign
    action: web.auto_sign
    url: "{{{{ vars.target_url }}}}"

  - id: export
    action: artifact.export
    include: [capture, har, signing]
"""

PLAYBOOK_DESKTOP = """\
schema: easy-rev.playbook/v1
platform: desktop
vars:
  process: ""
  binary: ""
steps:
  - id: static
    action: desktop.static
    binary: "{{{{ vars.binary }}}}"

  - id: attach
    action: desktop.attach
    process: "{{{{ vars.process }}}}"
    scripts:
      - hooks/ssl_pinning.js
      - hooks/crypto.js

  - id: dump
    action: desktop.dump
    include: [modules, exports, strings]
"""

PLAYBOOK_MOBILE = """\
schema: easy-rev.playbook/v1
platform: mobile
vars:
  package: ""
  device: ""
steps:
  - id: static
    action: mobile.static
    package: "{{{{ vars.package }}}}"
    # binary may be APK/IPA path
    binary: "{{{{ vars.binary | default('') }}}}"

  - id: spawn
    action: mobile.spawn
    package: "{{{{ vars.package }}}}"
    device: "{{{{ vars.device }}}}"
    scripts:
      - hooks/ssl_pinning.js
      - hooks/crypto.js
      - hooks/network.js

  - id: dump
    action: mobile.dump
    include: [classes, methods, keystore]
"""

README_MD = """\
# {name}

Easy-Rev Target Pack: `{pack_id}`  
Platform: **{platform}**

## 使用

```bash
easy-rev pack install ./
easy-rev explore --platform {platform} ...
easy-rev pack validate .
```

## Ops（吸收 reverse-skill 作战契约）

1. 编辑 `scope.yaml`：`auth.status=granted` + `network_profile` + `in_scope.assets`
2. `easy-rev ai call case.guard -i '{{"path":"."}}'` 确认 ready
3. 过程写 `evidence/`，结论写 `findings.md` / `path.md`
4. 可复用模式脱敏回写 `skills/field-journal/`

## 说明

请在授权范围内使用。根据目标修改 `playbook.yaml` 与 `hooks/`。
"""

HOOKS_WEB = '''\
"""Optional Python hooks for web protocol synthesis. Loaded with --trust."""

from __future__ import annotations

# async def sign_request(method, url, headers, body, ctx) -> dict: ...
'''

HOOKS_FRIDA_SSL = """\
// SSL pinning bypass skeleton (Frida)
// Customize for your authorized target only.
Java.perform(function () {
  // Android example placeholder
  console.log('[easy-rev] ssl_pinning hook loaded');
});
"""

HOOKS_FRIDA_CRYPTO = """\
// Crypto API hooks skeleton (Frida)
console.log('[easy-rev] crypto hook loaded');
"""

HOOKS_FRIDA_NETWORK = """\
// Network / socket hooks skeleton (Frida)
console.log('[easy-rev] network hook loaded');
"""


def _normalize_platform(platform: str) -> tuple[str, str]:
    """Return (family, os) for pack.yaml."""
    p = (platform or "web").lower()
    if p in {"web"}:
        return "web", "null"
    if p in {"windows"}:
        return "desktop", "windows"
    if p in {"macos", "darwin"}:
        return "desktop", "macos"
    if p in {"desktop"}:
        return "desktop", "null"
    if p in {"android"}:
        return "mobile", "android"
    if p in {"ios"}:
        return "mobile", "ios"
    if p in {"mobile"}:
        return "mobile", "null"
    return p, "null"


def _target_block(family: str, os_name: str) -> str:
    if family == "web":
        return '  url: "https://example.com"\n  notes: "authorized target only"'
    if family == "desktop":
        os_line = f"  os: {os_name}\n" if os_name != "null" else ""
        return (
            f"{os_line}"
            '  process: ""\n'
            '  binary: ""\n'
            '  notes: "PE / Mach-O path or running process"'
        )
    os_line = f"  os: {os_name}\n" if os_name != "null" else ""
    return (
        f"{os_line}"
        '  package: ""\n'
        '  binary: ""\n'
        '  device: ""\n'
        '  notes: "Android package / iOS bundle id"'
    )


def init_pack(
    dest: Path,
    *,
    pack_id: str,
    name: str | None = None,
    description: str = "",
    platform: str = "web",
    with_hooks: bool = False,
    with_ops: bool = True,
) -> Path:
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    name = name or pack_id
    family, os_name = _normalize_platform(platform)
    hooks_val = "null"
    if with_hooks:
        if family == "web":
            hooks_val = "hooks.py"
        else:
            hooks_val = "hooks/"

    (dest / "pack.yaml").write_text(
        PACK_YAML.format(
            pack_id=pack_id,
            name=name,
            description=description or name,
            platform=family,
            os=os_name,
            target_block=_target_block(family, os_name),
            hooks=hooks_val,
        ),
        encoding="utf-8",
    )

    if family == "web":
        playbook = PLAYBOOK_WEB
    elif family == "desktop":
        playbook = PLAYBOOK_DESKTOP
    else:
        playbook = PLAYBOOK_MOBILE
    (dest / "playbook.yaml").write_text(playbook, encoding="utf-8")
    (dest / "README.md").write_text(
        README_MD.format(name=name, pack_id=pack_id, platform=family),
        encoding="utf-8",
    )

    if with_hooks:
        if family == "web":
            (dest / "hooks.py").write_text(HOOKS_WEB, encoding="utf-8")
        else:
            hooks_dir = dest / "hooks"
            hooks_dir.mkdir(exist_ok=True)
            (hooks_dir / "ssl_pinning.js").write_text(HOOKS_FRIDA_SSL, encoding="utf-8")
            (hooks_dir / "crypto.js").write_text(HOOKS_FRIDA_CRYPTO, encoding="utf-8")
            if family == "mobile":
                (hooks_dir / "network.js").write_text(HOOKS_FRIDA_NETWORK, encoding="utf-8")

    if with_ops:
        try:
            from easy_rev.skill.evidence import ensure_ops_scaffold
            from easy_rev.skill.scope import default_scope, write_scope

            ensure_ops_scaffold(dest)
            if not (dest / "scope.yaml").is_file():
                write_scope(
                    dest,
                    default_scope(
                        case_id=pack_id,
                        primary={
                            "web": "web-reverse",
                            "desktop": "desktop-reverse",
                            "mobile": "mobile-reverse",
                        }.get(family, "general-re"),
                        platform=family if family != "desktop" else (os_name if os_name != "null" else "desktop"),
                        auth_status="pending",
                        network_profile="offline",
                        notes=description or name,
                    ),
                )
        except Exception:
            # ops is additive; pack scaffold must still succeed
            pass
    return dest
