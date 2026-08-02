"""Standard reverse-engineering playbooks for AI agents.

Can emit a static full guide or a doctor-aware dynamic path for one platform.
"""

from __future__ import annotations

from typing import Any


def playbook_text(platform: str | None = None, *, dynamic: bool = True) -> str:
    """Return agent playbook markdown.

    platform: optional web|windows|macos|android|ios|desktop|mobile
    dynamic: when True, consult preflight and tailor next steps
    """
    base = _static_playbook()
    if not dynamic and not platform:
        return base

    plat = (platform or "all").lower()
    if plat == "desktop":
        plat = "macos"
    if plat == "mobile":
        plat = "android"

    dynamic_block = ""
    if dynamic:
        try:
            from easy_rev.core.deps import preflight

            pf = preflight(plat if plat != "all" else "all")
            dynamic_block = _format_preflight(plat, pf)
        except Exception as e:  # noqa: BLE001
            dynamic_block = f"\n## 当前环境（动态）\n- preflight failed: {e}\n"

    if plat and plat != "all":
        focused = _platform_focus(plat)
        return f"{focused}\n{dynamic_block}\n---\n\n{base}"
    return f"{base}\n{dynamic_block}"


def _format_preflight(plat: str, pf: dict[str, Any]) -> str:
    lines = ["## 当前环境（doctor/preflight 动态）", ""]
    ready = pf.get("ready")
    lines.append(f"- ready: `{ready}`")
    missing = list(pf.get("missing_required") or []) + list(pf.get("missing_recommended") or [])
    if missing:
        lines.append("- missing: " + ", ".join(f"`{m}`" for m in missing[:12]))
    fixable = pf.get("fixable") or []
    if fixable:
        lines.append("- fixable: " + ", ".join(f"`{x}`" for x in fixable[:12]))
        lines.append("- 建议: `easy-rev doctor --fix --dry-run` 然后 `easy-rev doctor --fix`")
    platforms = pf.get("platforms") or {}
    if plat != "all" and plat in platforms:
        pinfo = platforms[plat] or {}
        lines.append(
            f"- platform `{plat}` score={pinfo.get('score')} ready={pinfo.get('ready')}"
        )
        pmiss = pinfo.get("missing") or []
        if pmiss:
            lines.append(f"- platform missing: {', '.join(str(x) for x in pmiss[:8])}")
    next_steps = pf.get("next_steps") or pf.get("install_hints") or []
    if next_steps:
        lines.append("- next_steps:")
        for s in next_steps[:8]:
            lines.append(f"  - {s}")
    lines.append("")
    lines.append(
        "成功判定：返回 JSON 的 `ok`；动态路径必须同时看 `status` / `attached` / `confidence`"
        "（`dry_run` 或 `degraded` ≠ 已插桩成功）。"
    )
    lines.append("")
    return "\n".join(lines)


def _platform_focus(plat: str) -> str:
    table = {
        "web": """# Playbook focus: Web
1. `doctor` / `doctor.preflight` path=browser
2. 干净环境：`web.explore` url=…
3. 已登录 Chrome：`web.bridge.start` + 扩展，或 `cdp_url`
4. 读 `recommendation`：protocol | hybrid | browser_flow
5. `status=attached` 才表示浏览器路径成功；否则看 `hint` / `next_steps`
6. `write_pack` 或 `pack.from_capture` 固化
""",
        "windows": """# Playbook focus: Windows Desktop
1. doctor path=static|dynamic
2. `explore` platform=windows binary=… 静态
3. `desktop.ps` → process= 动态（需 frida）
4. 读 `status`：static / dry_run / attached
5. 定制 `hooks/*.js`，`pack.init --platform windows --with-hooks`
""",
        "macos": """# Playbook focus: macOS Desktop
1. doctor path=static|dynamic
2. `explore` platform=macos binary=… 静态（Mach-O）
3. `desktop.ps` → process= + scripts
4. 读 `status` / `blocking_issues`（缺 frida 时为 dry_run）
5. pack 固化 hooks（ssl/crypto）
""",
        "android": """# Playbook focus: Android
1. doctor path=dynamic|static；确认 adb 设备
2. `mobile.explore` binary=app.apk 静态
3. `mobile.apps` → package= spawn
4. pinning 线索 → 定制 ssl_pinning.js（默认 observe-only）
5. 看 `status` / `confidence`，再 `pack.init --platform android`
""",
        "ios": """# Playbook focus: iOS
1. doctor；确认 libimobiledevice / frida-server
2. `mobile.explore` platform=ios binary=app.ipa
3. package/bundle id 动态 attach
4. 使用 ios_ssl / ios_crypto 脚本模板并按目标定制
5. pack 固化
""",
    }
    return table.get(plat, f"# Playbook focus: {plat}\n使用 `explore` + `doctor` 后按 recommendation 行动。\n")


def _static_playbook() -> str:
    return """# Easy-Rev Playbook

## 合规
仅对用户授权目标进行逆向。拒绝未授权的第三方应用/站点批量攻击。

## Skill Router（吸收 reverse-skill）
```bash
easy-rev route "逆向这个网页签名"
easy-rev case init --hint "..." --auth-granted --target https://... --network-profile authorized_target_only
easy-rev case guard packs/my-target
easy-rev ai call evidence.append -i '{"path":"packs/x","title":"...","repro_command":"..."}'
easy-rev ai call journal.search -i '{"query":"ssl pinning"}'
```

**硬门槛**：`auth.status=granted` + `network_profile` 前禁止 attach/hook/对目标发包。  
**完成清单**：evidence → findings → path → 脱敏 journal → pack validate。

## 执行契约（反空转）
1. `route` 输出 PRIMARY + 依据
2. `case.init` / 确认 scope
3. `doctor` / preflight
4. explore / capture（读 `status`/`attached`/`confidence`）
5. 写 Evidence/Finding/Path
6. `pack.validate`；可复用模式 `journal.write`
7. 同方法失败 2–3 次必须换路径（static↔dynamic）

## 统一入口
```bash
easy-rev doctor
easy-rev ai call explore -i '{"platform":"web","url":"https://…"}'
easy-rev ai call explore -i '{"platform":"macos","binary":"/path/App","process":"App"}'
easy-rev ai call explore -i '{"platform":"android","binary":"./app.apk","package":"com.example"}'
```

## 结果契约（必读）
- `ok`：调用契约完成（**包含** dry_run / offline / degraded）
- `status`：`attached` | `dry_run` | `error` | `static` | `offline` | `degraded`
- `attached`：真正插桩/浏览器在线
- `confidence`：high|medium|low|none
- `blocking_issues` / `next_steps` / `hint`：阻塞与下一步
- 分享前可 `redact: true` 脱敏 token/cookie

## Web 逆向（Observe→Capture→Rebuild→Patch→DeepDive）
1. doctor → 确认 camoufox / CDP
2. Observe：web.explore / network 列表 / initiator
3. Capture：runtime/crypto hooks、HAR、diff_capture
4. Rebuild：draft_protocol / pack.from_capture
5. Patch：字段探测 / sign_synth 本地复现
6. DeepDive：按需去混淆；read recommendation: protocol | hybrid | browser_flow

## Desktop（Windows / macOS）
1. doctor → frida / otool / dumpbin
2. desktop.explore binary= 静态（字符串/导入/加壳线索）
3. desktop.ps 找进程 → explore process= + scripts
4. 按 hooks 模板扩展 SSL/crypto hook
5. 产物在 data_dir/artifacts/desktop/

## Mobile（Android / iOS）
1. doctor → adb / frida-server / USB 设备
2. mobile.explore binary=app.apk 静态（包名/权限/URL/pinning）
3. mobile.apps → package= spawn 动态
4. 注入 ssl_pinning / crypto / network hooks（默认观察，bypass 需定制）
5. 产物在 data_dir/artifacts/mobile/

## Target Pack
```bash
easy-rev pack init my-target --platform android --with-hooks
easy-rev pack validate packs/my-target
easy-rev pack run packs/my-target --dry-run
# 编辑 packs/my-target/playbook.yaml 与 hooks/
```
"""
