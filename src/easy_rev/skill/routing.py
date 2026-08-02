"""PRIMARY skill routing ladder for agent tasks.

Maps user hints → Easy-Rev platform path + recommended tools.
"""

from __future__ import annotations

import re
from typing import Any

# Priority high → low. First strong family match after scoring wins.
ROUTE_RULES: list[dict[str, Any]] = [
    {
        "id": "R-WEB",
        "primary": "web-reverse",
        "platform": "web",
        "path": "browser",
        "patterns": [
            r"\bweb\b",
            r"\bjs\b",
            r"javascript",
            r"签名",
            r"加密参数",
            r"sign(ature)?",
            r"webpack",
            r"sourcemap",
            r"cdp",
            r"camoufox",
            r"chrome",
            r"browser",
            r"har\b",
            r"xhr",
            r"fetch",
            r"https?://",
            r"前端",
            r"协议包",
            r"抓包",
            r"cookie",
        ],
        "tools": ["doctor", "web.explore", "web.bridge.start", "web.analyze_js", "pack.from_capture"],
        "workflow": ["observe", "capture", "rebuild", "patch", "deepdive"],
        "basis": "Web / JS 签名 / 浏览器链路",
    },
    {
        "id": "R-ANDROID",
        "primary": "mobile-reverse",
        "platform": "android",
        "path": "dynamic",
        "patterns": [
            r"\bapk\b",
            r"\bandroid\b",
            r"smali",
            r"jadx",
            r"apktool",
            r"androguard",
            r"okhttp",
            r"ssl.?pinn",
            r"证书固定",
            r"\bfrida\b.*android",
        ],
        "tools": ["doctor", "mobile.explore", "mobile.apps", "mobile.scripts", "pack.init"],
        "workflow": ["static", "device", "spawn", "hooks", "pack"],
        "basis": "Android / APK / 移动动态插桩",
    },
    {
        "id": "R-IOS",
        "primary": "mobile-reverse",
        "platform": "ios",
        "path": "dynamic",
        "patterns": [
            r"\bipa\b",
            r"\bios\b",
            r"objection",
            r"jailbreak",
            r"越狱",
            r"bundle\s*id",
            r"mach-?o.*ios",
        ],
        "tools": ["doctor", "mobile.explore", "mobile.scripts", "pack.init"],
        "workflow": ["static", "device", "attach", "hooks", "pack"],
        "basis": "iOS / IPA / Objection 风格动态分析",
    },
    {
        "id": "R-MACOS",
        "primary": "desktop-reverse",
        "platform": "macos",
        "path": "dynamic",
        "patterns": [
            r"\bmacos\b",
            r"\bdarwin\b",
            r"mach-?o",
            r"\.app\b",
            r"otool",
            r"codesign",
            r"pkcs#?11",
            r"keychain",
            r"launchagent",
        ],
        "tools": ["doctor", "desktop.explore", "desktop.ps", "desktop.scripts", "pack.init"],
        "workflow": ["static", "ps", "attach", "hooks", "pack"],
        "basis": "macOS Desktop / Mach-O / 本机进程",
    },
    {
        "id": "R-WINDOWS",
        "primary": "desktop-reverse",
        "platform": "windows",
        "path": "dynamic",
        "patterns": [
            r"\bwindows\b",
            r"\bpe\b",
            r"\.exe\b",
            r"\.dll\b",
            r"dumpbin",
            r"win32",
            r"wmi",
        ],
        "tools": ["doctor", "desktop.explore", "desktop.ps", "desktop.scripts", "pack.init"],
        "workflow": ["static", "ps", "attach", "hooks", "pack"],
        "basis": "Windows Desktop / PE / 本机进程",
    },
    {
        "id": "R-DESKTOP",
        "primary": "desktop-reverse",
        "platform": "desktop",
        "path": "static",
        "patterns": [
            r"\bdesktop\b",
            r"\bbinary\b",
            r"桌面",
            r"客户端",
            r"厚客户端",
            r"thick.?client",
            r"\bfrida\b",
        ],
        "tools": ["doctor", "desktop.explore", "desktop.ps", "pack.init"],
        "workflow": ["static", "ps", "attach", "hooks", "pack"],
        "basis": "通用 Desktop 二进制 / Frida",
    },
    {
        "id": "R-MOBILE",
        "primary": "mobile-reverse",
        "platform": "mobile",
        "path": "static",
        "patterns": [
            r"\bmobile\b",
            r"移动端",
            r"app\s*逆向",
        ],
        "tools": ["doctor", "mobile.explore", "mobile.devices", "pack.init"],
        "workflow": ["static", "device", "spawn", "hooks", "pack"],
        "basis": "通用 Mobile 目标",
    },
    {
        "id": "R-PACK",
        "primary": "pack-ops",
        "platform": "any",
        "path": "pack",
        "patterns": [
            r"\bpack\b",
            r"target\s*pack",
            r"playbook",
            r"初始化\s*pack",
            r"写包",
            r"固化",
        ],
        "tools": ["pack.init", "pack.validate", "pack.run", "pack.list", "case.init"],
        "workflow": ["init", "scope", "validate", "run"],
        "basis": "Target Pack / 固化与执行",
    },
    {
        "id": "R-DOCTOR",
        "primary": "doctor",
        "platform": "any",
        "path": "env",
        "patterns": [
            r"\bdoctor\b",
            r"preflight",
            r"环境",
            r"缺依赖",
            r"install",
            r"toolchain",
        ],
        "tools": ["doctor", "doctor.preflight", "doctor.fix", "doctor.catalog"],
        "workflow": ["doctor", "fix", "recheck"],
        "basis": "环境诊断 / 依赖修复",
    },
]

FALLBACK = {
    "id": "R0",
    "primary": "general-re",
    "platform": "any",
    "path": "triage",
    "tools": ["doctor", "route", "explore", "pack.init", "case.init"],
    "workflow": ["route", "scope", "doctor", "explore", "evidence", "pack"],
    "basis": "未命中强关键词，走通用 triage",
}

_FAMILY = {
    "windows": "desktop",
    "macos": "desktop",
    "android": "mobile",
    "ios": "mobile",
    "web": "web",
}


def route_table() -> list[dict[str, Any]]:
    """Public routing matrix for agents / docs."""
    rows = []
    for r in ROUTE_RULES:
        rows.append(
            {
                "id": r["id"],
                "primary": r["primary"],
                "platform": r["platform"],
                "path": r["path"],
                "tools": list(r["tools"]),
                "workflow": list(r.get("workflow") or []),
                "basis": r["basis"],
            }
        )
    rows.append(
        {
            "id": FALLBACK["id"],
            "primary": FALLBACK["primary"],
            "platform": FALLBACK["platform"],
            "path": FALLBACK["path"],
            "tools": list(FALLBACK["tools"]),
            "workflow": list(FALLBACK["workflow"]),
            "basis": FALLBACK["basis"],
        }
    )
    return rows


def master_route(hint: str, *, platform: str | None = None) -> dict[str, Any]:
    """Classify a user task into PRIMARY skill + Easy-Rev tools."""
    text = (hint or "").strip()
    forced = (platform or "").strip().lower() or None
    if forced == "desktop":
        forced = "macos"
    if forced == "mobile":
        forced = "android"

    matches: list[dict[str, Any]] = []
    hay = text.lower()
    for idx, rule in enumerate(ROUTE_RULES):
        score = 0
        hit_patterns: list[str] = []
        for pat in rule["patterns"]:
            found = re.findall(pat, hay, flags=re.IGNORECASE)
            if found:
                score += len(found)
                hit_patterns.append(pat)
        if forced and rule["platform"] not in {forced, "any", "desktop", "mobile"}:
            family = _FAMILY.get(forced)
            if rule["platform"] != family and rule["id"] not in {"R-PACK", "R-DOCTOR"}:
                continue
        if score > 0:
            matches.append({**rule, "score": score, "hit_patterns": hit_patterns, "_idx": idx})

    if forced and matches:
        preferred = [
            m
            for m in matches
            if m["platform"] == forced or m["platform"] == _FAMILY.get(forced, forced)
        ]
        if preferred:
            matches = preferred + [m for m in matches if m not in preferred]

    if matches:
        matches.sort(key=lambda m: (-int(m["score"]), int(m.get("_idx", 0))))
        top = matches[0]
    else:
        top = {**FALLBACK, "score": 0, "hit_patterns": []}
        if forced:
            top = {
                **top,
                "platform": forced,
                "primary": {
                    "web": "web-reverse",
                    "windows": "desktop-reverse",
                    "macos": "desktop-reverse",
                    "android": "mobile-reverse",
                    "ios": "mobile-reverse",
                }.get(forced, top["primary"]),
                "basis": f"forced platform={forced}; no keyword hit",
            }

    plat = top["platform"]
    if plat == "desktop":
        plat = "macos"
    if plat == "mobile":
        plat = "android"

    next_steps = [
        "case.init / 确认 scope.auth.status=granted 后才能对目标 ACT",
        f"doctor platform={plat}" if plat != "any" else "doctor",
        f"打开 skills/{top['primary']}/SKILL.md（若存在）并执行 ACTION REQUIRED",
        "过程追加 evidence；结论写入 findings；可复用模式回写 field-journal（脱敏）",
    ]
    if top.get("tools"):
        next_steps.insert(2, "优先工具: " + ", ".join(list(top["tools"])[:5]))

    return {
        "ok": True,
        "hint": text,
        "route_id": top["id"],
        "primary": top["primary"],
        "platform": plat if plat != "any" else None,
        "path": top.get("path"),
        "basis": top.get("basis"),
        "score": int(top.get("score") or 0),
        "hit_patterns": list(top.get("hit_patterns") or [])[:12],
        "tools": list(top.get("tools") or []),
        "workflow": list(top.get("workflow") or []),
        "alternates": [
            {
                "route_id": m["id"],
                "primary": m["primary"],
                "platform": m["platform"],
                "score": m.get("score"),
                "basis": m.get("basis"),
            }
            for m in (matches[1:4] if matches else [])
        ],
        "ops_gate": {
            "must": ["auth.status=granted", "network_profile set", "ready_for_act"],
            "before_act": "case.guard / pack scope",
        },
        "next_steps": next_steps,
        "skill_paths": {
            "master": "skills/MASTER-ROUTING.md",
            "primary": f"skills/{top['primary']}/SKILL.md",
            "ops_scope": "skills/ops/scope-contract.md",
            "ops_evidence": "skills/ops/evidence-finding-path.md",
        },
    }
