"""Field journal: anonymized cross-pack experience reuse."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from easy_rev.util.redact import redact_string


def _repo_skills_root() -> Path:
    # prefer cwd skills/, then package-adjacent
    cwd = Path.cwd() / "skills" / "field-journal"
    if cwd.parent.is_dir():
        return cwd
    # src/easy_rev/skill/../../.. -> repo root when editable
    here = Path(__file__).resolve()
    candidate = here.parents[3] / "skills" / "field-journal"
    return candidate


def journal_root(path: str | Path | None = None) -> Path:
    if path:
        return Path(path).expanduser().resolve()
    return _repo_skills_root()


def _slug(text: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9\u4e00-\u9fff]+", "-", text.strip().lower())
    s = re.sub(r"-+", "-", s).strip("-")
    return (s or "entry")[:48]


def journal_write(
    *,
    title: str,
    summary: str,
    tags: list[str] | None = None,
    platform: str | None = None,
    pattern: str = "",
    commands: list[str] | None = None,
    pitfalls: list[str] | None = None,
    root: str | Path | None = None,
) -> dict[str, Any]:
    """Write an anonymized journal entry and update _index.md."""
    base = journal_root(root)
    base.mkdir(parents=True, exist_ok=True)
    day = datetime.now(UTC).strftime("%Y-%m-%d")
    slug = _slug(title)
    fname = f"{day}_{slug}.md"
    path = base / fname

    safe_summary = redact_string(summary)
    safe_pattern = redact_string(pattern) if pattern else ""
    safe_cmds = [redact_string(c) for c in (commands or [])]
    safe_pits = [redact_string(p) for p in (pitfalls or [])]
    tag_list = tags or []
    if platform and platform not in tag_list:
        tag_list = [platform, *tag_list]

    body = f"""# {redact_string(title)}

- date: {day}
- platform: {platform or "any"}
- tags: {", ".join(tag_list) or "n/a"}

## Summary

{safe_summary}

## Reusable pattern

{safe_pattern or "n/a"}

## Commands (sanitized)

"""
    for c in safe_cmds or ["n/a"]:
        body += f"- `{c}`\n"
    body += "\n## Pitfalls\n\n"
    for p in safe_pits or ["n/a"]:
        body += f"- {p}\n"
    body += "\n## Notes\n\nMUST NOT contain tokens/cookies/PII. See anonymization.md.\n"
    path.write_text(body, encoding="utf-8")
    _update_index(base, fname, title, tag_list, platform)
    return {"ok": True, "path": str(path), "id": fname}


def journal_search(
    query: str = "",
    *,
    platform: str | None = None,
    limit: int = 10,
    root: str | Path | None = None,
) -> dict[str, Any]:
    base = journal_root(root)
    if not base.is_dir():
        return {"ok": True, "hits": [], "count": 0, "root": str(base)}
    q = (query or "").lower()
    plat = (platform or "").lower()
    hits: list[dict[str, Any]] = []
    for p in sorted(base.glob("*.md"), reverse=True):
        if p.name.startswith("_") or p.name in {"anonymization.md", "precedent-auth.md"}:
            continue
        text = p.read_text(encoding="utf-8", errors="ignore")
        low = text.lower()
        if plat and plat not in low and f"platform: {plat}" not in low:
            # soft filter
            if f"platform: {plat}" not in low and plat not in p.name.lower():
                continue
        if q and q not in low and q not in p.name.lower():
            continue
        title = p.stem
        for line in text.splitlines():
            if line.startswith("# "):
                title = line[2:].strip()
                break
        hits.append(
            {
                "file": p.name,
                "path": str(p),
                "title": title,
                "preview": redact_string(" ".join(text.split())[:180]),
            }
        )
        if len(hits) >= limit:
            break
    return {"ok": True, "hits": hits, "count": len(hits), "root": str(base), "query": query}


def _update_index(
    base: Path,
    fname: str,
    title: str,
    tags: list[str],
    platform: str | None,
) -> None:
    index = base / "_index.md"
    line = f"- [{title}]({fname}) — platform={platform or 'any'}; tags={','.join(tags) or 'n/a'}\n"
    if index.is_file():
        text = index.read_text(encoding="utf-8")
        if fname in text:
            return
        if not text.endswith("\n"):
            text += "\n"
        index.write_text(text + line, encoding="utf-8")
    else:
        index.write_text(
            "# Field Journal Index\n\n跨 Pack 脱敏经验索引。新条目追加到本文件。\n\n" + line,
            encoding="utf-8",
        )


def ensure_journal_scaffold(root: str | Path | None = None) -> dict[str, Any]:
    base = journal_root(root)
    base.mkdir(parents=True, exist_ok=True)
    created: list[str] = []
    files = {
        "_template.md": """# {title}

- date: YYYY-MM-DD
- platform: web|macos|windows|android|ios
- tags:

## Summary

## Reusable pattern

## Commands (sanitized)

## Pitfalls

## Notes

MUST NOT contain tokens/cookies/PII.
""",
        "anonymization.md": """# Anonymization Rules

- 替换 token/cookie/authorization 为 `[REDACTED]`
- 邮箱/手机号/姓名脱敏
- 内网 IP 可用 `10.x.x.x` 占位
- 保留可复用的命令形态与算法模式
""",
        "precedent-auth.md": """# Precedent: Authorization

仅在以下情形对目标 ACT：

1. 用户自有系统
2. 书面授权 / 合同范围
3. Bug bounty 明确 in-scope
4. 公开 CTF / 本地 lab

否则只允许 route / doctor / 静态离线分析，并要求 case.scope.auth.status=granted。
""",
        "_index.md": "# Field Journal Index\n\n跨 Pack 脱敏经验索引。\n\n",
    }
    for name, content in files.items():
        p = base / name
        if not p.is_file():
            p.write_text(content, encoding="utf-8")
            created.append(name)
    return {"ok": True, "root": str(base), "created": created}
