"""Evidence → Finding → Path chain for Target Packs / cases."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _case_root(root: str | Path) -> Path:
    return Path(root).expanduser().resolve()


def _next_id(existing: list[str], prefix: str) -> str:
    nums = []
    for x in existing:
        m = re.match(rf"{prefix}-(\d+)$", x, flags=re.I)
        if m:
            nums.append(int(m.group(1)))
    n = (max(nums) + 1) if nums else 1
    return f"{prefix}-{n:03d}"


def append_evidence(
    root: str | Path,
    *,
    title: str,
    repro_command: str = "",
    source_type: str = "command",
    source_ref: str = "",
    raw_excerpt: str = "",
    content_hash: str = "",
    linked_workitem: str = "",
    evidence_id: str | None = None,
) -> dict[str, Any]:
    root_p = _case_root(root)
    ev_dir = root_p / "evidence"
    ev_dir.mkdir(parents=True, exist_ok=True)
    existing = [p.stem for p in ev_dir.glob("E-*.md")]
    eid = evidence_id or _next_id(existing, "E")
    body = f"""### {eid}
- title: {title}
- observed_at: {_now()}
- source_type: {source_type}
- source_ref: {source_ref or "n/a"}
- content_hash: {content_hash or "n/a"}
- repro_command: |
    {repro_command or "n/a"}
- raw_excerpt: |
    {raw_excerpt or "n/a"}
- linked_workitem: {linked_workitem or "n/a"}
- supersedes: none
"""
    path = ev_dir / f"{eid}.md"
    path.write_text(body, encoding="utf-8")
    # index
    index = {
        "schema": "easy-rev.evidence-index/v1",
        "items": sorted([p.stem for p in ev_dir.glob("E-*.md")]),
    }
    (ev_dir / "index.yaml").write_text(
        yaml.safe_dump(index, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    return {"ok": True, "id": eid, "path": str(path)}


def append_finding(
    root: str | Path,
    *,
    title: str,
    severity: str = "info",
    category: str = "reverse_algo",
    status: str = "candidate",
    evidence_ids: list[str] | None = None,
    location: str = "",
    impact: str = "",
    confidence: str = "medium",
    repro_steps: list[str] | None = None,
    remediation: str = "n/a",
    finding_id: str | None = None,
) -> dict[str, Any]:
    root_p = _case_root(root)
    findings_path = root_p / "findings.md"
    text = findings_path.read_text(encoding="utf-8") if findings_path.is_file() else "# Findings\n\n"
    existing = re.findall(r"^### (F-\d+)", text, flags=re.M)
    fid = finding_id or _next_id(existing, "F")
    eids = evidence_ids or []
    steps = repro_steps or []
    step_lines = "\n".join(f"  {i}. {s}" for i, s in enumerate(steps, 1)) or "  1. n/a"
    block = f"""
### {fid}
- title: {title}
- severity: {severity}
- category: {category}
- status: {status}
- evidence_ids: [{', '.join(eids)}]
- location: {location or "n/a"}
- impact: {impact or "n/a"}
- confidence: {confidence}
- repro_steps:
{step_lines}
- remediation: {remediation}
"""
    if not text.endswith("\n"):
        text += "\n"
    findings_path.write_text(text + block, encoding="utf-8")
    return {"ok": True, "id": fid, "path": str(findings_path), "evidence_ids": eids}


def append_path(
    root: str | Path,
    *,
    title: str,
    path_type: str = "callflow",
    start: str = "",
    goal: str = "",
    steps: list[dict[str, str]] | None = None,
    residual_risks: str = "",
    path_id: str | None = None,
) -> dict[str, Any]:
    root_p = _case_root(root)
    path_file = root_p / "path.md"
    text = path_file.read_text(encoding="utf-8") if path_file.is_file() else "# Paths\n\n"
    existing = re.findall(r"^### (P-\d+)", text, flags=re.M)
    pid = path_id or _next_id(existing, "P")
    step_lines = []
    for i, s in enumerate(steps or [], 1):
        action = s.get("action") or s.get("step") or str(s)
        ev = s.get("evidence") or "n/a"
        finding = s.get("finding") or "none"
        step_lines.append(f"  {i}. action: {action} — evidence: {ev} — finding: {finding}")
    if not step_lines:
        step_lines = ["  1. action: n/a — evidence: n/a — finding: none"]
    block = f"""
### {pid}
- title: {title}
- path_type: {path_type}
- start: {start or "n/a"}
- goal: {goal or "n/a"}
- steps:
{chr(10).join(step_lines)}
- residual_risks: {residual_risks or "n/a"}
"""
    if not text.endswith("\n"):
        text += "\n"
    path_file.write_text(text + block, encoding="utf-8")
    return {"ok": True, "id": pid, "path": str(path_file)}


def ensure_ops_scaffold(root: str | Path) -> dict[str, Any]:
    """Create evidence/findings/path/timeline scaffolds if missing."""
    root_p = _case_root(root)
    root_p.mkdir(parents=True, exist_ok=True)
    created: list[str] = []
    ev = root_p / "evidence"
    if not ev.exists():
        ev.mkdir(parents=True, exist_ok=True)
        (ev / "README.md").write_text(
            "# Evidence\n\n每条证据一个 `E-XXX.md`。Finding 必须引用至少 1 条 Evidence。\n",
            encoding="utf-8",
        )
        created.append("evidence/")
    if not (root_p / "findings.md").is_file():
        (root_p / "findings.md").write_text(
            "# Findings\n\n> status: candidate | validated | false_positive | accepted_risk\n"
            "> confidence: high | medium | low\n\n",
            encoding="utf-8",
        )
        created.append("findings.md")
    if not (root_p / "path.md").is_file():
        (root_p / "path.md").write_text(
            "# Paths\n\n> path_type: attack | callflow | solve\n\n",
            encoding="utf-8",
        )
        created.append("path.md")
    if not (root_p / "timeline.md").is_file():
        (root_p / "timeline.md").write_text(
            f"# Timeline\n\n- {_now()} case scaffold created\n",
            encoding="utf-8",
        )
        created.append("timeline.md")
    return {"ok": True, "path": str(root_p), "created": created}
