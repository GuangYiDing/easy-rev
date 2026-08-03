# Architecture — Easy-Rev

多端逆向框架：统一 `PlatformAdapter`，CLI / AI JSON 与平台解耦。

## 分层

```
easy_rev/
  core/                 # Platform / TargetSpec / ProbeResult / result status
  platforms/
    web/                # 浏览器引擎 + re/* 全套 Web 逆向
    desktop/            # Windows / macOS + Frida + 静态 PE/Mach-O/ELF
    mobile/             # Android / iOS + Frida + APK/IPA 静态
  pack/                 # Target Pack 模板 + run/validate
  skill/                # Router + scope gate + evidence + field-journal
  ai/                   # Agent 工具面（JSON in/out）
  cli/                  # easy-rev 命令行
  storage/              # 可选 SQLite 产物索引

skills/                 # 方法论 SKILL.md（Agent 可读，非内核）
```

统一入口：`PlatformAdapter.explore / capture / analyze / doctor`。

## 扩展点

| 点 | 做法 |
|----|------|
| 新平台 | 实现 `PlatformAdapter`，在 `get_adapter` 注册 |
| Frida 脚本 | 放入 `platforms/{desktop,mobile}/scripts/*.js` |
| Web 协议站点逻辑 | 只进 `packs/<id>/`，不改内核 |
| AI 工具 | `ai/tools.py` + `ai/handlers.py` |

## Unified dynamic status

动态路径（Frida / 浏览器）统一字段：

| field | meaning |
|-------|---------|
| `status` | `attached` \| `dry_run` \| `error` \| `offline` \| `degraded` \| `static` |
| `ok` | 调用完成无崩溃（`dry_run`/`offline` 也为 true） |
| `attached` | 真正附着 |
| `dry_run` | 可选依赖缺失，契约成功但未附着 |
| `degraded` | 从首选路径降级 |
| `hint` | 安装 / 下一步提示 |

实现：`easy_rev.core.result.dynamic_result`。

**注意**：`ok=true` 且 `dry_run=true` 不表示已成功插桩；Agent 应读 `status` / `attached`。

## Web degrade path

`web.explore` 在无 Camoufox/Playwright 且无 `cdp_url` 时：

1. 若提供 `capture_path` → offline 图/pack（`status=offline`）
2. 否则 → `status=degraded` + `install_hints`，不崩溃

## Doctor / Preflight / Auto-fix

统一依赖目录：`easy_rev.core.deps`（检测 + 安装配方 + readiness 分数）。

```bash
easy-rev doctor                      # 全端检查 + score/missing/fixable
easy-rev doctor -p web --path browser
easy-rev preflight -p android --path dynamic
easy-rev doctor --fix --dry-run     # 预览 pip 安装命令
easy-rev doctor --fix               # 自动补齐 fixable（pip / camoufox fetch）
easy-rev doctor --fix --only frida,camoufox
easy-rev ai call doctor.fix -i '{"ids":["frida"],"dry_run":true}'
easy-rev ai call doctor.catalog -i '{}'
```

输出字段：

- `platforms.*.score` / `ready` / `checks[]` / `capabilities`
- `missing_required` / `missing_recommended` / `fixable`
- `install_hints` / `next_steps` / `ai_hint`
- `status_legend`

Auto-fix 默认仅 pip extras + post_cmd（如 `camoufox fetch`）；`--allow-system` 才允许 brew。

## Frida live sessions

In-process sessions (`easy_rev.platforms.common.frida_live`):

- `frida.session.start|stop|list|drain|eval`
- Messages: `schema=easy-rev.frida.message/v1` (`type`, `event`, `payload`, optional `error`)
- Missing frida → `status=dry_run` stub still drains schema messages

## Skill Router + Ops

吸收 reverse-skill 作战契约，落地为可执行工具：

| tool | 作用 |
|------|------|
| `route` | PRIMARY 路由 |
| `case.init` / `case.guard` | scope 门禁 |
| `evidence.append` / `finding.append` / `path.append` | 证据链 |
| `journal.write` / `journal.search` | 脱敏经验库 |

`pack.run --execute` 前会跑 scope gate；dry-run 始终允许规划。

## Pack run

`pack.run` / `easy-rev pack run PATH`:

- default `dry_run=true` plans steps (local tools may execute)
- `--execute` runs mapped AI tools / minimal `http.request` replay
- Writes `run-dry-report.json` or `run-report.json`

## MCP

```bash
pip install 'easy-rev[mcp]'
easy-rev mcp
# or: python -m easy_rev.mcp_server
# or: easy-rev-mcp
```

Exposes all `TOOL_SPECS` over stdio MCP.

## 合规

仅授权目标。产物可能含 token/PII：勿提交 `artifacts/`。


## Result envelope (explore / dynamic)

Agent-facing explore results always include:

| field | meaning |
|-------|---------|
| `ok` | contract completed (true for dry_run/offline/degraded) |
| `status` | `attached` \| `dry_run` \| `error` \| `static` \| `offline` \| `degraded` |
| `attached` | truly instrumented / browser live |
| `dry_run` | optional dep missing; not attached |
| `degraded` | fallback path |
| `confidence` | `high` \| `medium` \| `low` \| `none` |
| `hint` / `next_steps` / `blocking_issues` | guidance |
| `artifacts` / `findings` | paths + structured detail |

`ProbeResult.to_envelope()` is the single serialization path used by `ai call explore`.
Pass `redact: true` to strip tokens/cookies before sharing.
