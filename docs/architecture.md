# Architecture — Easy-Rev

商业级多端逆向框架：统一 `PlatformAdapter`，CLI / AI JSON 与平台解耦。

## 分层

```
easy_rev/
  core/                 # Platform / TargetSpec / ProbeResult / result status
  platforms/
    web/                # 浏览器引擎 + re/* 全套 Web 逆向
    desktop/            # Windows / macOS + Frida + 静态 PE/Mach-O/ELF
    mobile/             # Android / iOS + Frida + APK/IPA 静态
  pack/                 # Target Pack 模板
  ai/                   # Agent 工具面（JSON in/out）
  cli/                  # easy-rev 命令行
  storage/              # 可选 SQLite 产物索引
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

## Doctor

`easy-rev doctor` / `ai call doctor` 额外输出：

- `missing` — 缺失可选依赖名
- `install_hints` — 可复制安装命令
- `status_legend` — 状态字段说明

## Frida live sessions

In-process sessions (`easy_rev.platforms.common.frida_live`):

- `frida.session.start|stop|list|drain|eval`
- Messages: `schema=easy-rev.frida.message/v1` (`type`, `event`, `payload`, optional `error`)
- Missing frida → `status=dry_run` stub still drains schema messages

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
