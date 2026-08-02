# Easy-Rev

<p align="center">
  <strong>商业级多端逆向工程框架</strong><br/>
  Web · Desktop (Windows / macOS) · Mobile (Android / iOS)
</p>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white" alt="Python" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License" /></a>
  <a href="#平台能力"><img src="https://img.shields.io/badge/Platforms-Web%20%7C%20Desktop%20%7C%20Mobile-8A2BE2" alt="Platforms" /></a>
  <a href="#ai--agent"><img src="https://img.shields.io/badge/AI-Agent%20%2B%20MCP-111111" alt="AI" /></a>
  <a href="#frida-会话"><img src="https://img.shields.io/badge/Frida-Live%20Session-FF6B00" alt="Frida" /></a>
  <a href="https://github.com/GuangYiDing/easy-rev/stargazers"><img src="https://img.shields.io/github/stars/GuangYiDing/easy-rev?style=social" alt="Stars" /></a>
</p>

<p align="center">
  <a href="#ai-agent-一键安装">🚀 Agent 一键安装</a> ·
  <a href="#快速开始">快速开始</a> ·
  <a href="#平台能力">平台能力</a> ·
  <a href="#ai--agent">AI / Agent</a> ·
  <a href="#target-pack">Target Pack</a> ·
  <a href="#文档">文档</a> ·
  <a href="#合规声明">合规</a>
</p>

---

**Easy-Rev** 把多端逆向收敛成统一 CLI 与 AI 工具面：一次 `explore` 覆盖抓包、静态分析、Frida 插桩与协议化产物，最终沉淀为可分享的 **Target Pack**。

面向安全研究、授权渗透测试、协议还原与 AI Coding Agent 自动化逆向。

> **仅用于自有系统、书面授权测试与合法安全研究。禁止未授权逆向、刷号、盗号或破解。**

---

## 为什么选 Easy-Rev

| 痛点 | Easy-Rev 的做法 |
|------|----------------|
| 工具链割裂（浏览器 / Frida / APK 各玩各的） | 统一 `PlatformAdapter`：`explore` / `capture` / `analyze` / `doctor` |
| 环境难配、依赖黑盒 | `doctor` + `preflight` 打分、缺失清单、可一键 `--fix` |
| 结果难复现、难交接 | **Target Pack**（`pack.yaml` + playbook + hooks）可分享、可 dry-run / 执行 |
| Agent 无法稳定驱动逆向 | **JSON in / JSON out** 工具面 + **MCP stdio** 服务 |
| Web 已登录场景难抓 | Chrome 扩展 Bridge + CDP 附着 |
| 动态路径误判成功 | 统一 `status`：`attached` / `dry_run` / `degraded` / … |

---

## 平台能力

| 平台 | 静态 | 动态 | 亮点 |
|------|------|------|------|
| **Web** | JS 签名/风险分析、依赖图、HAR | Camoufox 反检测浏览器、runtime/crypto hooks、会话 | 一键 explore → 协议化 Pack；Chrome 扩展完整逆向 |
| **Desktop** | PE / Mach-O（Windows · macOS） | Frida 附着、内置 SSL/crypto/http/module 脚本 | `desktop ps` + explore；Live Session drain |
| **Mobile** | APK / IPA | Frida spawn/attach、设备与应用枚举 | Pinning / crypto hooks；Android 深度静态（androguard 可选） |

```text
                    ┌─────────────────────────────────────┐
                    │     easy-rev CLI  ·  AI tools  ·  MCP │
                    └─────────────────┬───────────────────┘
                                      │
              ┌───────────────────────┼───────────────────────┐
              ▼                       ▼                       ▼
        ┌──────────┐            ┌──────────┐            ┌──────────┐
        │   Web    │            │ Desktop  │            │  Mobile  │
        │ Camoufox │            │ PE/Mach-O│            │ APK/IPA  │
        │ CDP/Ext  │            │  Frida   │            │  Frida   │
        └────┬─────┘            └────┬─────┘            └────┬─────┘
             │                       │                       │
             └───────────────────────┼───────────────────────┘
                                     ▼
                          ┌────────────────────┐
                          │   Target Pack      │
                          │  playbook · hooks  │
                          └────────────────────┘
```

---

## AI Agent 一键安装

不想自己敲命令？把下面**整段提示词**复制给 Cursor / Claude Code / Codex / Windsurf / ChatGPT 等任意 Agent，它会自动完成 clone、虚拟环境、依赖安装与 `doctor` 修复。

### 用法

1. 复制下方提示词（可按注释改平台与安装范围）
2. 粘贴给本地有终端权限的 Agent
3. 等它跑完并汇报 `doctor` 结果即可开始逆向

### 提示词（复制即用）

````md
# 任务：一键安装并配置 Easy-Rev（多端逆向框架）

请你作为本机环境工程师，**自动**为我安装并验证 [Easy-Rev](https://github.com/GuangYiDing/easy-rev)，完成后用简洁中文汇报结果。

## 目标能力（按需二选一，默认 full）
- full：Web + Desktop/Mobile 动态 + MCP（`pip install -e ".[all]"`）
- web-only：仅 Web（`".[dev,web,mcp]"` + camoufox fetch）
- desktop-mobile：桌面/移动动态（`".[dev,frida,android,mcp]"`）

当前选择：**full**

## 硬约束
1. 需要 Python **3.11+**；若版本不够，说明如何升级，不要静默用旧版本硬装。
2. 优先使用项目内 **venv**（`.venv`），不要污染系统 Python。
3. macOS / Linux 用 `source .venv/bin/activate`；Windows 用 `.venv\Scripts\activate`。
4. 默认**不要**执行 `doctor --fix --allow-system`（不擅自 brew/装系统包）；若缺系统工具，只列出安装建议让我确认。
5. 仅做环境配置与自检；**不要**对未授权目标做 explore / 抓包 / 插桩。
6. 每步失败要读报错并修复或给出明确阻塞原因；不要假装成功。

## 执行步骤（按序）

### A. 取得源码
- 若当前目录已是 easy-rev 仓库（存在 `pyproject.toml` 且 name 为 easy-rev）：直接使用。
- 否则：
  ```bash
  git clone https://github.com/GuangYiDing/easy-rev.git
  cd easy-rev
  ```
- 若我指定了工作目录，在该目录下操作。

### B. 创建并激活虚拟环境
```bash
python3 --version   # 必须 ≥ 3.11；没有 python3 再试 python
python3 -m venv .venv
# macOS/Linux:
source .venv/bin/activate
# Windows PowerShell:
# .venv\Scripts\Activate.ps1
python -m pip install -U pip setuptools wheel
```

### C. 安装框架
```bash
# full（默认）
pip install -e ".[all]"

# web-only 时改为：
# pip install -e ".[dev,web,mcp]"

# desktop-mobile 时改为：
# pip install -e ".[dev,frida,android,mcp]"
```

若选择含 Web（full / web-only），再执行：
```bash
python -m camoufox fetch
```
（失败则记录，继续 doctor，不要整段中止。）

可选：若存在 `.env.example` 且无 `.env`：
```bash
cp .env.example .env
```

### D. 自检与自动修复（仅 pip 级）
```bash
easy-rev --version
easy-rev doctor
easy-rev doctor --fix --dry-run
easy-rev doctor --fix
```

按我选择的能力再跑预检（有则执行）：
```bash
# full 或 web-only
easy-rev preflight -p web --path browser
# full 或 desktop-mobile
easy-rev preflight -p macos --path dynamic   # 非 macOS 可跳过或改 windows/android
easy-rev preflight -p android --path dynamic
```

### E. 让 Agent 能驱动逆向（读规则）
- 阅读并遵守仓库根目录 `AGENTS.md`
- 主接口：
  - `easy-rev ai tools` / `ai schema` / `ai playbook`
  - `easy-rev ai call <tool> -i '<json>'`
  - `easy-rev explore -p <platform> ...`
- 成功判定：看返回 JSON 的 `ok`，动态路径还要看 `status` / `attached`（`dry_run` ≠ 已插桩）

### F. 交付报告（必须）
用中文输出：
1. 安装路径、Python 版本、是否 venv
2. 已安装 extras（all / web / frida / …）
3. `easy-rev doctor` 的 ready / score 摘要与 missing 列表
4. 仍需我手动安装的系统依赖（adb / frida-server / Xcode CLT 等）及建议命令
5. 下一步我可以复制执行的 3 条示例命令（Web explore / desktop analyze / pack init，占位 URL 用「授权站」）

现在开始执行，不要只给说明。
````

### 变体：已在仓库内

若 Agent 已经打开本仓库，可用更短版本：

````md
请按本仓库 README「AI Agent 一键安装」与 AGENTS.md，在当前目录用 .venv 安装 easy-rev（默认 `pip install -e ".[all]"`，含 Web 时执行 `python -m camoufox fetch`），然后跑 `easy-rev doctor` 与 `easy-rev doctor --fix`，用中文汇报 ready/missing 与下一步命令。不要对未授权目标做逆向。
````

### 装好后 Agent 常用接口

```bash
easy-rev ai playbook
easy-rev ai call doctor -i '{}'
easy-rev ai call explore -i '{"platform":"web","url":"https://授权站/"}'
```

---

## 快速开始

### 要求

- Python **3.11+**
- macOS / Linux / Windows（桌面与移动动态能力依赖本机工具链，见 `doctor`）

### 手动安装

```bash
git clone https://github.com/GuangYiDing/easy-rev.git
cd easy-rev

python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

pip install -e ".[dev]"

# 按需安装可选能力
pip install -e ".[web]"     && python -m camoufox fetch   # Web 真浏览器
pip install -e ".[frida]"                                 # 桌面 / 移动动态插桩
pip install -e ".[android]"                               # Android 深度静态
pip install -e ".[tls]"                                   # TLS 指纹协议重放
pip install -e ".[mcp]"                                   # MCP Server
# 或：pip install -e ".[all]"
```

### 30 秒自检

```bash
easy-rev doctor
easy-rev doctor -p web
easy-rev doctor --fix --dry-run    # 预览可自动安装的依赖命令
easy-rev doctor --fix              # 自动补齐 fixable 的 pip 依赖
easy-rev preflight -p web --path browser
```

### 一键探索（授权目标）

```bash
# Web：抓包 + 签名线索 + 依赖图 + 可选写 Pack
easy-rev web explore "https://授权站/path" --write-pack --pack-id my-site

# 统一入口
easy-rev explore -p web --url "https://授权站/path"
easy-rev explore -p macos --binary /path/to/App --process "App"
easy-rev explore -p android --binary ./app.apk --package com.example.app
```

---

## 使用示例

### Web

```bash
# Camoufox 探索
easy-rev web explore "https://授权站/signup" --write-pack --pack-id my-site

# 已登录 Chrome：扩展 Bridge
easy-rev re bridge
# Chrome → 开发者模式加载 extensions/easy-rev-chrome
easy-rev re bridge-status

# 从 capture 构建协议 Pack / 导出 HAR
easy-rev ai call pack.from_capture -i '{"path":"./artifacts/capture.json","pack_id":"my-site"}'
easy-rev ai call web.har_export -i '{"path":"./artifacts/capture.json"}'
```

### Desktop（Windows / macOS）

```bash
easy-rev desktop analyze /path/to/App.app/Contents/MacOS/App
easy-rev desktop ps
easy-rev desktop explore --process "MyApp" --binary /path/to/binary
easy-rev ai call desktop.scripts -i '{}'
```

### Mobile（Android / iOS）

```bash
easy-rev mobile devices
easy-rev mobile apps
easy-rev mobile analyze ./app.apk
easy-rev mobile explore --binary ./app.apk --package com.example.app
easy-rev explore -p ios --package com.example.app --device <udid>
```

### Target Pack

```bash
easy-rev pack init demo-web --platform web --with-hooks
easy-rev pack list
easy-rev pack validate ./packs/demo-web
easy-rev pack run ./packs/demo-web              # 默认 dry-run
easy-rev pack run ./packs/demo-web --execute    # 真执行（慎用，仅授权目标）
```

内置示例：`packs/demo-web`、`packs/demo-android`。

---

## AI / Agent

Easy-Rev 为 Coding Agent 设计：**稳定契约、可机器解析、可预检环境**。

```bash
easy-rev ai tools          # 工具列表
easy-rev ai schema         # JSON Schema
easy-rev ai playbook       # 推荐操作剧本
easy-rev ai call doctor -i '{}'
easy-rev ai call explore -i '{"platform":"web","url":"https://授权站/"}'
easy-rev ai call explore -i '{"platform":"macos","binary":"/path","process":"App"}'
easy-rev ai call explore -i '{"platform":"android","binary":"./a.apk","package":"com.x"}'
```

### MCP

```bash
pip install 'easy-rev[mcp]'
easy-rev mcp               # stdio MCP，暴露全部 AI tools
# 或：easy-rev-mcp
```

Agent 规则与工作流见 **[AGENTS.md](AGENTS.md)**。

### 动态状态语义（必读）

| `status` | 含义 |
|----------|------|
| `attached` | 已真正附着 Frida / 浏览器 |
| `dry_run` | 缺可选依赖，契约成功但未附着（`ok` 仍可为 true） |
| `offline` / `degraded` | Web 无浏览器时的降级路径 |
| `static` | 仅静态分析 |
| `error` | 尝试失败 |

**请同时读 `status` / `attached`，不要只看 `ok`。** `doctor` 会给出 `install_hints` 与 readiness score。

### Frida 会话

```bash
easy-rev ai call frida.session.start -i '{"kind":"desktop","target":"MyApp","scripts":["module_enum.js"]}'
easy-rev ai call frida.session.drain -i '{"session_id":"..."}'
easy-rev ai call frida.session.stop  -i '{"session_id":"..."}'
```

消息 schema：`easy-rev.frida.message/v1`。

---

## 架构一览

```text
easy_rev/
  core/           # Target / Platform / Artifact / 统一 dynamic_result
  platforms/
    web/          # 浏览器引擎 + re/*（抓包、签名、依赖图、协议化…）
    desktop/      # Windows / macOS + Frida + 静态分析
    mobile/       # Android / iOS + Frida + APK/IPA
  pack/           # Target Pack 模板、校验、运行
  ai/             # Agent 工具注册与 handler
  cli/            # easy-rev 命令行
  storage/        # 可选 SQLite 产物索引
```

统一扩展点：

| 扩展 | 做法 |
|------|------|
| 新平台 | 实现 `PlatformAdapter`，注册到 `get_adapter` |
| Frida 脚本 | `platforms/{desktop,mobile}/scripts/*.js` |
| 站点 / App 逻辑 | **只进** `packs/<id>/`，不改内核 |
| AI 工具 | `ai/tools.py` + `ai/handlers.py` |

详见 [docs/architecture.md](docs/architecture.md)。

---

## 项目结构

```text
easy-rev/
├── src/easy_rev/          # 框架内核
├── packs/                 # Target Pack 示例与目标剧本
├── extensions/
│   └── easy-rev-chrome/   # Chrome 扩展（Bridge 抓包）
├── docs/                  # 架构与分平台说明
├── tests/                 # 契约与深度测试
├── AGENTS.md              # AI Agent 主规则
└── pyproject.toml
```

---

## 文档

| 文档 | 内容 |
|------|------|
| [AGENTS.md](AGENTS.md) | AI / Agent 操作规则与 playbook 摘要 |
| [docs/architecture.md](docs/architecture.md) | 分层架构、状态模型、扩展点 |
| [docs/web-re.md](docs/web-re.md) | Web 逆向、Bridge、协议化 |
| [docs/desktop-re.md](docs/desktop-re.md) | 桌面静态 + Frida |
| [docs/mobile-re.md](docs/mobile-re.md) | 移动端静态 + Frida |
| [extensions/easy-rev-chrome/README.md](extensions/easy-rev-chrome/README.md) | Chrome 扩展说明 |

---

## 开发

```bash
source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
ruff check src tests
```

建议贡献前：

1. 跑通 `easy-rev doctor` 与相关平台 `preflight`
2. 新能力优先挂到 `ai` 工具面（JSON 契约）
3. 目标相关逻辑进 Pack，勿污染 `src/easy_rev/**` 内核

---

## 路线图（摘要）

- [x] 统一多端 `explore` / `analyze` / `capture`
- [x] Doctor 依赖目录、打分、auto-fix
- [x] Target Pack 校验与 dry-run / execute
- [x] AI tools + MCP stdio
- [x] Web：Camoufox、扩展 Bridge、CDP、协议草稿
- [x] Desktop / Mobile：静态 + Frida Live Session
- [ ] 更多开箱即用 Pack 与 Frida 脚本模板
- [ ] 协议回放与 TLS 指纹路径的端到端示例
- [ ] 发布稳定版 PyPI 包与变更日志

欢迎通过 Issue / PR 提议优先级。

---

## 合规声明

本项目仅供：

- 你**拥有**或已获**书面授权**的系统
- 合法安全研究、教学与防御性评估

**禁止**用于未授权访问、账号滥用、破解付费或任何违法用途。使用者自行承担合规责任。

产物可能含 token / Cookie / PII：请勿将 `artifacts/` 与敏感 Pack 提交到公共仓库。

---

## 许可证

[MIT](LICENSE) © easy-rev contributors

---

## 致谢

- [Frida](https://frida.re/) — 动态插桩
- [Camoufox](https://camoufox.com/) — 反检测浏览器
- 以及所有开源安全工具链的贡献者

---

<p align="center">
  如果 Easy-Rev 对你有帮助，请点一个 ⭐ Star — 这是对我们最大的鼓励。
</p>
