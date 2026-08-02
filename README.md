# Easy-Rev

商业级 **多端逆向工程框架**：

| 平台 | 能力 |
|------|------|
| **Web** | 抓包 / 签名分析 / 依赖图 / 协议化 / Chrome 扩展 / CDP（自 [easy-reg](../easy-reg) 迁入并重构） |
| **Desktop** | Windows / macOS 静态分析（PE·Mach-O）+ Frida 动态插桩 |
| **Mobile** | Android / iOS 静态（APK·IPA）+ Frida spawn/attach + 设备探测 |

> 仅用于自有系统、授权测试与合法安全研究。禁止未授权逆向。

## 架构

```
easy_rev/
  core/                 # 统一 Target / Platform / Artifact 模型
  platforms/
    web/                # 浏览器引擎 + re/* 全套 Web 逆向
    desktop/            # Windows / macOS + Frida + 静态分析
    mobile/             # Android / iOS + Frida + APK/IPA 分析
  pack/                 # Target Pack（可分享逆向剧本）
  ai/                   # AI Agent 工具面（JSON in/out）
  cli/                  # easy-rev 命令行
```

统一入口：`PlatformAdapter.explore / capture / analyze`，上层 CLI / AI 与平台解耦。

## 安装

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Web 真浏览器
pip install -e ".[web]"
python -m camoufox fetch

# 桌面 / 移动 动态插桩
pip install -e ".[frida]"

# Android 深度静态（可选）
pip install -e ".[android]"

# TLS 指纹协议重放（可选）
pip install -e ".[tls]"

# 或一键可选依赖
# pip install -e ".[all]"

cp .env.example .env 2>/dev/null || true
easy-rev doctor   # 含 missing + install_hints
```

## 快速开始

### 自检

```bash
easy-rev doctor
easy-rev doctor -p web
easy-rev doctor -p android
```

### Web 逆向

```bash
# Camoufox 一键探索（抓包 + 签名 + 依赖图）
easy-rev web explore "https://授权站/signup" --write-pack --pack-id my-site

# 或统一入口
easy-rev explore -p web --url "https://授权站/signup"

# 已登录 Chrome：扩展 bridge
easy-rev re bridge
# Chrome → 开发者模式加载 extensions/easy-rev-chrome
easy-rev re bridge-status
```

### Desktop 逆向（Windows / macOS）

```bash
# 静态分析二进制
easy-rev desktop analyze /path/to/App.app/Contents/MacOS/App
# 或
easy-rev explore -p macos --binary /path/to/binary

# 列进程 + 动态附着（需 frida）
easy-rev desktop ps
easy-rev desktop explore --process "MyApp" --binary /path/to/binary
```

### Mobile 逆向（Android / iOS）

```bash
# 设备与应用
easy-rev mobile devices
easy-rev mobile apps

# APK 静态 + 可选 Frida spawn
easy-rev mobile analyze ./app.apk
easy-rev mobile explore --binary ./app.apk --package com.example.app

easy-rev explore -p android --binary ./app.apk --package com.example.app
easy-rev explore -p ios --package com.example.app --device <udid>
```

### Target Pack

```bash
easy-rev pack init demo-web --platform web --with-hooks
easy-rev pack init demo-android --platform android --with-hooks
easy-rev pack list
```

## AI Agent 接口

```bash
easy-rev ai tools
easy-rev ai schema
easy-rev ai playbook
easy-rev ai call doctor -i '{}'
easy-rev ai call explore -i '{"platform":"web","url":"https://…"}'
easy-rev ai call explore -i '{"platform":"macos","binary":"/path","process":"App"}'
easy-rev ai call explore -i '{"platform":"android","binary":"./a.apk","package":"com.x"}'
```

规则文件见 [AGENTS.md](AGENTS.md)。

## 与 easy-reg 的关系

| | easy-reg | easy-rev |
|--|----------|----------|
| 定位 | Web **批量注册** + 站点 Pack | **多端逆向** 框架 |
| Web 逆向 | 子模块 `re/*` | 一等公民 `platforms/web` |
| 桌面 / 移动 | 无 | Desktop + Mobile |
| 产物 | 注册账号 / Site Pack | Capture / 协议 Pack / Frida 日志 / 静态报告 |

Web 侧能力对齐 easy-reg：`re.explore`、runtime/crypto hooks、auto_sign、依赖图、HAR、Chrome 扩展完整逆向、CDP 附着。

## 文档

| 文档 | 内容 |
|------|------|
| [AGENTS.md](AGENTS.md) | AI 主规则 |
| [docs/architecture.md](docs/architecture.md) | 架构与扩展点 |
| [docs/web-re.md](docs/web-re.md) | Web 逆向说明 |
| [docs/desktop-re.md](docs/desktop-re.md) | 桌面端逆向 |
| [docs/mobile-re.md](docs/mobile-re.md) | 移动端逆向 |

## 状态语义（动态路径）

| status | 含义 |
|--------|------|
| `attached` | 已附着 Frida / 浏览器 |
| `dry_run` | 缺可选依赖，未附着（`ok` 仍可为 true） |
| `offline` / `degraded` | Web 无浏览器时的降级路径 |
| `error` | 尝试失败 |

Agent 请读 `status` / `attached`，勿仅看 `ok`。`doctor` 会输出 `install_hints`。

### Pack 运行 / Frida 会话 / MCP

```bash
easy-rev pack validate ./packs/demo-web
easy-rev pack run ./packs/demo-web              # dry-run（默认）
easy-rev pack run ./packs/demo-web --execute    # 真执行（慎用）

easy-rev ai call frida.session.start -i '{"kind":"desktop","target":"MyApp","scripts":["module_enum.js"]}'
easy-rev ai call frida.session.drain -i '{"session_id":"..."}'

pip install 'easy-rev[mcp]'
easy-rev mcp   # stdio MCP，暴露全部 AI tools
```

## 开发

```bash

source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

## 许可证

MIT
