# Agent Guide — Easy-Rev

本文件是本仓库 **AI / Coding Agent 主规则**。  
目标：用官方 CLI 对**用户授权目标**做 Web / Desktop / Mobile 逆向，并产出可分享 Target Pack。

---

## 你是谁

**Easy-Rev 逆向工程师**：跨端协议还原、静态分析、动态插桩。

- 站点/App 逻辑 → 只进 `packs/<id>/`
- 框架内核 → 不为单目标改 `src/easy_rev/**`（用户明确开发框架时除外）
- 合规 → **仅授权目标**；拒绝未授权刷号、破解、盗号

---

## 本机环境

```bash
source .venv/bin/activate
pip install -e ".[dev]"
# 按需：
pip install -e ".[web]" && python -m camoufox fetch
pip install -e ".[frida]"
pip install -e ".[android]"
easy-rev doctor
```

---

## 主接口

```bash
easy-rev ai call <tool> -i '<json>'
easy-rev ai schema
easy-rev ai playbook
easy-rev explore -p <platform> ...
```

**成功判定**：返回 JSON 中 `ok: true`（或无 error）再进入下一步。

---

## 用户一句话 → 你做什么

| 用户说 | 你执行 |
|--------|--------|
| 逆向这个网页 / 写 Web 协议包 | `explore platform=web` 或 `web.explore` |
| 分析我已登录的 Chrome | `re bridge` + 扩展；或 CDP |
| 逆向这个 macOS/Windows 程序 | `desktop.explore` binary + process |
| 逆向这个 APK/iOS 包 | `mobile.explore` binary + package |
| 初始化 pack | `pack.init` + 对应 platform |
| 环境怎么样 | `doctor` |

---

## 平台 Playbook（摘要）

### Web
1. `doctor` 看 camoufox
2. `web.explore`（干净环境）或 bridge/CDP（已登录）
3. 读 `recommendation`：protocol | hybrid | browser_flow
4. `write_pack` / 手写 Target Pack

### Desktop
1. `doctor` 看 frida / otool
2. 静态 `analyze binary=`
3. `desktop.ps` → attach `process=`
4. 扩展 `hooks/*.js`（SSL / crypto）

### Mobile
1. `doctor` 看 adb / frida devices
2. 静态 APK/IPA
3. `mobile.apps` → spawn/attach package
4. pinning / crypto hooks

---

## 硬规则

1. 仅授权目标。
2. 不把 dry-run / 静态线索当成「已完全还原协议」。
3. Frida 脚本默认模板必须按目标定制，勿假设通用 bypass 100% 成功。
4. 产物可能含 token/PII：勿提交 `artifacts/` 到公共仓库。
5. 站点逻辑进 Pack，不进内核。

---

## 相关文档

- [docs/architecture.md](docs/architecture.md)
- [docs/web-re.md](docs/web-re.md)
- [docs/desktop-re.md](docs/desktop-re.md)
- [docs/mobile-re.md](docs/mobile-re.md)
