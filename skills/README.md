# Easy-Rev Skills

方法论与作战契约层（吸收自 [reverse-skill](https://github.com/zhaoxuya520/reverse-skill) 的路由/scope/证据链/field-journal 思想），**执行面仍是 Easy-Rev CLI / AI tools / Target Pack**。

## 读序

```text
AGENTS.md → skills/MASTER-ROUTING.md → PRIMARY SKILL.md
  → case.init / scope.yaml
  → doctor → explore / attach
  → evidence → findings → path
  → journal（脱敏）
```

## 目录

| 路径 | 用途 |
|------|------|
| `MASTER-ROUTING.md` | PRIMARY 快路径 |
| `web-reverse/` | Web 五阶段工作流 |
| `desktop-reverse/` | Desktop 静态+Frida |
| `mobile-reverse/` | Android/iOS |
| `ops/` | scope / 证据链契约 |
| `field-journal/` | 跨 Pack 脱敏经验 |

## CLI

```bash
easy-rev route "逆向 APK SSL pinning"
easy-rev case init --hint "..." --auth-granted --target com.example
easy-rev case guard packs/my-target
easy-rev skill list
easy-rev skill journal-search "oauth"
```
