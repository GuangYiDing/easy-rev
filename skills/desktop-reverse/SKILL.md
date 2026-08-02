---
name: desktop-reverse
description: Windows/macOS 桌面二进制静态分析 + Frida 动态插桩，产出 Target Pack。
---

# Desktop Reverse — ACTION REQUIRED

1. route → desktop-reverse
2. case.guard ready
3. doctor path=static|dynamic
4. `desktop.explore` binary= 静态
5. `desktop.ps` → process= + scripts
6. 定制 `hooks/*.js`（SSL/crypto），写 evidence
7. pack.validate

默认 Frida 模板必须按目标定制；observe-first，勿假设通用 bypass 100% 成功。
