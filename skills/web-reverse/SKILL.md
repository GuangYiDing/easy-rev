---
name: web-reverse
description: Web / JS 签名与协议还原。Observe→Capture→Rebuild→Patch→DeepDive，固化为 Target Pack。
---

# Web Reverse — ACTION REQUIRED

1. `NOW`: `easy-rev route` 确认 PRIMARY=web-reverse
2. `NOW`: `case.init` / `case.guard`（auth granted）
3. `NEXT`: `doctor` path=browser
4. `ACT`: 按五阶段执行，禁止只回复“明白了”

## 五阶段

1. **Observe** — `web.explore` / network / initiator / js 分析
2. **Capture** — crypto/runtime hooks、HAR、`web.diff_capture`
3. **Rebuild** — `pack.from_capture` / `web.offline_chain` / draft protocol
4. **Patch** — `web.sign_synth`、字段探测、本地复现
5. **DeepDive** — 去混淆/长期算法提纯（按需）

## 成功判定

- `status=attached` 才算浏览器路径成功
- `dry_run` / `degraded` ≠ 已还原
- 产物：scope + evidence + findings + pack
