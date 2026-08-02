# Easy-Rev PRIMARY 快路径

> 与 `easy-rev route` / `skill.routing.master_route` 保持一致。

## 执行契约

```text
1. 先路由后动手（easy-rev route / ai call route）
2. 输出 PRIMARY + 一句话依据
3. case.init / scope.yaml — auth 未 granted 禁止对目标 ACT
4. doctor / preflight
5. 打开 PRIMARY skills/*/SKILL.md → ACTION REQUIRED
6. 过程追加 evidence / timeline；结论 Evidence→Finding→Path
7. 结束：pack.validate + journal.write（脱敏）
```

## 优先级（高 → 低）

| ID | 条件 | PRIMARY | platform |
|----|------|---------|----------|
| R-WEB | 网页/JS/签名/CDP/HAR | web-reverse | web |
| R-ANDROID | APK/jadx/pinning | mobile-reverse | android |
| R-IOS | IPA/越狱/Objection | mobile-reverse | ios |
| R-MACOS | Mach-O/.app/otool | desktop-reverse | macos |
| R-WINDOWS | PE/exe/dll | desktop-reverse | windows |
| R-DESKTOP | 通用桌面/Frida | desktop-reverse | desktop |
| R-MOBILE | 通用移动端 | mobile-reverse | mobile |
| R-PACK | pack/playbook 固化 | pack-ops | any |
| R-DOCTOR | 环境/依赖 | doctor | any |
| R0 | 未命中 | general-re | triage |

## 边界

- 站点/App 逻辑只进 `packs/<id>/`，不改 `src/easy_rev/**`（开发框架除外）
- 不把 dry_run / static 线索当成已完全还原协议
- 仅授权目标
