# Web JS 签名 webpack 观察优先

- date: 2026-08-03
- platform: web
- tags: web, sign, webpack

## Summary

前端签名任务先 Observe 网络与 initiator，再最小化 hook，最后本地 Rebuild；避免空想补环境。

## Reusable pattern

Observe → Capture → Rebuild → Patch → DeepDive

## Commands (sanitized)

- `easy-rev route "网页签名"`
- `easy-rev ai call web.explore -i '{"url":"https://target.example"}'`
- `easy-rev ai call pack.from_capture -i '{"capture_path":"..."}'`

## Pitfalls

- 把 dry_run 当成功
- 跳过 capture 直接猜 HMAC 字段
