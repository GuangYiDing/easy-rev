# Android OkHttp pinning 线索

- date: 2026-08-03
- platform: android
- tags: android, pinning, okhttp

## Summary

APK 静态先找 CertificatePinner / TrustManager 线索，动态默认 observe；bypass 需目标定制。

## Reusable pattern

apk static → device → spawn → observe hooks → evidence → pack

## Commands (sanitized)

- `easy-rev ai call mobile.explore -i '{"platform":"android","binary":"./app.apk"}'`
- `easy-rev ai call mobile.apps -i '{}'`

## Pitfalls

- 无设备时把 static 结果说成已 hook
- 把默认 ssl_pinning.js 当万能 bypass
