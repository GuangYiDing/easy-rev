# Desktop Frida SSL 先枚举再 hook

- date: 2026-08-03
- platform: macos
- tags: desktop, frida, ssl

## Summary

Mach-O/PE 先静态字符串与导入，再 `desktop.ps` 附着；SSL hook 模板必须按二进制定制。

## Reusable pattern

static → ps → attach(observe) → customize hooks → evidence

## Commands (sanitized)

- `easy-rev ai call desktop.explore -i '{"platform":"macos","binary":"/Apps/App.app/Contents/MacOS/App"}'`
- `easy-rev ai call desktop.ps -i '{}'`

## Pitfalls

- 通用 pinning bypass 直接当已成功
- 未写 repro_command 导致无法复现
