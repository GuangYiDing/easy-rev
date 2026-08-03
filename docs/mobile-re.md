# Mobile 逆向（Android / iOS）

## 目标

1. **静态**：APK/IPA 包结构、包名、权限、URL、SSL Pinning、多 DEX 混淆；**native ELF/so 分析**；**DEX string_ids**；**AXML string pool + start-element 树**；IPA **Payload 二进制/framework Mach-O 线索**  
2. **动态**：Frida USB/remote spawn·attach；**live session**（start/drain/eval）；Android Java hooks + **iOS ObjC 脚本模板**  
3. **设备**：adb / idevice / frida device 列表

## 安装

```bash
pip install -e ".[frida]"
pip install -e ".[android]"   # androguard 可选深度解析

# Android
# - 安装 adb
# - 设备 root 或可调试 + frida-server

# iOS
# - libimobiledevice（idevice_id 等）
# - 已越狱设备 + frida
```

## 命令

```bash
easy-rev doctor -p android
easy-rev mobile devices
easy-rev mobile apps

easy-rev mobile analyze ./app.apk
easy-rev mobile explore --binary ./app.apk --package com.example.app

easy-rev explore -p ios --package com.example.app --device <udid>
```

## AI

```bash
easy-rev ai call mobile.explore -i '{
  "platform": "android",
  "binary": "./app.apk",
  "package": "com.example.app",
  "spawn": true,
  "duration_s": 10,
  "scripts": ["packs/my-android/hooks/ssl_pinning.js"]
}'
```

## 产物

- `artifacts/mobile/<name>/static_report.json`
- `artifacts/mobile/frida/capture-*.jsonl` / `summary-*.json`

## Target Pack

```bash
easy-rev pack init my-android --platform android --with-hooks
# hooks/ssl_pinning.js  crypto.js  network.js
```

## 脚本库

| 脚本 | 端 |
|------|-----|
| `ssl_pinning.js` / `crypto.js` / `network.js` | Android (Java) |
| `ios_ssl.js` / `ios_crypto.js` | iOS (ObjC / CommonCrypto) |

```bash
easy-rev mobile scripts
easy-rev mobile scripts ios_ssl.js
easy-rev ai call mobile.scripts -i '{"name":"ios_crypto"}'
```

## 安全提示

- 仅在**自有或书面授权**应用上使用
- 生产 App 的 pinning/加固绕过涉及法律与 ToS，默认模板仅为结构示意
- 勿将含 token 的 capture 提交公共仓库

## 已具备的深度

- **APK**：包名/权限/URL/多 DEX 混淆线索/native so、`network_security_config` pin-set、META-INF 签名线索
- **IPA**：CFBundleIdentifier、MinimumOSVersion、NSPinnedDomains/TrustKit、framework 枚举
- **androguard**：可选深度，缺失不阻断基础路径
- **Frida**：无设备/无安装时 `dry_run`+`hint`；捆绑 `ssl_pinning.js` / `crypto.js` / `network.js`
- CLI：`easy-rev mobile scripts`

## 路线图

- jadx/apktool 流水线封装
- objection 风格交互会话
- iOS dump decrypted IPA 辅助
