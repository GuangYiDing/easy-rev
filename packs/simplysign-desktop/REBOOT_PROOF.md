# 重启后免 OTP — 实施路径

## 更新（2026-08-03 续）：双保险达成「首次 OTP 后永久无人值守」

- `refresh_token` **不能**作为唯一依赖：Certum 可随时吊销，无法保证永久无人值守。
- 保底层：TOTP 种子存 macOS 钥匙串
  （service `easy-rev-simplysign-totp`，写入走 `security -i` stdin，不落盘不入库）。
- 会话死后：`auto-recover.sh` 自动触发登录框并键入钥匙串生成的 OTP
  （`totp-keychain.py type --check`）。
- 达成条件（均为一次性配置）：
  1. 种子已导入钥匙串（`pbpaste | totp-keychain.py store`）；
  2. 系统设置 → 隐私与安全性 → 辅助功能，勾选运行脚本的终端/Codex；
  3. Mac 保持登录态，钥匙串解锁。
- 在此条件下，「重启/断会话后完全免手输 OTP」成立；否则退化为
  keepalive 通知人工输一次 OTP。

## 为什么正式版做不到“直接挖 token”

- `/Applications/SimplySign Desktop.app` 开启了 **Hardened Runtime**
- 本机 SIP 开启 → Frida/lldb **无法 attach** 正式进程
- Keychain 中 **没有** 找到已持久化的 SimplySign OAuth 条目  
  （NXOAuth2 虽支持 keychain，但当前会话更像内存态）

## 可行路径

```
[一次性] 在 DEBUG 副本登录并输 OTP
    → Frida 捕获 access_token + refresh_token (+ client_id/secret)
    → 写入 ~/Library/Application Support/easy-rev/simplysign-session/session.json

[之后每次开机]
    → silent-restore.py 用 refresh_token 换新 access_token（无 OTP）
    → 再把 token 注入 DEBUG Desktop 的连接态 / 或走云签 API
    → jsign 继续走 PKCS#11
```

## 一步：捕获（需要你参与一次 OTP）

```bash
packs/simplysign-desktop/scripts/capture-oauth-once.sh
```

在弹出的 **DEBUG** SimplySign 中：Connect with cloud → 输 OTP。  
成功后生成：

`~/Library/Application Support/easy-rev/simplysign-session/session.json`

## 二步：验证 refresh 是否可无交互

```bash
python3 packs/simplysign-desktop/scripts/silent-restore.py
```

- 若成功：云端允许 refresh，**重启免 OTP 在协议层成立**
- 若 401/invalid_grant：Certum 把 refresh 绑了交互策略，只能尽量拉长会话，无法保证重启后绝对免 OTP

## 三步：开机注入（待 refresh 验证成功后做）

计划：

1. LaunchAgent 启动 DEBUG Desktop（adhoc + get-task-allow）
2. Frida 注入 access_token 到 NXOAuth2Client / 触发内部 Connect 不弹 WebView
3. 保持 PKCS shm server，jsign 无感

或并行研究：直接调 `cloudsign.webnotarius.pl` 签名 API，绕过 Desktop。

## 边界

- 私钥永不落地；永远依赖 Certum 云端
- refresh_token 也可能被服务端轮转/吊销（改密、风控、证书过期）
- session.json 含高敏感凭证：权限 600，勿提交 git
