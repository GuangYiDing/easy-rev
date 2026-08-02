# simplysign-desktop

目标：**OTP 只输一次，之后本机持续 Windows 代码签名**。

## 已在本机落地（2026-08-02）

| 项 | 状态 |
|----|------|
| 当前云会话 | 有效（进程 PID 持有 `/CC_SM_FOR_RC*`，`pkcs11-tool` 可列证书） |
| 单实例守护 | `~/Library/LaunchAgents/pl.ads.SimplySignDesktop.plist` → `scripts/start-simplysign-if-needed.sh`（每 60s 确保进程在，不重复拉起） |
| 会话探测 | `~/Library/LaunchAgents/com.easyrev.simplysign-keepalive.plist` → 每 5 分钟探测；失效会通知「需要一次 OTP」 |
| 偏好 | 关闭「启动就弹登录」；保留「有应用请求且未登录时弹登录」 |

```bash
# 自检
pgrep -lf 'SimplySign Desktop'
pkcs11-tool --module /usr/local/lib/libSimplySignPKCS.dylib --login --pin 0000 --list-objects --type cert
tail -n 20 ~/Library/Logs/simplysign-keepalive.log
```

## 你要的使用方式

1. **现在如果已经能列证书**：什么都不用做，直接 `jsign` / `npm run dist:win:certum`。
2. **若菜单显示未连接 / 通知让你 OTP**：菜单栏 SimplySign → **Connect with cloud** → 输入 **一次** OTP。
3. **之后**：
   - 不要 Quit / Disconnect
   - 不要强杀进程
   - 签名多少次都不必再输 OTP（同一会话内已验证可连续 `SIGN_HASH`）

## 现实边界（必须说清）

- 私钥在 Certum 云端，**无法**做成完全离线、永不鉴权的本地签。
- 本机 OAuth token **主要挂在 Desktop 进程会话**里；Keychain 里没扫到可复用的 SimplySign refresh 条目。
- 因此：
  - **同一次登录会话内**：可以一直签（已测数小时+）。
  - **重启 Mac / 手动退出 Desktop / 云端吊销 token**：需要再 OTP **一次**。
- 我们做的是把「再 OTP」压到只在会话真死时发生，并用守护 + 通知兜住。

## 架构

```
jsign → libSimplySignPKCS.dylib → (shm) SimplySign Desktop → cloudsign.webnotarius.pl
```

## 脚本

- `scripts/start-simplysign-if-needed.sh` — 单实例启动
- `scripts/session-check-once.sh` — 单次会话探测（launchd 用）
- `scripts/session-keepalive.sh` — 前台循环版
- `scripts/apply-otp-less-prefs.sh` — 偏好调整

## Frida（可选深化）

`hooks/session_trace.js` — 需 macOS 调试权限才能 attach。用于抓 token refresh / session expired。

## 合规

仅用于自有 Certum 证书与本机授权签名工作流。


## 重启后也不要 OTP

这需要 **再完成一次** 受控 OTP 捕获（正式版有 Hardened Runtime，挖不出内存 token）。

详见 [REBOOT_PROOF.md](REBOOT_PROOF.md)。

```bash
packs/simplysign-desktop/scripts/capture-oauth-once.sh
python3 packs/simplysign-desktop/scripts/silent-restore.py
```
