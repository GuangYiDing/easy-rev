#!/usr/bin/env bash
# 调整 SimplySign 偏好，减少「启动就弹 OTP」。改完建议重启 Desktop。
set -euo pipefail

DOMAIN="pl.ads.SimplySign-Desktop"

echo "Before:"
defaults read "$DOMAIN" 2>/dev/null || true

# 启动后不自动弹登录框（需要签名时再 Connect，或保持旧会话）
defaults write "$DOMAIN" SimplySignDesktopShowLogonDialogAfterApplicationStartup -int 0

# 保留：有应用请求且未登录时仍弹窗（避免 jsign 静默失败）
defaults write "$DOMAIN" SimplySignDesktopShowLogonDialogWhenAnyAppRequestsAccess -string Yes

# 继续缓存用户名
defaults write "$DOMAIN" CacheUserIdAtLogon -string Yes 2>/dev/null || true

echo "After:"
defaults read "$DOMAIN"

cat <<'MSG'

已写入偏好。请：
1) 退出 SimplySign Desktop（菜单 Quit）
2) 再打开 /Applications/SimplySign Desktop.app
3) 需要签名前手动 Connect with cloud，输入一次 OTP
4) 保持进程运行；配合 scripts/session-keepalive.sh

若要恢复启动弹窗：
  defaults write pl.ads.SimplySign-Desktop SimplySignDesktopShowLogonDialogAfterApplicationStartup -int 1
MSG
