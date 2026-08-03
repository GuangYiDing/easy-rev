# simplysign-desktop

目标：**OTP 尽量只输一次，支撑本机 / self-hosted CI 的 Windows 代码签名**。

应用：SimplySign Desktop `2.10.22`（Asseco / Certum 云签）  
链路：`jsign → libSimplySignPKCS.dylib → SimplySign Desktop → cloudsign.webnotarius.pl`

## 结论（2026-08-03 本机复核）

| 问题 | 答案 |
|------|------|
| 能不能「永远不再输 OTP」？ | **官方做不到**。私钥在 Certum 云 HSM，登录靠 OAuth + 手机 TOTP。 |
| 能不能「一次登录后长时间不用再输」？ | **能**。保持 Desktop 进程在线且云会话有效，同一会话内可连续 `SIGN_HASH`。 |
| 能不能进 CI/CD 自动发版？ | **能，但必须 self-hosted 本机/专用机**；GitHub 托管 runner 不合适。 |
| 重启/断会话后？ | 默认还要 OTP；可用 **TOTP 密钥自动输入** 做到无人值守重登。 |

## 更新（2026-08-03 晚场）：无 Desktop headless 签名已打通

**协议层已闭环**（`protocol/PROTOCOL.md`、`protocol/client.py`）：

- 抓到并保存 `refresh_token`（不轮转）+ 证书 PEM（`~/Library/Application Support/easy-rev/simplysign-session/`）。
- `python3 packs/simplysign-desktop/protocol/client.py refresh` → 无 OTP 续期 access_token（30 分钟）。
- `python3 packs/simplysign-desktop/protocol/client.py sign --file <exe>` → 云端 RSA 签名（签名可被证书公钥验证）。
- 含义：CI 可在**任何能出网、持有 token 的机器**上签名，不再依赖本机 Desktop 常驻；
  Desktop 只在首次登录（换 refresh_token）时需要。

> 安全提示：`refresh_token` + `cert.pem` 等同签名权，请按密钥保管（session 目录已 600，勿进 git）。

### 本机当前状态

- Desktop 进程已连续运行约 6+ 天（官方 LaunchAgent `pl.ads.SimplySignDesktop`）
- 偏好已关「启动即弹登录」；账号缓存 `<account>`
- PKCS 仍可列 softcard/证书
- **实际签名当前失败**（`CKR_FUNCTION_FAILED`）：能 list ≠ 能 sign，云端 access token 多半已失效
- 需要你在菜单栏 **Connect with cloud** 再输 **一次** OTP，签名就会恢复

## 推荐架构（发版 / CI）

```
[self-hosted macOS ARM64 runner / 本机]
   ├─ SimplySign Desktop 常驻（官方 LaunchAgent 开机自启）
   ├─ easy-rev keepalive 每 5 分钟探测会话
   │     └─ 失效时 macOS 通知「需要一次 OTP」
   └─ CI: npm run dist:win:certum / release:r2:win
```

`codex-configurator` 已有文档：`docs/windows-code-signing.md`  
workflow 应：

```yaml
runs-on: [self-hosted, macOS, ARM64]
```

不要把这张云证书接到 GitHub 托管 runner。

## 本机已落地

| 项 | 状态 |
|----|------|
| OTP-less 启动偏好 | 已写 `pl.ads.SimplySign-Desktop` |
| 官方开机自启 | `~/Library/LaunchAgents/pl.ads.SimplySignDesktop.plist` |
| 会话探测 | `~/Library/LaunchAgents/com.easyrev.simplysign-keepalive.plist`（5 分钟） |
| TOTP 自动重登脚本 | `scripts/auto-connect-totp.py`（需你存一次 otpauth secret） |

```bash
# 自检
pgrep -lf 'SimplySign Desktop'
tail -n 20 ~/Library/Logs/simplysign-keepalive.log
# 签名冒烟（需会话有效）
jsign --storetype PKCS11   --keystore /tmp/simplysign-pkcs11.cfg   --storepass 0000   --alias <CERT_ALIAS>   --tsaurl http://time.certum.pl   --alg SHA-256 your.exe
```

## 使用方式

1. 菜单栏 SimplySign → **Connect with cloud** → 输入 **一次** OTP  
2. 之后尽量：
   - 不要 Quit / Disconnect
   - 不要强杀进程
   - 保持 Mac 登录态（Aqua session）
3. 发版直接：`npm run dist:win:certum` 或 `npm run release:r2:win`

## 进一步：会话死后也不用手输 OTP

SimplySign 手机端绑定的是标准 TOTP。可把激活 QR 的 `otpauth://` 密钥存到密码管理器，再落到本机：

```bash
mkdir -p "$HOME/Library/Application Support/easy-rev/simplysign-session"
cat > "$HOME/Library/Application Support/easy-rev/simplysign-session/totp.env" <<'EOF'
CERTUM_OTP_URI=otpauth://totp/SimplySign:you@example.com?secret=BASE32SECRET&digits=6&period=30
EOF
chmod 600 "$HOME/Library/Application Support/easy-rev/simplysign-session/totp.env"
```

```bash
# 只看当前 OTP
python3 packs/simplysign-desktop/scripts/auto-connect-totp.py

# 先在菜单栏打开登录框，再自动键入 OTP（需辅助功能权限）
python3 packs/simplysign-desktop/scripts/auto-connect-totp.py --type
```

社区同类做法（Windows SendKeys）：  
https://www.devas.life/how-to-automate-signing-your-windows-app-with-certum/

这不是绕过 MFA，只是把手机 App 生成 OTP 的步骤自动化。

## 重启后完全免 OTP（未完成）

见 [REBOOT_PROOF.md](REBOOT_PROOF.md)：要抓 OAuth `refresh_token` 再静默 refresh。  
正式版有 Hardened Runtime，需 DEBUG 副本 + Frida；且 Certum 可能拒绝非交互 refresh。  
当前 `session.json` **尚未捕获**。

```bash
packs/simplysign-desktop/scripts/capture-oauth-once.sh
python3 packs/simplysign-desktop/scripts/silent-restore.py
```

## 脚本

- `scripts/start-simplysign-if-needed.sh` — 单实例启动
- `scripts/session-check-once.sh` — launchd 探测
- `scripts/session-keepalive.sh` — 前台循环
- `scripts/apply-otp-less-prefs.sh` — 偏好
- `scripts/auto-connect-totp.py` — TOTP 生成 / 自动键入
- `scripts/capture-oauth-once.sh` / `silent-restore.py` — 重启免 OTP 试验路径

## 合规

仅用于自有 Certum 证书与授权签名工作流。  
`totp.env` / `session.json` 含高敏感凭证：权限 600，勿提交 git。


## 协议化

见 [protocol/PROTOCOL.md](protocol/PROTOCOL.md)。

```bash
# 查看内置 OAuth client 配置
python3 packs/simplysign-desktop/protocol/client.py config

# 有 session.json 后尝试无 UI refresh
python3 packs/simplysign-desktop/protocol/client.py refresh

# 捕获一次登录+签名（会要求再 OTP 一次，换可解密流量）
packs/simplysign-desktop/scripts/capture-protocol-once.sh
```
