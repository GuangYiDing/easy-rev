# simplysign-desktop

目标：**OTP 尽量只输一次，支撑授权的 Windows 代码签名自动化**。

应用：SimplySign Desktop `2.10.22`（Asseco / Certum 云签）  
链路：`jsign → libSimplySignPKCS.dylib → SimplySign Desktop → cloudsign.webnotarius.pl`

## 结论（2026-08-03 本机复核）

| 问题 | 答案 |
|------|------|
| 能不能「永远不再输 OTP」？ | **官方做不到**。私钥在 Certum 云 HSM，登录靠 OAuth + 手机 TOTP。 |
| 能不能「一次登录后长时间不用再输」？ | **能**。保持 Desktop 进程在线且云会话有效，同一会话内可连续 `SIGN_HASH`。 |
| 能不能自动化签名？ | **能**，但凭据必须使用受保护的本地存储或秘密管理服务。 |
| 重启/断会话后？ | 默认还要 OTP；可用 **TOTP 密钥自动输入** 做到无人值守重登。 |

## 更新（2026-08-03 晚场）：无 Desktop headless 签名已打通

**协议层已闭环**（`protocol/PROTOCOL.md`、`protocol/client.py`）：

- 抓到并保存 `refresh_token`（不轮转）+ 证书 PEM（`~/Library/Application Support/easy-rev/simplysign-session/`）。
- `python3 packs/simplysign-desktop/protocol/client.py refresh` → 无 OTP 续期 access_token（30 分钟）。
- `python3 packs/simplysign-desktop/protocol/client.py sign --file <exe>` → 云端 RSA 签名（签名可被证书公钥验证）。
- 含义：协议客户端可在受控环境中完成签名，不再依赖 Desktop 常驻；
  Desktop 只在首次登录（换 refresh_token）时需要。

> 安全提示：`refresh_token` + `cert.pem` 等同签名权，请按密钥保管（session 目录已 600，勿进 git）。

### 本机当前状态

- Desktop 进程已连续运行约 6+ 天（官方 LaunchAgent `pl.ads.SimplySignDesktop`）
- 偏好已关「启动即弹登录」；账号缓存 `<account>`
- PKCS 仍可列 softcard/证书
- **实际签名当前失败**（`CKR_FUNCTION_FAILED`）：能 list ≠ 能 sign，云端 access token 多半已失效
- 需要你在菜单栏 **Connect with cloud** 再输 **一次** OTP，签名就会恢复

## 自动化边界

- 本 Pack 只提供会话恢复和协议客户端，不记录下游业务仓库或发布流程。
- 调用方应按自身环境集成，不得将 TOTP 种子、token、证书或客户端密钥写入仓库与日志。
- 仅在用户授权的证书和签名目标上使用。

## 本机已落地

| 项 | 状态 |
|----|------|
| OTP-less 启动偏好 | 已写 `pl.ads.SimplySign-Desktop` |
| 官方开机自启 | `~/Library/LaunchAgents/pl.ads.SimplySignDesktop.plist` |
| 会话探测 | launchd 5 分钟（plist 当前 `.disabled`，启用步骤见下） |
| TOTP 种子 | macOS 钥匙串 `easy-rev-simplysign-totp`（一次性导入，不落盘/不提交） |
| TOTP 自动重登 | `scripts/auto-recover.sh` + `totp-keychain.py type`（会话死后自动键入 OTP） |

```bash
# 自检
pgrep -lf 'SimplySign Desktop'
tail -n 20 ~/Library/Logs/simplysign-keepalive.log
# 签名冒烟（需会话有效）
jsign --storetype PKCS11   --keystore /tmp/simplysign-pkcs11.cfg   --storepass 0000   --alias <CERT_ALIAS>   --tsaurl http://time.certum.pl   --alg SHA-256 your.exe
```

## 使用方式

1. **首次（一次性）**：从 Certum/SimplySign 账户安全设置拿到激活 QR / `otpauth://` URI，
   复制后导入钥匙串（见下节）。这是「首次 OTP」后永久无人值守的前提。
2. 之后每次：
   - 菜单栏 SimplySign → **Connect with cloud**（人工路径）
   - 或让 `session-keepalive.sh` 自动探测并自动重登（钥匙串 TOTP）
3. 之后尽量：
   - 不要 Quit / Disconnect
   - 不要强杀进程
   - 保持 Mac 登录态（Aqua session）
4. 由调用方的自动化流程调用本 Pack 的签名能力。

## 首次 OTP 后永久无人值守（钥匙串 TOTP）

SimplySign 手机端绑定的是标准 TOTP。可把激活 QR 的 `otpauth://` 密钥存到密码管理器，再落到本机：

### 1. 获取种子（正规途径，任选其一）

- 查找首次激活 SimplySign 时保存的二维码 / `otpauth://` URI（如 1Password/Bitwarden 里的 TOTP 项）；
- 没有的话：进入 **Certum/SimplySign 账户安全设置 → 重置并重新绑定移动令牌**，
  新激活二维码出现时顺手把 TOTP 项记入密码管理器（二维码里含 `secret=...`）。

> **不要**尝试从当前 6 位验证码反推种子（做不到）；
> **不要**把二维码、URI 或种子发到聊天、提交仓库或公共 CI。

### 2. 一次性导入钥匙串（种子只进本机 Keychain）

```bash
# 从密码管理器复制 otpauth:// URI 后：
pbpaste | python3 packs/simplysign-desktop/scripts/totp-keychain.py store
# 或手动粘贴到 stdin：
python3 packs/simplysign-desktop/scripts/totp-keychain.py store
# 也可传 --account you@example.com 记录账户
```

种子写入 macOS 登录钥匙串：

```text
service : easy-rev-simplysign-totp
account : simplysign（或 Certum 邮箱）
```

> 若导入时用了 `--account you@example.com`，后续恢复脚本也要认同一账户：
> 在 launchd/终端环境里设 `SIMPLYSIGN_TOTP_ACCOUNT=you@example.com`，
> 或恢复时同样加 `--account`。

脚本不打印、不落盘种子；密钥只在导入时经 stdin 进入 `security -i`，
不经过任何命令行参数。

```bash
# 只看当前 OTP
python3 packs/simplysign-desktop/scripts/totp-keychain.py show

# 检查种子是否在钥匙串（不显示种子）
python3 packs/simplysign-desktop/scripts/totp-keychain.py check

# 打开登录框后自动键入 OTP（需辅助功能权限）
python3 packs/simplysign-desktop/scripts/totp-keychain.py type
```

### 3. 会话死后自动重登（无人值守）

```bash
# 前台循环：每 5 分钟探测 PKCS，失效则自动用钥匙串 TOTP 重登
packs/simplysign-desktop/scripts/session-keepalive.sh
# 或 launchd 一次性入口（探测失败时也会自动恢复）
packs/simplysign-desktop/scripts/session-check-once.sh
```

`auto-recover.sh` 的逻辑：启动 Desktop → 探测失败 → 先试协议层
`client.py refresh`（保 headless 签名路径）→ 钥匙串有种子 → 辅助功能已授权 →
自动触发登录框并键入 OTP → 复探 PKCS。

启用 launchd 常驻（可选，`session-keepalive.sh` 前台循环等效）：

```bash
mv ~/Library/LaunchAgents/com.easyrev.simplysign-keepalive.plist.disabled \
   ~/Library/LaunchAgents/com.easyrev.simplysign-keepalive.plist
launchctl load ~/Library/LaunchAgents/com.easyrev.simplysign-keepalive.plist
```

该 plist 已指向 `session-check-once.sh`（探测失败会自动调用 `auto-recover.sh`）。

**前提**（一次性环境配置）：

1. 系统设置 → 隐私与安全性 → **辅助功能**：勾选运行脚本的终端 / Codex 应用；
2. Desktop 官方 LaunchAgent 开机自启（已配置）；
3. 保持 Mac 登录态（Aqua session），钥匙串解锁。

社区同类做法（Windows SendKeys）：  
https://www.devas.life/how-to-automate-signing-your-windows-app-with-certum/

这不是绕过 MFA，只是把手机 App 生成 OTP 的步骤自动化。

## 重启后完全免 OTP（状态更新）

见 [REBOOT_PROOF.md](REBOOT_PROOF.md)。现在的双保险：

- **快速层**：`refresh_token` 静默续期（协议层已闭环，`client.py refresh/sign`）；
  但 Certum 可随时吊销它，**不能作为唯一依赖**。
- **保底层**：钥匙串 TOTP 种子自动重登（本文件上一节）。只要种子在钥匙串、
  辅助功能已授权，任何会话死亡都能自动恢复，实现「首次 OTP 后永久无人值守」。

`session.json` 当前不在磁盘上（如需要 headless 签名，用 `capture-oauth-once.sh`
重新捕获一次）。

```bash
packs/simplysign-desktop/scripts/capture-oauth-once.sh
python3 packs/simplysign-desktop/scripts/silent-restore.py
```

## 脚本

- `scripts/start-simplysign-if-needed.sh` — 单实例启动
- `scripts/session-check-once.sh` — launchd 探测
- `scripts/session-keepalive.sh` — 前台循环（失效自动恢复）
- `scripts/auto-recover.sh` — 自动恢复编排（refresh → 钥匙串 TOTP 重登）
- `scripts/totp-keychain.py` — 种子导入 / 检查 / 显示 OTP / 自动键入
- `scripts/auto-connect-totp.py` — TOTP 生成/键入（钥匙串优先，兼容旧 env）
- `scripts/apply-otp-less-prefs.sh` — 偏好
- `scripts/capture-oauth-once.sh` / `silent-restore.py` — 重启免 OTP 试验路径

## 合规

仅用于自有 Certum 证书与授权签名工作流。  
TOTP 种子只存钥匙串（`easy-rev-simplysign-totp`），不落盘、不入库、不进 CI。
`session.json` / `client_credentials.json` / 抓包文件含高敏感凭证：权限 600，勿提交 git。
旧版 `totp.env` 明文方案已废弃：迁移到钥匙串后请删除该文件。


## 协议化

见 [protocol/PROTOCOL.md](protocol/PROTOCOL.md)。

协议化状态：**OAuth 捕获 → refresh 续期 → 云端 RSA 签名 → Authenticode 组装** 已闭环。
下游业务仓库、CI 拓扑、发布平台和命令不属于本公开 Pack，应在私有环境中维护。

```bash
# 查看内置 OAuth client 配置（client secret 固定脱敏）
python3 packs/simplysign-desktop/protocol/client.py config

# 有 session.json 后尝试无 UI refresh
python3 packs/simplysign-desktop/protocol/client.py refresh

# 校验云端 RSA 签名（脱敏输出）
python3 packs/simplysign-desktop/protocol/client.py verify \
  --digest <SHA256_HEX> --signature <HEX> --cert cert.pem

# 捕获一次登录+签名（会要求再 OTP 一次，换可解密流量）
packs/simplysign-desktop/scripts/capture-protocol-once.sh
```
