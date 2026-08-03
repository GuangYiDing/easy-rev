# Findings — SimplySign Desktop 2.10.22

## 2026-08-03 实测闭环（headless 签名）

状态：**refresh + sign 已无 Desktop 验证通过**（详情见 `protocol/PROTOCOL.md`）。

### 抓取手段

- 正式版有 Hardened Runtime，无法 Frida；改用 debug 副本（ad-hoc 重签 + `get-task-allow`）挂钩。
- Debug 副本登录 WebView 不稳定（`runModalForWindow` 内 SIGBUS/SIGILL），但**登录成功后签名稳定**。
- 明文 HTTPS：app 静态链接 OpenSSL，挂钩主程序导出的 `SSL_write` / `SSL_read` 直接抓明文（非 MITM，绕开 pinning）。
- 会话建立后，卡片列表/探针是本地缓存（无 TCP）；**真实签名才产生云端流量**（经系统代理 127.0.0.1:7890）。
- app 的网络栈：**原始 socket + 静态 OpenSSL**（非 NSURLSession / NSURLConnection / CFNetwork / libcurl 导出符号）。

### 实测值

- 运行时 OAuth：client_id `44rvDKKEWY53a7xBeF5w`，client_secret `<client_secret>`（见本机 session.json），scope `…/idp/oauth2.0/profile`，User-Agent `bond-007`。
- refresh：`grant_type=refresh_token` → 200，`access_token`（1800s），**refresh_token 不轮转**。
- card id：`<cardId>`（见本机 session.json）；证书 subject `CN=<name>`，issuer `Certum Code Signing 2021 CA`。
- 签名流程：multipart POST `…/certificates/signature`（`req` = digests JSON + `certificate` = PEM）→ 202 task → GET task（去掉 `:443`）→ 303/200 → RSA 签名（512B），`openssl pkeyutl -verify` 通过。

### 结论

拿到 `refresh_token` 后 CI 可完全无 OTP 签名；Desktop 仅用于首次登录换取 token。

## Binary

- Path: `/Applications/SimplySign Desktop.app/Contents/MacOS/SimplySign Desktop`
- Format: Mach-O fat (arm64/x86_64), 未发现明显加壳
- Bundle ID: `pl.ads.SimplySign-Desktop`
- `LSUIElement=1`（菜单栏应用）
- ObjC 关键类：`SCCAppDelegate`, `SCCServerForPKCS11Requests`, `SCCClientForPKIServerRequests`, `PanelWebViewController`, `NXOAuth2*`

## PKCS#11 IPC

库：`SimplySignPKCS-MS-1.1.24.dylib`

共享内存/信号量名（字符串）：

- `/CC_SM_FOR_RC`, `/CC_SM_FOR_RC_WFC`, `/CC_SM_FOR_RC_CR`, `/CC_SM_FOR_RC_OCTG`
- `/CC_SM_FOR_CS_*`（日志：`/CC_SM_FOR_CS_0501`）
- `/CC_SI_FOR_UL_`
- `/CC_SM_FH`

客户端未登录时：`pkislGetUserData. User seems to be not logged in. Increase timeOut...`

命令枚举（日志）：

- `GET_SOFTCARDS_LIST` / `GET_SOFTCARD_STATUS`
- `GET_PUBLIC_KEYS_LIST` / `GET_CERTIFICATES_LIST`
- `SIGN_HASH`
- redirector: `CLIENT_CONNECT` / `CLIENT_DISCONNECT`

## OAuth2

Client（公共写在 XML，非用户密码）：

- authorize: `https://cloudsign.webnotarius.pl/idp/oauth2.0/authorize`
- token: `https://cloudsign.webnotarius.pl/idp/oauth2.0/accessToken`
- refresh 形态字符串：`grant_type=refresh_token&client_id=%s&client_secret=%s&refresh_token=%s`
- `Authorization: Bearer %s`

Token 对象字段：`access_token`, `refresh_token`, `expires_in`, `expiresAt`, `token_type`

Keychain：NXOAuth2 AccountStore（`SecKeychainItemCopyContent` 字符串存在）。本机 `security dump-keychain` 未以明文服务名直接搜到，可能使用自定义 accountType 编码存储。

## SAD

存在 SAD（Signature Activation Data）路径：

- JSON 模板含 `pin`, `nonce`, `sadEncryptedData`, `usertoken`, `cardno`
- Code Signing 云卡当前 pinless（`pin min/max 0/0`），日常 jsign 使用占位 PIN `0000`

## 用户偏好键全集

- `SimplySignDesktopLaunchApplicationAfterUserLogon`
- `SimplySignDesktopShowLogonDialogWhenAnyAppRequestsAccess`
- `SimplySignDesktopShowLogonDialogAfterApplicationStartup`
- `SimplySignDesktopLogApplicationExecution`
- `SimplySignDesktopLogonUserId`
- `SimplySignDesktopShowOnlyValidCertificates`
- `SimplySignDesktopWasFirstLogon`

## 日志样本位置

- `~/YYYY-MM-DD_SSD.log`（`LogsPath=home`）


## Protocolization (2026-08-03)

- libcurl + **SSLKEYLOGFILE** supported; also **public key pinning** (MITM brittle).
- OAuth code appears in WebKit cache redirect `https://cloudsign.webnotarius.pl/redirect/?code=OC-…` (single-use).
- Token + card/sign traffic is **not** in CFURL cache (goes through curl).
- Static SCS1_ATOM map documented in `protocol/PROTOCOL.md`.
- Client skeleton: `protocol/client.py` (`refresh` / `probe`).
- Capture harness: `scripts/capture-protocol-once.sh`.
- Live sign verified after re-OTP: alias `<CERT_ALIAS>` (CN=<name> / Certum Code Signing 2021 CA).


## Browser extension capture (2026-08-03)

Capture files (local Application Support):

- `ext-capture-20260803-103908.json`
- `ext-capture-20260803-104006.json` (last)

Observed CAS login form POST:

- URL: `POST https://cloudsign.webnotarius.pl/idp/login?service=...callbackAuthorize...`
- Content-Type: `application/x-www-form-urlencoded`
- Fields: `username` (email), `password` (mobile OTP token), `lt`, `execution` (CAS flow id), `submit=Login`
- Real OAuth client id in service URL: `44rvDKKEWY53a7xBeF5w` + `client_name=CasOAuthClient`
- Redirect URI: `https://cloudsign.webnotarius.pl/redirect` (returns body `OK` when `?code=` present)

Gap:

- Extension stopped with `detach:target_closed` on document form navigation
- No `redirect/?code=OC-...` and no `access_token`/`refresh_token` in capture
- Token exchange likely continues after form POST (302 chain); need capture that survives full-page navigation or Desktop-side token capture



## Browser OAuth chain (ext-capture-20260803-110432, v0.3.3)

Successful CAS SSO then **OAuth authorize failure** (no `code`):

1. `POST/GET /idp/login?service=callbackAuthorize...`
2. `302` → `/idp/oauth2.0/callbackAuthorize?client_id=44rvDKKEWY53a7xBeF5w&response_type=code&redirect_uri=https://cloudsign.webnotarius.pl/redirect&client_name=CasOAuthClient&ticket=ST-...`
3. `302` → `https://cloudsign.webnotarius.pl/`  (**no `redirect/?code=`**)
4. `302` → `https://simplysign.certum.pl/`
5. `301` → `https://www.certum.pl/pl/simplysign/` (marketing)

Implications:

- Extension capture of navigation/redirects works (debugger stayed up; 225 events).
- Browser login **does authenticate to CAS** (ST ticket issued) but **does not mint OAuth authorization code** for this public client in browser context.
- Desktop WebView historically did reach `redirect/?code=OC-...` (cache evidence). Browser path is not equivalent for token export.
- Protocol pack for headless sign cannot rely on browser OAuth alone with client `44rvDKKEWY53a7xBeF5w`; need Desktop-held tokens or another registered client.
