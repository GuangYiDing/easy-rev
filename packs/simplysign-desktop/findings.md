# Findings — SimplySign Desktop 2.10.22

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
