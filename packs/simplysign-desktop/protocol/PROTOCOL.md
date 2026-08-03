# SimplySign Desktop — 协议还原（SCS1_ATOM）

> 来源：二进制字符串 / `SimplySignDesktop.xml` / 本机日志 / OAuth WebView 缓存  
> 目标版本：Desktop 2.10.22 + PKCS#11 MS-1.1.24  
> 状态：**2026-08-03 已实测闭环** —— refresh 与 sign 均可无 Desktop、无 OTP headless 完成；
> 明文 HTTPS 体由 Frida 挂钩 app 内静态 OpenSSL `SSL_write/SSL_read` 抓取，非推断。

## 0.1 验证结论（一行版）

**拿到 `refresh_token` 后，可以不启动 SimplySign Desktop 完成「续期 + 云签名」**：

```text
refresh（无 OTP，30 分钟 access_token，refresh_token 不轮转）
  → 用 Bearer 签名（multipart POST → 202 task → poll → RSA 签名）
```

签名可用证书公钥验证（`openssl pkeyutl -verify` 通过）。  
会话文件：`~/Library/Application Support/easy-rev/simplysign-session/session.json`（600）+ `cert.pem`。  
命令行：`python3 packs/simplysign-desktop/protocol/client.py refresh` / `sign --file <exe>`。

## 0. 总览

```
jsign / signtool
   │  PKCS#11
   ▼
libSimplySignPKCS.dylib  ──shm──▶  SimplySign Desktop
                                      │  HTTPS (libcurl, 有公钥 pinning)
                                      ▼
                         cloudsign.webnotarius.pl
                           ├─ /idp/oauth2.0/*     (登录 / refresh)
                           └─ /card/v1/cards/*    (软卡 / 证书 / 签名)
```

私钥 **永不** 出云端。协议化 = 复制 Desktop 对 IDP + SCS 的 HTTP 调用，而不是导出密钥。

## 1. OAuth2 / IDP

| 项 | 值 |
|----|----|
| Authorize | `https://cloudsign.webnotarius.pl/idp/oauth2.0/authorize` |
| Token | `https://cloudsign.webnotarius.pl/idp/oauth2.0/accessToken` |
| Logout/Revoke | `https://cloudsign.webnotarius.pl/idp/oauth2.0/revoke` |
| Profile/Scope URL | `https://cloudsign.webnotarius.pl/idp/oauth2.0/profile` |
| Redirect | `https://cloudsign.webnotarius.pl/redirect` |
| Client ID | 见 `~/SimplySignDesktop.xml` → `OAuth2ClientId`（公共客户端配置，非用户密码） |
| Client Secret | 同上 `OAuth2ClientSecret`；`OAuth2ProtectClientCredentials=Yes` |
| Token 请求 Content-Type | `application/x-www-form-urlencoded` |
| 可能的鉴权 | `Authorization: Basic …` **或** body 内 `client_id`/`client_secret` |

### 1.1 授权码登录（交互，需 OTP）

1. Desktop WebView 打开 authorize（带 `client_id` / `redirect_uri` / `response_type=code` …）
2. 用户输入邮箱 + 手机 TOTP
3. 302 到 `https://cloudsign.webnotarius.pl/redirect/?code=OC-…`
4. Desktop 用 `grant_type=authorization_code` 换 token

本机 WebKit 缓存可见历史 redirect（code 已消耗，不能重放）：

```
https://cloudsign.webnotarius.pl/redirect/?code=OC-…
```

### 1.1.5 OTP 登录 HTTP 链（2026-08-03 实测打通，替代 WebView）

不需要浏览器/Desktop，纯 HTTP 即可完成 OTP 登录换取 token
（实现：`otp_login.py`，仅依赖 Python 标准库）：

```text
1) GET /idp/oauth2.0/authorize?client_id=…&response_type=code&redirect_uri=…&client_name=CasOAuthClient
   → 302 /idp/login?service=<encoded callbackAuthorize> → 200 表单
     （hidden: execution, _eventId=submit, username, password；lt 可空）
2) POST /idp/login?service=…  username=<邮箱>&password=<OTP>&execution=…&_eventId=submit
   → 302 /idp/oauth2.0/callbackAuthorize?…&ticket=ST-…
   → 302 https://cloudsign.webnotarius.pl/redirect/?code=OC-…
   （OTP 错误 → HTTP 401 + 登录页）
3) POST /idp/oauth2.0/accessToken
   grant_type=authorization_code&client_id=…&client_secret=…&redirect_uri=…&code=OC-…
   → {access_token, refresh_token, expires_in:1800}
```

要点：必须保持 cookie jar；callbackAuthorize 后继续手动跟随一跳直到
`code=OC-…`。浏览器扩展之前在此失败，纯 HTTP 客户端实测成功。

### 1.2 Refresh（无 OTP，若服务端允许）

已实测（2026-08-03）：

```http
POST /idp/oauth2.0/accessToken HTTP/1.1
Host: cloudsign.webnotarius.pl
User-Agent: bond-007
Content-Type: application/x-www-form-urlencoded
Accept: */*

grant_type=refresh_token&client_id=44rvDKKEWY53a7xBeF5w&client_secret=<client_secret>&refresh_token=<refresh_token>
```

响应（HTTP 200，JSON）：

```json
{"access_token":"<access_token>","token_type":"bearer","expires_in":1800}
```

要点：

- **refresh_token 不轮转**（响应只返回新 access_token），可长期保存复用。
- access_token 有效期 **1800 秒（30 分钟）**。
- client_id / client_secret 为运行时值：`44rvDKKEWY53a7xBeF5w` / `<client_secret>`（与 XML 长 ID 不同，Frida 从 `NXOAuth2Client` 读出）。
- 响应带 `Set-Cookie: SESSION=…`（无状态感知，仅记录）。
- 失败文案：`Token refresh error. Login again` / `Access token could not be refreshed`。

### 1.3 Token 对象字段（NXOAuth2）

`access_token`, `refresh_token`, `expires_in` / `expiresAt`, `token_type`  
后续业务调用：`Authorization: Bearer %s`

> 本机 Keychain **未** 以明文服务名找到持久条目；当前会话 token 更像进程内 + NXOAuth2 自定义 accountType 存储。

## 2. SCS 业务 API（SCS1_ATOM）

Host：`cloudsign.webnotarius.pl`  
Base：`card/v1/cards`（XML `SCSPartOfUrl`）

通用：

- `Authorization: Bearer <access_token>`
- JSON：`Content-Type: application/json` / `application/json;charset=UTF-8`
- 部分接口：`multipart/form-data`（签名）
- URL 拼装模板：`https://%s/%s/%s/%s` 或 `…?extended=true`

### 2.1 路径映射（XML）

| 动作 | PartOfUrl |
|------|-----------|
| Softcards 任务 | `tasks` |
| Public keys 任务 | `keys/tasks` |
| Certificates 任务 | `certificates/tasks` |
| Sign via key | `keys/signature` |
| Sign via certificate | `certificates/signature` |
| Change PIN/PUK / unlock | `pin` / `puk` |
| Decrypt key | `keys/decrypt` |

推断 URL（需抓包确认 method/精确路径）：

```
https://cloudsign.webnotarius.pl/card/v1/cards/tasks
https://cloudsign.webnotarius.pl/card/v1/cards/keys/tasks
https://cloudsign.webnotarius.pl/card/v1/cards/certificates/tasks
https://cloudsign.webnotarius.pl/card/v1/cards/{card}/certificates/signature
https://cloudsign.webnotarius.pl/card/v1/cards/{card}/keys/signature
```

字符串硬编码片段：`card/v1/cards/` + `/certificates`。

### 2.2 签名 multipart（已实测，2026-08-03）

完整流程（与 Desktop 2.10.22 实测一致，headless 可复现）：

```http
POST /card/v1/cards/{cardId}/certificates/signature HTTP/1.1
Host: cloudsign.webnotarius.pl
User-Agent: bond-007
Accept: application/json, text/plain, */*
Content-Type: multipart/form-data; boundary=--<BOUNDARY>
Authorization: Bearer AT-…

----<BOUNDARY>
Content-Disposition: form-data; name="req"
Content-Type: application/json;charset=UTF-8

{ "digests": [ "<SHA256-HEX-UPPER>" ], "digesttype": "SHA256" }
----<BOUNDARY>
Content-Disposition: form-data; name="certificate"; filename="blob"
Content-Type: application/octet-stream

-----BEGIN CERTIFICATE-----
…PEM…
-----END CERTIFICATE-----
----<BOUNDARY>--
```

响应（HTTP 202）：

```json
{"state":"pending","atom:link":"https://cloudsign.webnotarius.pl:443/scs1/card/v1/cards/{cardId}/certificates/signature/task/{taskId}","message":"Your request has been accepted for processing.","ping-after":400}
```

轮询（注意去掉 `:443`；任务结果**一次性**，取到即消失）：

```http
GET /scs1/card/v1/cards/{cardId}/certificates/signature/task/{taskId}
Authorization: Bearer AT-…
Content-Type: application/json
```

- 常见返回 `303 See Other`，`Location` 指向最终结果资源；继续 GET 该 Location。
- 最终响应 `200`：`{"<SHA256-HEX-UPPER>": "<RSA-SIGNATURE-HEX>"}`（512 字节 RSA，PKCS#1 v1.5）。
- `digesttype` 字面量 `SHA256`；字段名 `req` / `certificate`；`filename="blob"`。
- 响应 `{"signatures": …}` 片段来自其它构建，实测返回 digest→sig 映射。

算法字面量：`RSA_PKCS1`  
时间格式：`%Y-%m-%dT%H:%M:%S`

### 2.3 SAD（Signature Activation Data）

JSON 模板：

```json
{
  "encryptKeyId": "%s",
  "certificate": "%s",
  "algorithm": "RSA_PKCS1",
  "digestType": "%s",
  "digests": ["%s"],
  "sadEncryptedData": "%s"
}
```

配套：

```json
{"saddigesttype":"SHA512","saddigest":"…","pin":"%s","nonce":"%lld"}
```

字段串联痕迹：

```
saddigesttype SHA512 pin nonce sadencryptkeyid usertoken cardno usercertificate signalg digesttype digests
```

SAD 相关 path：`scs-sad/v1` + `infrastructureKey` + `signature`。  
Code Signing 云卡本机为 **pinless**（占位 PIN `0000`），日常 Authenticode 路径可能不走完整 SAD 交互，但仍可能带 `sadEncryptedData`。

## 3. 本机 PKCS#11 侧（非云协议，但是入口）

共享内存名：

- `/CC_SM_FOR_RC*` 控制
- `/CC_SM_FOR_CS_*` 客户端会话（日志见 `/CC_SM_FOR_CS_0501`）

命令（日志）：

- `GET_SOFTCARDS_LIST` / `GET_SOFTCARD_STATUS`
- `GET_PUBLIC_KEYS_LIST` / `GET_CERTIFICATES_LIST`
- `SIGN_HASH`
- redirector：`CLIENT_CONNECT` / `CLIENT_DISCONNECT`

证书 alias（本机）：`<CERT_ALIAS>`（序列号）

## 4. 协议化路线图

| 阶段 | 内容 | 状态 |
|------|------|------|
| A | 静态还原 URL / OAuth / multipart / SAD | **已完成**（本文） |
| B | SSLKEYLOG + pcap 捕获一次登录+签名，补全 method/字段 | 脚本已备 |
| C | 验证 `refresh_token` 可否无 UI 换票 | `silent-restore.py` |
| D | 纯 Python 实现 list-cards / sign-hash | `client.py` 骨架 |

**若 C 失败**：协议仍可文档化，但自动化必须保留 Desktop 会话或 TOTP 自动登录。

## 5. 捕获方法（推荐）

应用使用 **libcurl 且支持 `SSLKEYLOGFILE`**，同时存在 **公钥 pinning**（MITM 证书替换会失败）。

因此用 **旁路解密** 而不是中间人：

```bash
packs/simplysign-desktop/scripts/capture-protocol-once.sh
```

流程：

1. 退出 Desktop  
2. 以 `SSLKEYLOGFILE` 启动 Desktop + `tcpdump`  
3. Connect + OTP 一次，再跑一次 jsign  
4. 用 keylog 解密 pcap → 导出 token 与 sign 请求到 `protocol/captures/`

## 6. 合规

仅用于自有证书与授权签名自动化。`captures/`、`session.json`、`sslkeys.log` 含高敏感凭证，默认 gitignore。
