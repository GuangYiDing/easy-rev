# Easy-Rev Chrome Extension

把**当前标签页**发给本机 Easy-Rev，能力对齐 Camoufox `site.capture` 主路径。

| 能力 | 扩展完整模式 |
|------|----------------|
| Network（XHR/fetch/body） | ✅ chrome.debugger Network |
| Cookie / storage / DOM | ✅ |
| fetch/XHR/WS page hooks | ✅ 注入 `page_hooks.js` |
| crypto.subtle / CryptoJS | ✅ |
| 签名函数发现 + 试签 | ✅ `__easy_rev_sign__` |
| auto_sign / 依赖图 / pack | ✅ bridge 侧完整流水线 |
| **录制模式（推荐）** | ✅ 一点开始 · 自由操作 · **空闲自动上传** |
| **页内 HUD** | ✅ 业务计数 / 倒计时 / 结束·取消 |
| **桌面通知** | ✅ 上传成功/失败 |
| 持续预言机会话 | ✅ 「保持附着」+「试签」 |

**不需要**整机 `--remote-debugging-port`。

版本 **0.3.2** 进一步修复：登录后若被 1Password 等扩展短暂切到 `chrome-extension://`，会等待回到 http(s) 再 reattach，并用 `tabs.onUpdated` / 1s 轮询兜底记录 URL。

版本 **0.3.1** 修复整页跳转丢包（`target_closed` 后自动重挂 debugger + `webNavigation` 兜底 OAuth `code`）。

版本 **0.3.0** 体验重点：

- 弹窗主路径只保留「开始 / 结束 / 取消」；设置收进折叠区
- 打开弹窗**自动检测 Bridge**
- 开始录制前 **preflight Bridge**，连不上立刻失败并提示命令
- 页内右下角 **HUD**（可拖、可最小化）
- 导航后 **自动重注 hooks**
- MV3 Service Worker 休眠后 **尝试恢复录制会话**
- 上传完成 **系统通知** + 角标 OK/ERR

---

## 1. Bridge

```bash
source .venv/bin/activate
easy-rev re bridge
# http://127.0.0.1:18766
```

## 2. 加载 / 重载扩展

`chrome://extensions` → 开发者模式 → 加载已解压 → 本目录。  
改代码后点 **重新加载**（0.3 起需要 notifications 权限，旧安装务必重载）。

## 3. 推荐流程（最少点击）

1. 登录目标站，打开目标页  
2. 点扩展图标（弹窗会自动检查 Bridge，右上角应显示 **Bridge ✓**）  
3. 点 **开始录制**  
   - 角标 `REC` / 数字 = 已捕获业务请求数  
   - **页内右下角 HUD** 实时显示进度  
   - **可以关掉弹窗**，继续在页面里操作  
4. 自由触发：注册 / 生图 / 生视频 / 语音…  
5. 结束方式（任选）：  
   - **空闲自动上传**（默认）：足够业务流量后安静 N 秒（默认 12s）  
   - **最长录制**到点自动上传（默认 180s）  
   - HUD / 弹窗 **结束并上传**  
   - **取消**（不上传）

```bash
easy-rev ai call re.bridge.status -i '{}'
# 或
curl -s http://127.0.0.1:18766/health
```

可调参数（弹窗 → **设置与高级**）：

| 参数 | 默认 | 含义 |
|------|------|------|
| 空闲自动结束 | 12s | 有业务流量后，安静多久就上传 |
| 最长录制 | 180s | 硬上限 |
| 最少业务请求数 | 2 | 达到后再启用空闲自动结束 |
| 空闲自动上传 | 开 | 关掉则只靠手动结束 / 最长录制 |

**业务流量**判定：XHR/Fetch、POST/PUT/PATCH、WebSocket、或 URL 含 `/rest/` `/api/` `imagine` `livekit` `media` 等。

## 4. 高级：定时窗口 / 预言机

弹窗底部「设置与高级」：

- **定时分析当前页**：固定监听 N 秒后上传（适合极短路径）
- **保持附着** + **试签当前页 sign()**：预言机会话

## 注意

- 勿同时开该 tab 的 DevTools（会抢 debugger；断开时会尝试把已抓到的数据上传）  
- Bridge 仅本机  
- 关弹窗 **不影响** 录制（逻辑在 service worker + 页内 HUD）  
- 角标 `OK` = 已上传成功；系统通知也会弹出  
- `chrome://`、Web Store 等受限页无法注入 HUD / hooks  

## vs Camoufox / 整机 CDP

| | 录制扩展 | Camoufox | 整机 CDP |
|--|----------|----------|----------|
| 登录态 | 你的 Chrome | 需重登 | 你的 Chrome |
| 手动点击次数 | **1 次开始**（结束可自动） | 自动 multi_step | session.act |
| 状态可见性 | 角标 + **页内 HUD** + 通知 | CLI | CLI |
| hooks/crypto/auto_sign | ✅ | ✅ | ✅ |
| 批量 run pack | pack 后 run | ✅ | hybrid |
