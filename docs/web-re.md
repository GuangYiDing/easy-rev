# Web 逆向

能力主要来自 easy-reg 的 `re/*` 体系，在 Easy-Rev 中作为 `platforms/web` 一等公民。

## 能力清单

| 能力 | 入口 |
|------|------|
| 一键逆向 | `easy-rev web explore` / `ai call web.explore` |
| 全量抓包 | `web capture`（network + runtime hooks + signing） |
| 强签名 | auto_sign / crypto hooks / browser oracle |
| 依赖图协议包 | capture → pack 草稿 |
| Chrome 扩展 | `easy-rev re bridge` + `extensions/easy-rev-chrome` |
| CDP 附着 | `cdp_url=http://127.0.0.1:9222` |
| HAR 1.2 | capture 同步导出 |
| JS 静态分析 | `ai call web.analyze_js` |
| 签名合成 | `ai call web.sign_synth`（crypto events → Python sign_request） |
| Capture diff | `ai call web.diff_capture` |
| 离线协议链 | `ai call web.offline_chain`（classify→graph→pack→sign） |
| 诊断 | `ai call web.diagnose`（capture / job / HTTP tips） |
| HAR 导出 | `ai call web.har_export` |
| 长会话 | `web.session.start` / `stop` / `list` |
| Pack 校验 | `easy-rev pack validate ./packs/x` / `pack.validate` |

## 引擎选择

| 场景 | 用法 |
|------|------|
| 干净环境自动填表/点向导 | Camoufox（`pip install 'easy-rev[web]'`） |
| 已登录 Chrome 即时分析 | 扩展完整模式（推荐） |
| 多 tab 深度控制 | CDP 附着 |
| 纯协议试探 | `http_client` + 可选 curl_cffi |

## 扩展完整逆向

```bash
easy-rev re bridge
# → http://127.0.0.1:18766
# 加载 extensions/easy-rev-chrome
# 在目标页点「完整分析」/ 录制
easy-rev re bridge-status
```

## 强签名策略（自动）

1. **纯协议 HMAC**：crypto hooks 捕获密钥并校验 → 合成 Python signer  
2. **浏览器预言机**：混淆/WASM → 页面 JS 签名  
3. **手写 hooks**：前两者不足时人工补 `sign_request`

> 对抗性混淆下不存在 100% 全自动数学保证；框架把可自动化路径做成默认。

## 离线协议还原链（无浏览器）

```bash
# 1) JS 风险
easy-rev ai call web.analyze_js -i '{"text":"function signRequest(b){return CryptoJS.HmacSHA256(b,k)}"}'
# 2) 依赖图
easy-rev ai call web.dependency_graph -i '{"apis":[...]}'
# 3) 从 capture 写 pack
easy-rev pack from-capture ./capture.json --pack-id my-site
# 4) 一键离线链
easy-rev ai call web.offline_chain -i '{"capture_path":"./capture.json","pack_id":"my-site"}'
# 5) 两次 capture 差分
easy-rev ai call web.diff_capture -i '{"a_path":"./c1.json","b_path":"./c2.json"}'
# 6) crypto hook 事件 → 可恢复 signer
easy-rev ai call web.sign_synth -i '{"events":[{"api":"CryptoJS.HmacSHA256","key":"k","message":"m","result":"..."}]}'
```

## 与注册框架的差异

Easy-Rev **不做**批量开号农场；邮箱/短信/验证码 Provider 不在核心范围。  
表单 auto_fill 仅用于触发注册/登录 API 以便抓包分析。  
仅用于授权目标与合法安全研究。
