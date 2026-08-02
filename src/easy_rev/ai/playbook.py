"""Standard reverse-engineering playbooks for AI agents."""

from __future__ import annotations


def playbook_text() -> str:
    return """# Easy-Rev Playbook

## 合规
仅对用户授权目标进行逆向。拒绝未授权的第三方应用/站点批量攻击。

## 统一入口
```bash
easy-rev doctor
easy-rev ai call explore -i '{"platform":"web","url":"https://…"}'
easy-rev ai call explore -i '{"platform":"macos","binary":"/path/App","process":"App"}'
easy-rev ai call explore -i '{"platform":"android","binary":"./app.apk","package":"com.example"}'
```

## Web 逆向（来自 easy-reg 能力）
1. doctor → 确认 camoufox / CDP
2. web.explore 或 re.explore（Camoufox 干净环境）
3. 已登录 Chrome：web.bridge.start + 扩展完整分析
4. 读 recommendation: protocol | hybrid | browser_flow
5. pack.init / write_pack 固化为 Target Pack

## Desktop（Windows / macOS）
1. doctor → frida / otool / dumpbin
2. desktop.explore binary= 静态（字符串/导入/加壳线索）
3. desktop.ps 找进程 → explore process= + scripts
4. 按 hooks 模板扩展 SSL/crypto hook
5. 产物在 data_dir/artifacts/desktop/

## Mobile（Android / iOS）
1. doctor → adb / frida-server / USB 设备
2. mobile.explore binary=app.apk 静态（包名/权限/URL/pinning）
3. mobile.apps → package= spawn 动态
4. 注入 ssl_pinning / crypto / network hooks
5. 产物在 data_dir/artifacts/mobile/

## Target Pack
```bash
easy-rev pack init my-target --platform android --with-hooks
# 编辑 packs/my-target/playbook.yaml 与 hooks/
```
"""
