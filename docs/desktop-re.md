# Desktop 逆向（Windows / macOS）

## 目标

对桌面客户端做：

1. **静态**：格式识别、字符串、导入库、加壳/反调试线索、加密 API 线索  
2. **动态**：Frida attach、模块/导出枚举、自定义 JS hooks  

## 安装

```bash
pip install -e ".[frida]"
# macOS 常用系统工具：otool, codesign, lldb, strings（Xcode CLT）
# Windows：dumpbin（VS）、可选 sigcheck
```

## 命令

```bash
easy-rev doctor -p macos
easy-rev desktop analyze /path/to/binary
easy-rev desktop ps
easy-rev desktop explore --binary /path/to/binary --process MyApp

# 统一入口
easy-rev explore -p windows --binary app.exe --process app.exe
easy-rev explore -p macos --binary ./App --process App
```

## AI

```bash
easy-rev ai call desktop.explore -i '{
  "platform": "macos",
  "binary": "/Applications/Foo.app/Contents/MacOS/Foo",
  "process": "Foo",
  "duration_s": 8
}'
```

## 产物

- `artifacts/desktop/<name>/static_report.json`
- `artifacts/desktop/<name>/strings.txt`
- `artifacts/desktop/frida/capture-*.jsonl`

## Target Pack

```bash
easy-rev pack init my-desktop --platform macos --with-hooks
# hooks/ssl_pinning.js  hooks/crypto.js
```

## 已具备的技术深度

- **PE**：节表 + 熵（加壳线索）、导入 DLL/函数、**导出表**（无 pefile 依赖）
- **Mach-O / Fat**：dylib/rpath、**segments**、**symtab 真导出**、**LC_DYLD_EXPORTS_TRIE / dyld_info export trie**；`otool -L` 增强
- **ELF**：header + section 熵 + `lib*.so` needed / 符号线索（桌面 Linux / 供 Mobile 复用）
- **字符串**：ASCII + UTF-16LE、URL/反调试/加密/网络启发式 + structured `findings`
- **Frida**：`dry_run`/`hint` 契约；脚本库  
  `ssl_trace` · `crypto_trace` · **`module_enum`** · **`file_trace`** · **`http_trace`**

```bash
easy-rev desktop scripts
easy-rev desktop scripts module_enum.js
easy-rev ai call desktop.scripts -i '{"name":"file_trace"}'
```
- CLI：`easy-rev desktop scripts` 列出捆绑脚本

## 扩展方向（路线图）

- Mach-O 符号与 ObjC 类枚举
- 内存 dump API
- 按目标自动生成 bypass 变体（非通用保证）
