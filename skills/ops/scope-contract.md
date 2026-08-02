# Scope 契约（ACT 前硬门槛）

任何对目标的 hook / 发包 / attach 之前，必须存在 `scope.yaml` 且：

- `auth.status = granted`
- `network_profile.mode` 已设置
- `in_scope.assets` 非空（`offline` 纯静态可空）

```bash
easy-rev case init --hint "..." --auth-granted --target https://example.com \
  --network-profile authorized_target_only
easy-rev case guard packs/<id>
```

`network_profile`：

| mode | 允许 | 禁止 |
|------|------|------|
| offline | 本地静态/样本 | 外连 |
| lab_only | lab/VM | 生产 |
| authorized_target_only | in_scope 资产 | 列表外 |
| unrestricted_lab | 隔离实验网（书面） | 互联网生产 |
