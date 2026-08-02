# Evidence → Finding → Path

## Evidence（不可变观察）

`evidence/E-XXX.md`，必须含 `repro_command`。

```bash
easy-rev ai call evidence.append -i '{
  "path":"packs/demo","title":"OAuth token endpoint",
  "repro_command":"easy-rev ai call explore -i {...}"
}'
```

## Finding（结论）

`findings.md` 中 `F-XXX`，`evidence_ids` 非空。

## Path（调用/攻击/解题路径）

`path.md` 中 `P-XXX`，每步尽量挂 evidence。

报告 / Pack README 应能从 Evidence 复现关键结论。
