# skill-demo

Easy-Rev Target Pack: `skill-demo`  
Platform: **web**

## 使用

```bash
easy-rev pack install ./
easy-rev explore --platform web ...
easy-rev pack validate .
```

## Ops（吸收 reverse-skill 作战契约）

1. 编辑 `scope.yaml`：`auth.status=granted` + `network_profile` + `in_scope.assets`
2. `easy-rev ai call case.guard -i '{"path":"."}'` 确认 ready
3. 过程写 `evidence/`，结论写 `findings.md` / `path.md`
4. 可复用模式脱敏回写 `skills/field-journal/`

## 说明

请在授权范围内使用。根据目标修改 `playbook.yaml` 与 `hooks/`。
