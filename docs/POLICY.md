# 策略语法

策略是一份 JSON 文档，四类控制相互独立：

1. `rules`：按顺序匹配工具调用，决定放行、拒绝或转人工审批；
2. `egress` + `sensitive`：跨调用的数据血缘控制；
3. `rate`：会话级调用频率；
4. `hide_denied`：是否把被拒绝的工具从 `tools/list` 中摘掉。

最小可用策略：

```json
{
  "version": 1,
  "name": "read-only",
  "default_decision": "deny",
  "rules": [
    { "id": "read", "tool": "fs.read", "decision": "allow" }
  ]
}
```

## 顶层字段

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `version` | 整数 | 1 | 目前只接受 1 |
| `name` | 字符串 | `unnamed` | 报告与账本中显示 |
| `default_decision` | `allow` \| `deny` | `deny` | 所有规则都不匹配时的判定 |
| `rules` | 数组 | `[]` | 最多 128 条，`id` 不可重复 |
| `sensitive` | 数组 | `[]` | 声明哪些工具结果需要打血缘标记 |
| `egress` | 对象 | 无 | `{ "tools": [...], "on_taint": "deny" \| "approval" }` |
| `rate` | 对象 | `{window_ms: 60000, max_calls: 60}` | 每条会话独立计数 |
| `approval_ttl_ms` | 整数 | 45000 | 审批请求的默认有效期 |
| `min_secret_len` | 整数 | 12 | 血缘提取的最小值长度 |
| `hide_denied` | 布尔 | true | 被无条件拒绝的工具不进入 `tools/list` |

字段越界或类型错误会直接拒绝加载，错误信息带 JSON 路径，不回显字段值。

## 规则

```json
{
  "id": "write-report",
  "tool": "fs.write",
  "decision": "approval",
  "reason": "写报告需要人工确认",
  "approval_ttl_ms": 45000,
  "when": [
    { "arg": "path", "glob": ["reports/*", "reports/**"] }
  ]
}
```

| 字段 | 说明 |
| --- | --- |
| `id` | 唯一，1–64 字符；出现在账本、错误响应和报告里 |
| `tool` | 工具名的 glob。`*` 匹配任意字符（含 `.` 和 `/`），`?` 匹配一个字符 |
| `decision` | `allow` / `deny` / `approval` |
| `reason` | 可选的说明，进入拒绝消息与审批台 |
| `when` | 可选，全部条件满足才算命中（AND） |
| `approval_ttl_ms` | 仅对 `approval` 生效，覆盖顶层默认值 |

### `when` 条件

```json
{ "arg": "path", "prefix": ["..", "/", "C:\\"], "negate": true }
```

- `arg`：参数名。取 `params.arguments[arg]`；非字符串值先按 JSON 文本处理；缺失视为空串。
- `glob`：任一匹配即可（OR）。
- `prefix`：任一前缀命中即可（OR）。
- `negate`：把结果取反。常用于“路径不以这些前缀开头”。
- `normalize: "path"`：匹配前先做词法路径规范化（`\` 转 `/`，解析 `.` 与 `..`）。没有它，`reports/../../etc/passwd` 会通过 `reports/*` 这类前缀检查。
- 多个 `when` 之间是 AND。

`glob` 是整串匹配，不做路径规范化。`reports/*` 与 `reports/a/b.md` 不匹配，需要显式写 `reports/**`。

### 求值顺序

```
1. 频率检查      超出 rate 直接 deny，规则 "rate-limit"
2. 血缘检查      外发工具的参数含敏感值时，按 egress.on_taint 判定，规则 "egress-taint"
3. 规则列表      第一条命中的规则生效
4. 默认判定      default_decision
```

血缘排在第 2 位，是因为它表达的是“这个值不能出去”，比“这个工具通常允许”更强；把血缘放在规则之后，一条宽泛的 allow 就能绕过它。

规则按顺序匹配而不是“最具体优先”，是为了让策略可读、可预测。代价是顺序写错会遮蔽后面的规则，`moongate check` 会对同工具模式的无条件规则给出遮蔽警告：

```sh
node bin/moongate.mjs check --policy examples/policy.workspace.json
```

建议的顺序：**窄范围 deny（逃逸、危险参数）→ 常规 allow → 需要审批的动作 → 兜底 deny**。

## 能力裁剪

`hide_denied: true` 时，`tools/list` 会过滤掉同时满足以下条件的工具：

- 命中了**无条件**的 `deny` 规则；或
- 没有任何规则命中，且 `default_decision` 是 `deny`。

带 `when` 的 deny 规则不会导致工具被隐藏（它只封掉部分参数），带 `when` 的 allow/approval 会让工具保持可见。

## 敏感来源与血缘

```json
{
  "sensitive": [
    { "tool": "fs.read", "when": [{ "arg": "path", "glob": ["**/*.env", "**/secrets/**"] }] },
    { "tool": "vault.read" }
  ],
  "egress": { "tools": ["net.*", "mail.*"], "on_taint": "deny" }
}
```

被 `sensitive` 命中的工具调用，其结果会被扫描：

1. 按 `[A-Za-z0-9_.-]` 切分，长度 ≥ `min_secret_len`；
2. 至少含一个数字或大写字母；
3. 排除字段名：后面紧跟 `=` 的，或“引号 + 冒号”结构中的键；
4. 每个值取 SHA-256 前 16 位作为指纹，记录来源调用编号；
5. 账本与控制台只出现指纹和 4 字符前缀，不出现原值。

外发工具的参数（递归遍历所有字符串叶子）会做同样的提取。指纹交集非空即判定为携带敏感数据。

阈值越低，拦截越严，误报越多。默认 12 是“多数 API Key / Token”与“普通英文单词”之间的折中；`min_secret_len` 可调，但不建议低于 8。

## 频率

```json
{ "rate": { "window_ms": 60000, "max_calls": 30 } }
```

滑动窗口内统计**所有**工具调用尝试（包括被拒绝的），超过即拒绝。被拒绝的调用也计数，是为了避免 Agent 在拒绝后高频重试形成忙等。

## 常见写法

**只读工作区**

```json
{
  "default_decision": "deny",
  "rules": [
    { "id": "escape", "tool": "*", "decision": "deny",
      "when": [{ "arg": "path", "prefix": ["..", "/", "~"] }] },
    { "id": "read", "tool": "fs.read", "decision": "allow" },
    { "id": "list", "tool": "fs.list", "decision": "allow" }
  ]
}
```

**写操作一律人工确认**

```json
{
  "default_decision": "deny",
  "rules": [
    { "id": "write", "tool": "fs.write", "decision": "approval", "approval_ttl_ms": 60000 }
  ]
}
```

**阻止路径穿越**

```json
{
  "rules": [
    { "id": "deny-escape", "tool": "fs.*", "decision": "deny",
      "reason": "path escapes the workspace",
      "when": [{ "arg": "path", "normalize": "path", "prefix": ["..", "/", "C:/", "~"] }] }
  ]
}
```

`normalize` 是词法的：它不访问文件系统、不解析符号链接、不做 URL 解码。

**允许外发，但禁止携带刚读到的凭据**

```json
{
  "rules": [
    { "id": "read", "tool": "fs.read", "decision": "allow" },
    { "id": "post", "tool": "net.post", "decision": "allow" }
  ],
  "sensitive": [{ "tool": "fs.read", "when": [{ "arg": "path", "glob": ["**/*.env"] }] }],
  "egress": { "tools": ["net.*"], "on_taint": "deny" }
}
```

## 已知限制

- 血缘只匹配**原样出现**的值。Base64、分片、改写会绕过；这是精确匹配的代价。
- 不解析工具语义，`tool` 名称由服务端决定，恶意服务端可以改名规避规则；因此策略应配合“默认拒绝 + 显式允许”。
- `when` 只支持单层参数名，不支持 `a.b.c` 路径。
- 不支持正则，只有 glob 与前缀；这是为了保持求值可预测、无回溯风险。
- 服务端 guard 只执行 `deny`；`approval` 在 guard 里返回 `allow`，审批由网关负责。
