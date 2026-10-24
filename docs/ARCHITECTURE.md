# 架构

## 两个执行点，一套判定核心

MoonGate 的判定逻辑只有一个实现：MoonBit 写的 `policy.mbt` / `lineage.mbt` / `engine.mbt`。它被放在两个位置执行：

1. **网关进程**（`bin/moongate.mjs` + `src/gateway.mjs`）：有状态，负责跨调用的血缘、审批、账本，并转发协议行。
2. **服务端内嵌 guard**：无状态，只做硬拒绝（禁用的工具、逃逸路径、默认拒绝）。服务端在工具函数执行前调用一次。

```
┌────────────────────┐
│  MCP Client         │  Claude Desktop / Cursor / SDK / 自研 Agent
└─────────┬──────────┘
          │ stdio（换行分隔 JSON-RPC）
┌─────────▼──────────────────────────────────────────────┐
│  bin/moongate.mjs + src/gateway.mjs                     │
│  · 拉起上游、泵送两个方向的行                            │
│  · 执行动作：upstream / client / ledger / approval      │
│  · 审批台 HTTP (127.0.0.1)                              │
└─────────┬──────────────────────────────────────────────┘
          │ 每行调用一次
┌─────────▼──────────────────────────────────────────────┐
│  MoonBit engine (dist/engine.js)                       │
│  protocol.mbt  JSON-RPC 解析、请求/响应关联              │
│  policy.mbt    策略解析、首匹配求值、路径规范化           │
│  lineage.mbt   密钥形状提取、指纹、外发匹配               │
│  engine.mbt    会话状态机、审批、账本事件、guard         │
│  report.mbt    链校验、聚合报告                          │
│  sha256.mbt    摘要、指纹、哈希链                        │
└─────────┬──────────────────────────────────────────────┘
          │ stdio
┌─────────▼──────────────────────────────────────────────┐
│  MCP Server                                             │
│  · 工具函数执行前：guard_check(tool, args)              │
│  · 同一份 MoonBit 策略，硬拒绝                          │
└────────────────────────────────────────────────────────┘
```

## 为什么这样分工

**有状态的东西必须在网关。** 值级血缘要记住“这个值来自第几次调用”，审批要挂起请求、等一个不在协议里的人，账本要串前序哈希。这些都无法在单个工具函数里完成。

**无状态的东西应该在服务端再判一次。** 一个工具该不该被调用、路径是否逃出工作区，只依赖工具名和参数，不依赖会话历史。把它们编译进服务端，代理被绕过时仍然有效。

**guard 不处理审批。** `approval` 在 guard 里返回 `allow`。否则网关已经批准的调用会被服务端再挡一次，形成死锁。审批的语义是“这次允许”，只有网关知道。

## 一次工具调用的完整路径

```
client → { "method":"tools/call", "params":{"name":"fs.write","arguments":{...}} }
  │
  ├─ 解析 JSON-RPC，关联 id
  ├─ 频率检查（超限 → deny / rate-limit）
  ├─ 血缘检查（外发工具 + 参数含已知敏感值 → deny / egress-taint）
  ├─ 替身检查（参数含 «mg:…» → 必须有 reveal 规则，否则 secret-reveal 拒绝）
  ├─ 规则匹配（首条命中 → allow / deny / approval；参数按需做路径规范化）
  │
  ├─ allow     → 转发原始行；把 call_id 与工具名记入 inflight
  ├─ deny      → 合成 -32001 给 client；不写上游 stdin
  └─ approval  → 挂起原始行；发出 approval 动作；等待审批台
                   ├─ 批准 → 转发原始行，授权消费
                   ├─ 拒绝 → -32001
                   └─ 超时 → -32002
  │
  ▼
server → guard_check(name, args)
  ├─ deny  → 返回 isError，工具函数不执行
  └─ allow → 执行工具
  │
  ▼
server → 结果行
  │
  ├─ 若 id 对应 tools/list → 按策略裁剪工具清单后转发
  ├─ 若 id 在 inflight  → 若是敏感来源，提取值、写入 vault 与血缘表
  │                       并把结果里的明文替换为 «mg:<fp>»
  └─ 转发改写后的结果给 client（敏感值不出网关）
```

## 多服务端模式

`--servers servers.json` 时，宿主为每个服务端拉起一个进程，并做三件不属于判定的事：

1. 启动时对每个服务端 `initialize` + `tools/list`，记录工具归属；
2. 客户端 `tools/list` 时合并清单（重名加 `服务端名.` 前缀），再交给引擎过滤；
3. 客户端 `tools/call` 时，按引擎放行的工具名找到归属进程，把请求写到那个进程的 stdin。

引擎仍然只有一个会话：血缘、配额、审批、vault 都跨服务端共享。因此“文件服务端读到密钥、网络服务端发送”是一条真实的跨进程数据流，而不是同一个服务端里的两个工具。

约束：目前只对 `tools` 做合并与路由；`resources`/`prompts` 发往第一个服务端。

## 密钥替身

敏感工具结果进入引擎后，`scan_raw` 取出密钥形状的值，`remember_raw` 做三件事：

1. 把指纹与来源写入血缘表（用于外发判定）；
2. 把原值、指纹、来源调用写入会话 `vault`（只在内存）；
3. 用 `«mg:<fingerprint>»` 替换结果里所有字符串叶子，再转发给客户端。

调用方向相反：客户端参数里出现占位符时，引擎先查 `reveal` 规则。没有匹配就返回 `secret-reveal`，不转发；有匹配就把占位符换回原值，再写上游 stdin。

替换规则与工具规则分开，是因为“允许调用 net.post”和“允许 net.post 看见密钥”是两件事。审批摘要基于**替换前**的参数（只含占位符），所以审批人看不到明文，账本也不会记录明文。

vault 的生命周期等于会话：进程退出即消失；没有落盘、没有导出命令。代价是网关重启后旧占位符无法解析——这是有意的，旧占位符应当失效。

## 账本格式

一行一个 JSON 对象：

```json
{
  "seq": 7,
  "ts": 1761100000004,
  "session": "run-2026-10-22T09-10-33-580Z",
  "kind": "decision",
  "tool": "net.post",
  "call": "c3",
  "decision": "deny",
  "rule": "egress-taint",
  "reason": "arguments carry 1 value(s) seen in sensitive results",
  "digest": "…",
  "via": "client",
  "args_keys": ["url", "body"],
  "evidence": [
    { "fingerprint": "9c1f…", "preview": "sk-l…", "source_call": "c2", "source_tool": "fs.read" }
  ],
  "prev": "…",
  "hash": "…"
}
```

哈希计算：

```
hash = SHA-256(prev_hash + "\n" + canonical(event_without_hash))
```

`canonical` 递归排序对象键，数字统一为整数或最短浮点表示。实现上不使用语言自带的字符串比较来决定键序（MoonBit 的 `String` 比较并非字典序），而是逐码位比较，保证跨后端一致。

## 关键取舍

**判定放在转发之前。** 结果返回后再检查只能做事后审计；要阻止副作用，必须在写上游 stdin 之前完成。服务端 guard 同理，在工具函数入口之前。

**替身替代“只拦截”。** 只拦截会让 Agent 无法完成需要密钥的任务；替身让它在看不到明文的情况下继续工作，同时在未授权目的地保持拒绝。代价是引入了一份内存中的明文，必须明确它的生命周期与边界。

**血缘用归一化匹配而不是语义分类。** 语义分类需要模型，结论不稳定、难解释；精确值加常见编码（拆分、改大小写、Base64、URL-safe）的归一化匹配可复现，证据能指向具体调用。代价是任意加密、压缩或语义改写仍覆盖不到。

**审批挂起请求，而不是返回“待批准”错误。** 返回错误会让 Agent 立刻重试或放弃；挂起让它在一次请求内等待人的决定。

**账本逐条落盘。** 用 `appendFileSync` 而不是流缓冲，是为了崩溃时前面的判定仍然可读。吞吐不是瓶颈。

**工具清单裁剪。** 让 Agent 看不到被禁用的工具，比让它试错后被拒绝更省 token，也更符合最小权限。

**路径规范化是词法的。** 解析 `.` 与 `..`，不碰文件系统、不解析符号链接。它关闭了 `reports/../../etc/passwd` 这类前缀绕过，但不防御符号链接逃逸，这一点写在 `SEMANTICS.md` 里。

## 可测试性

引擎不依赖进程：`client_line(session, line, now)` 返回动作数组，测试直接断言“有没有 upstream 动作”。guard 更简单：`guard_decision(policy, tool, args)` 是纯函数。因此大部分安全语义可以在毫秒级验证，进程级测试只用于验证真实副作用与绕过场景。

`now` 由调用方传入（毫秒时间戳，`Int64`），审批过期、频率窗口都可以用固定时间测试，不需要睡眠。

## 扩展点

- 新策略原语：`policy.mbt` 增加字段与匹配分支，补测试；
- 新传输（HTTP/SSE、WebSocket）：宿主侧实现“读一行 → 调引擎 → 执行动作”，引擎不改；
- 新审批通道（IM、工单）：替换 `src/approval.mjs`，动作协议不变；
- 服务端 guard：任何 Node 服务端可嵌入 `dist/engine.js`；MoonBit 服务端直接调用 `guard_decision`；
- 账本外锚定：定期把 `verify` 的 head 写到外部系统，可检测整体替换。
