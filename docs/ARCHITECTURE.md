# 架构

## 为什么分成 MoonBit 引擎和 Node 传输层

MCP 的 stdio 传输依赖进程与管道，而 MCP 生态的绝大多数服务端是 npm 包。让网关能拉起任意 `node xxx` 或 `npx xxx`，是实际可用性的前提；这部分在 Node 里只需要几十行。

但“能不能拦得住”取决于协议状态机、判定顺序、血缘与账本的实现质量。这些放在 MoonBit 里，理由有三：

1. 判定逻辑是纯函数式的状态变换，适合无 GC 压力的强类型语言；
2. 同一套代码可编译到 JS/Wasm/Native，不被 Node 锁死；
3. 边界清晰：把 `src/` 删掉，引擎依然能对每条消息给出正确判定，只是没有人替它搬运字节。

因此 JS 侧不做任何判定，只执行引擎返回的动作。

## 组件

```
┌────────────────────┐
│  MCP Client         │  Claude Desktop / Cursor / SDK / 自研 Agent
└─────────┬──────────┘
          │ stdio (newline-delimited JSON-RPC)
┌─────────▼──────────────────────────────────────────────┐
│  bin/airlock.mjs + src/gateway.mjs                     │
│  · 拉起上游进程，泵送两个方向的行                        │
│  · 执行动作：upstream / client / ledger / approval      │
│  · 审批台 HTTP (127.0.0.1)                              │
└─────────┬──────────────────────────────────────────────┘
          │ 每行调用一次
┌─────────▼──────────────────────────────────────────────┐
│  MoonBit engine (dist/engine.js)                       │
│  protocol.mbt  JSON-RPC 解析、请求/响应关联              │
│  policy.mbt    策略解析、首匹配求值、能力裁剪             │
│  lineage.mbt   密钥形状提取、指纹、外发匹配               │
│  engine.mbt    会话状态机、审批、账本事件                 │
│  report.mbt    链校验、聚合报告                          │
│  sha256.mbt    摘要、指纹、哈希链                        │
└─────────┬──────────────────────────────────────────────┘
          │ stdio
┌─────────▼──────────┐
│  MCP Server         │  文件 / HTTP / 数据库 / 任何工具
└────────────────────┘
```

## 一次工具调用的完整路径

```
client → { "method":"tools/call", "params":{"name":"fs.write","arguments":{...}} }
  │
  ├─ 解析 JSON-RPC，关联 id
  ├─ 频率检查（超限 → deny / rate-limit）
  ├─ 血缘检查（外发工具 + 参数含已知敏感值 → deny / egress-taint）
  ├─ 规则匹配（首条命中 → allow / deny / approval）
  │
  ├─ allow     → 转发原始行；把 call_id 与工具名记入 inflight
  ├─ deny      → 合成 -32001 响应给 client；不写上游 stdin
  └─ approval  → 挂起原始行；发出 approval 动作；等待审批台
                   ├─ 批准 → 转发原始行，授权消费
                   ├─ 拒绝 → -32001
                   └─ 超时 → -32002
  │
  ▼
server → 结果行
  │
  ├─ 若 id 对应 tools/list → 按策略裁剪工具清单后转发
  ├─ 若 id 在 inflight  → 若是敏感来源，提取值指纹写入血缘表
  └─ 转发原始结果给 client（不修改内容）
```

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

`verify` 从空 `prev` 开始，逐条重算，命中不一致立即返回序号与原因。

## 关键取舍

**判定放在转发之前，而不是结果返回之后。** 结果返回后再检查只能做事后审计；要阻止副作用，必须在写上游 stdin 之前完成。

**血缘用精确值，而不是语义分类。** 语义分类需要模型，结论不稳定、难解释；精确值匹配可复现，且证据能指向具体调用。代价是变形外泄覆盖不到，这一点写在 `SEMANTICS.md` 里。

**审批挂起请求，而不是返回“待批准”错误。** 返回错误会让 Agent 立刻重试或放弃；挂起让它在一次请求内等待人的决定，协议上更自然。代价是需要超时兜底。

**账本逐条落盘。** 用 `appendFileSync` 而不是流缓冲，是为了崩溃时前面的判定仍然可读。吞吐不是这个工具的瓶颈。

**工具清单裁剪。** 让 Agent 看不到被禁用的工具，比让它试错后被拒绝更省 token，也更符合最小权限。

## 可测试性

引擎不依赖进程：`client_line(session, line, now)` 返回动作数组，测试直接断言“有没有 upstream 动作”。因此大部分安全语义可以在毫秒级验证，进程级测试只用于验证真实副作用。

`now` 由调用方传入（毫秒时间戳，`Int64`），审批过期、频率窗口都可以用固定时间测试，不需要睡眠。

## 扩展点

- 新策略原语：`policy.mbt` 增加字段与匹配分支，`policy_wbtest.mbt` 补测试；
- 新传输（HTTP/SSE、WebSocket）：只需在宿主侧实现“读一行 → 调引擎 → 执行动作”，引擎不改；
- 新审批通道（IM、工单）：替换 `src/approval.mjs`，动作协议不变；
- 账本外锚定：定期把 `verify` 的 head 写到外部系统，可检测整体替换。
