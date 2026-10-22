# MoonGate（月门）

**MCP 工具的双点执行边界。** 同一套 MoonBit 判定核心，既跑在网关进程里，也能被 MCP 服务端直接嵌入：网关被绕过时，服务端自己仍然会拒绝。

- 策略、值级血缘、一次性审批、哈希链账本，判定全部发生在执行之前
- 第二执行点是一个几十行的嵌入调用，不需要改协议、不需要模型配合
- 核心用 MoonBit 写，可编译到 JavaScript / Wasm；仓库自带编译产物，不装 MoonBit 也能运行

[报告样例](examples/report.sample.html) · [English](README.en.md) · [架构](docs/ARCHITECTURE.md) · [策略语法](docs/POLICY.md) · [信任边界](docs/SEMANTICS.md) · [驳回意见回应](docs/REVIEW-RESPONSE.md)

---

## 先说清楚：与现有方案的关系

MCP 安全网关在 2026 年已经是一个拥挤的赛道。以下项目都在做类似的事，功能上有明显重合：

| 项目 | 已有能力 |
| --- | --- |
| MCP Shield | 策略、密钥脱敏、跨工具外泄链、人工审批、哈希链审计 |
| MCPKernel / MCPGuard | 策略、污点扫描、沙箱、签名审计 |
| mcp-firewall | 策略、审批、哈希链、仪表盘 |
| taintmcp | 输出污点标记、来源追踪、首匹配策略 |
| AgentPerms | 录制真实会话后推断最小权限，再代理执行 |

**MoonGate 不是第一个策略网关，也不声称发明了这些机制。** 我们的差异只有两点，但都是结构性的：

1. **双点执行**：上面这些方案都是“一个代理进程”。代理被绕过（客户端直连服务端、服务端被别的进程调用、配置写错）就没有保护。MoonGate 把同一份策略编译进服务端，在工具函数执行前再判一次。两个点独立生效。
2. **MoonBit 单核多后端**：判定核心是一套 `.mbt` 代码，网关卡在 Node 里用，服务端可以直接嵌同一份编译产物；后续可编译到 Wasm/Native，不绑定运行时。这是 Python/TypeScript 方案做不到的部署形状。

如果你只需要一个代理，MoonGate 和上面几个项目能力接近；第二执行点是它存在的理由。这一点写在 [REVIEW-RESPONSE](docs/REVIEW-RESPONSE.md) 里，没有回避。

## 第二点解决什么

```
Agent ──stdio──▶ MoonGate 网关 ──stdio──▶ MCP Server ──▶ 文件 / 网络 / 数据库
                     │                        │
                     │ 判定 1                 │ 判定 2（内嵌 guard）
                     │ 策略 + 血缘 + 审批      │ 同一份策略，硬拒绝
                     └────────────────────────┘
```

演示里有一个专门的场景：**绕过网关，直接用客户端连服务端**，调用 `fs.delete` 和 `reports/../../etc/passwd`。两次都被服务端自己的 guard 拒绝，文件仍然存在。

网关负责有状态的部分：跨调用的数据血缘、人工审批、账本。服务端 guard 负责无状态的硬规则：禁用工具、路径逃逸、默认拒绝。分工写在 [SEMANTICS.md](docs/SEMANTICS.md)。

## 五分钟运行

只需要 Node.js 22+，仓库带 `dist/engine.js`。

```sh
git clone https://github.com/zhangbowen2006/moongate.git
cd moongate
node demo/run.mjs
```

演示启动真实进程、写真实文件、发真实 HTTP 请求，9 个场景逐项断言：

| 场景 | 可观测证据 |
| --- | --- |
| 凭据被读取后外发 | 被 `egress-taint` 拒绝；本地接收端计数保持 0 |
| `reports/../../etc/passwd` | 规范化后命中 `deny-escape`，上游未收到请求 |
| 写报告 | 审批台出现请求；批准后文件才落盘 |
| 换内容再写 | 参数哈希变化，必须重新审批；拒绝后文件不变 |
| 删除文件 | 工具未出现在 `tools/list`，强行调用也被拒绝 |
| **绕过网关直连服务端** | **服务端 guard 拒绝删除与路径穿越，文件仍在** |
| 账本 | `verify` 逐条重算哈希链 |

```sh
node bin/moongate.mjs verify --ledger runs/demo.jsonl
node bin/moongate.mjs report --ledger runs/demo.jsonl
```

### 从源码构建

需要 [MoonBit](https://www.moonbitlang.com/download/) 0.10.16+。

```sh
moon check --deny-warn
moon test --deny-warn       # 29 个单元测试
node scripts/build.mjs
node --test test/*.test.mjs # 8 个进程级测试
```

## 两种接入方式

### 1. 作为网关（任何 MCP 客户端）

把客户端配置里的启动命令换成 `moongate run ... -- <原命令>`：

```jsonc
{
  "mcpServers": {
    "workspace": {
      "command": "node",
      "args": [
        "/abs/path/moongate/bin/moongate.mjs", "run",
        "--policy", "/abs/path/policy.json",
        "--ledger", "/abs/path/runs/session.jsonl",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/abs/path/workspace"
      ]
    }
  }
}
```

网关对 MCP 透明；被拒绝的调用返回 `-32001`，带规则、原因和血缘证据。

### 2. 作为服务端内的守卫（第二执行点）

服务端（Node）在启动时加载同一份策略，执行工具前调用一次：

```js
import * as gate from 'moongate/dist/engine.js';
import { readFileSync } from 'node:fs';

const guard = JSON.parse(gate.guard_create(readFileSync('policy.json', 'utf8'))).handle;

// 每个工具函数执行前
const verdict = JSON.parse(gate.guard_check(guard, 'fs.delete', JSON.stringify(args)));
if (verdict.decision === 'deny') {
  return { isError: true, content: [{ type: 'text', text: `blocked by ${verdict.rule}` }] };
}
```

`approval` 在 guard 里被当作 `allow`：审批是有状态的，归网关管；guard 只执行硬拒绝，避免把网关已经批准的动作再挡一次。

MoonBit 服务端可以直接 `@moongate.guard_decision(policy, tool, args)`，不需要经过 JS。

## 三道检查（网关）

### 策略

规则按声明顺序匹配，第一条命中生效，未命中落到 `default_decision`（默认拒绝）。参数条件支持 glob、前缀、取反和路径规范化：

```jsonc
{ "id": "deny-escape", "tool": "fs.*", "decision": "deny",
  "reason": "path escapes the workspace",
  "when": [{ "arg": "path", "normalize": "path", "prefix": ["..", "/", "C:/", "~"] }] }
```

`normalize: "path"` 会先解析 `.` 与 `..`，所以 `reports/../../etc/passwd` 不会被 `reports/*` 这种规则误放行。这是这一版修掉的一个真实绕过。

被无条件拒绝的工具不会出现在 `tools/list`。

### 值级血缘

策略把某些结果标记为敏感后，网关提取其中形似密钥的值，只保存 SHA-256 指纹与 4 字符前缀，并记住来源调用。之后任何外发工具的参数中出现同一个值，调用被拒绝，证据指向源调用。

判定依据是值本身，不是 Agent 声称的标签。它不试图理解自然语言，因此可解释、可复现；代价是只覆盖“原样携带”，边界写在 [SEMANTICS.md](docs/SEMANTICS.md)。

### 一次性审批

需要审批的调用会挂起，在本地审批台（`127.0.0.1` 随机端口）出现。批准与 `(工具名, 参数)` 的规范化 SHA-256 绑定：换参数要重新批、用一次即失效、超时回 `-32002`。

## 账本

每行 JSONL 包含 `prev` 与 `hash`：

```
hash_n = SHA-256(prev_hash + "\n" + canonical(event_without_hash))
```

`canonical` 递归排序键，任何一行被改动都会让 `verify` 失败并指出序号。账本只记录工具名、参数键名、摘要和值指纹，不记录参数值。

## 工程证据

- `moon test --deny-warn`：29 个单元测试（策略顺序、血缘误报、路径规范化、guard、审批一次性、账本篡改）
- `node --test`：8 个真实进程测试（副作用、路径穿越、绕过网关、篡改、报告）
- `interop/`：官方 SDK 客户端 + 官方 filesystem 服务端，4/4 通过
- CI：Linux / macOS / Windows 三平台，含演示与互操作

## 边界

- 服务端没有嵌入 guard 时，绕过网关就失去保护；不是沙箱，不限制服务端自身权限
- 血缘是精确值匹配，编码、分片、改写可绕过
- 路径规范化是词法的，不解析符号链接
- 审批台无身份认证，只适合单机
- 只实现 stdio 传输

完整威胁模型与失败模式：[docs/SEMANTICS.md](docs/SEMANTICS.md)。

## 许可

MIT。MoonBit 核心库以 Apache-2.0 分发，许可证与 NOTICE 随 `dist/` 保留，见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。项目为独立新项目，无既有项目代码复用、无第三方项目移植；AI 辅助范围见 [PROVENANCE](docs/PROVENANCE.md)。
