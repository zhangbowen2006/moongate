# MoonGate（月门）

[![CI](https://github.com/zhangbowen2006/moongate/actions/workflows/ci.yml/badge.svg)](https://github.com/zhangbowen2006/moongate/actions/workflows/ci.yml)
[![Mooncakes](https://img.shields.io/badge/mooncakes-zhangbowen2006%2Fmoongate-dfed86)](https://mooncakes.io/docs/zhangbowen2006/moongate)

**零改造的 MCP 执行边界。** 不改服务端一行代码：`moongate serve --policy p.json -- node <server entry>` 启动现有 MCP 服务端，同一套 MoonBit 策略就在服务端进程内、工具函数执行前生效。客户端不需要指向新地址，服务端不需要引入新依赖。

**密钥替身。** 敏感值在进入模型上下文之前被替换成 `«mg:…»` 占位符；只有策略显式允许的目的地，网关才会在转发前换回真值。模型可以“使用”密钥，但从未看见它。

- 零改造适配现有服务端：用官方 `@modelcontextprotocol/server-filesystem` 验证，拦截发生在服务端进程内，副作用没有发生
- 一个网关可带多个 MCP 服务端，跨进程血缘成立
- 策略、值级血缘、会话配额、一次性审批、哈希链账本，判定全部发生在执行之前
- 核心用 MoonBit 写，已发布到 [Mooncakes](https://mooncakes.io/docs/zhangbowen2006/moongate)；可编译到 JavaScript / Wasm

[报告样例](examples/report.sample.html) · [English](README.en.md) · [架构](docs/ARCHITECTURE.md) · [策略语法](docs/POLICY.md) · [信任边界](docs/SEMANTICS.md) · [驳回意见回应](docs/REVIEW-RESPONSE.md) · [同类项目对照](docs/OVERLAP.md) · [自查](docs/SELF-AUDIT.md)

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
| Authsome / OneCLI | 凭据代理：Agent 只拿到占位符，代理在出口替换 |

Mooncakes 上已有 `yadidyc/moonpod`（通用策略核心，含预算/审批/审计）、`eisem/moon_policy`（RBAC）等模块。**MoonGate 不是它们的扩展，也不复用它们的代码**；完整对照、检索记录与差异见 [docs/OVERLAP.md](docs/OVERLAP.md)。

如果你要的是通用策略语言或 RBAC，MoonPod / MoonPolicy 更合适；MoonGate 只做 MCP 工具调用这一层边界。

**MoonGate 不是第一个策略网关，也不声称发明这些机制。** 我们的差异是结构性的：

1. **零改造的服务端内执行**：上面这些方案都是一个代理进程，必须把客户端指过去；代理被绕过（客户端直连服务端、配置写错）就没有保护。MoonGate 用 Node loader 在服务端进程内注入判定，服务端源码不变，工具函数执行前就拦下。
2. **在工具调用边界做密钥替身**：凭据代理通常在 HTTP 出口替换 header；MoonGate 在 MCP 的 `tools/call` 参数与工具结果里做替换，占位符可以跨工具流转，替换目标由策略逐条授权。模型上下文里始终没有明文。
3. **MoonBit 单核多后端**：网关与服务端 guard 共用一套 `.mbt`；同一份代码发布为 Mooncakes 库，可编译到 JS/Wasm。

如果只用一个代理，MoonGate 和上面几个项目能力接近；零改造的服务端内执行与密钥替身是它存在的理由。这一点写在 [REVIEW-RESPONSE](docs/REVIEW-RESPONSE.md) 里，没有回避。

## 两个执行点

```
Agent ──stdio──▶ MoonGate 网关 ──stdio──▶ MCP Server ──▶ 文件 / 网络 / 数据库
                     │                        │
                     │ 判定 1                 │ 判定 2（内嵌 guard）
                     │ 策略 + 血缘 + 审批      │ 同一份策略，硬拒绝
                     └────────────────────────┘
```

演示里有一个专门的场景：**绕过网关，直接用客户端连服务端**，调用 `fs.delete` 和 `reports/../../etc/passwd`。两次都被服务端自己的 guard 拒绝，文件仍然存在。

网关负责有状态的部分：跨调用的数据血缘、人工审批、密钥替身、账本。服务端 guard 负责无状态的硬规则：禁用工具、路径逃逸、默认拒绝、未解析的占位符。

## 密钥替身

```
工具结果:  API_KEY=sk-live-9f3a2b7c1d4e
              │ 网关提取、指纹、存入会话 vault
              ▼
模型看到:  API_KEY=«mg:8b201fda70f4dd1b»
              │
              ├─ 发往未授权地址 → 拒绝（secret-reveal），明文不离开网关
              └─ 发往授权地址   → 转发前替换回真值，上游收到真实密钥
```

- vault 只在内存里，随会话结束消失；账本只记录指纹、4 字符前缀和替换次数。
- 替换规则与工具规则分开：允许调用某个工具，不等于允许它看见密钥。
- 服务端 guard 遇到未解析的占位符直接拒绝，避免绕过网关后把占位符当参数执行。

它不试图理解语义，只做精确值替换；边界写在 [SEMANTICS.md](docs/SEMANTICS.md)。

## 五分钟运行

只需要 Node.js 22+，仓库带 `dist/engine.js`。

```sh
git clone https://github.com/zhangbowen2006/moongate.git
cd moongate
node demo/run.mjs
```

演示启动**四个真实进程**（客户端、网关、文件服务端、网络服务端），写真实文件、发真实 HTTP 请求，10 个场景逐项断言：

| 场景 | 可观测证据 |
| --- | --- |
| 读取凭据 | 模型只看到 `«mg:…»`，明文没有进入上下文 |
| 替身发往未授权地址 | `secret-reveal` 拒绝；接收端 0 次 |
| 替身发往已授权地址 | 网关替换回真值；接收端收到真实密钥，1 次 |
| `reports/../../etc/passwd` | 规范化后命中 `deny-escape`，上游未收到请求 |
| 写报告 | 审批台出现请求；批准后文件才落盘 |
| 换内容再写 | 参数哈希变化，必须重新审批；拒绝后文件不变 |
| 删除文件 | 工具未出现在 `tools/list`，强行调用也被拒绝 |
| 绕过网关直连服务端 | 服务端 guard 拒绝删除与路径穿越，文件仍在 |
| 账本 | `verify` 逐条重算哈希链 |

```sh
node bin/moongate.mjs verify --ledger runs/demo.jsonl
node bin/moongate.mjs report --ledger runs/demo.jsonl
```

### 从源码构建

需要 [MoonBit](https://www.moonbitlang.com/download/) 0.10.16+。

```sh
moon check --deny-warn
moon test --deny-warn       # 42 个单元测试
node scripts/build.mjs
node --test test/*.test.mjs # 18 个 Node 测试
```

## 作为 MoonBit 库使用

```sh
moon add zhangbowen2006/moongate@0.6.1
```

```moonbit
import {
  "zhangbowen2006/moongate" @moongate,
}

fn main {
  let policy = @moongate.parse_policy(policy_json) catch {
    @moongate.PolicyError(message) => abort(message)
  }
  // 服务端第二执行点：只做硬拒绝，approval 交给网关
  let verdict = @moongate.guard_decision(policy, "fs.delete", args_json)
  println(@moongate.json_render(verdict))
}
```

网关侧使用 `new_session`、`client_line`、`server_line`、`resolve_approval`，接口与 `pkg.generated.mbti` 一致。

## 多个服务端

一个网关可以同时带多个 MCP 服务端。客户端看到合并后的工具清单，网关按工具归属把调用路由到对应进程，判定仍由同一个引擎完成：

```jsonc
// examples/servers.demo.json
{ "servers": [
  { "name": "fs",  "command": "node", "args": ["demo/server.mjs"], "env": { "MOONGATE_ROLE": "fs" } },
  { "name": "net", "command": "node", "args": ["demo/server.mjs"], "env": { "MOONGATE_ROLE": "net" } }
] }
```

```sh
node bin/moongate.mjs run --policy examples/policy.workspace.json \
  --servers examples/servers.demo.json --ledger runs/multi.jsonl
```

工具名冲突时自动加 `服务端名.` 前缀。跨进程血缘是重点：文件服务端读到的密钥被替换成占位符，网络服务端拿到占位符时同样受 `reveal` 约束。

当前多服务端模式只合并 `tools`；`resources`/`prompts` 路由到第一个服务端。

## 复用 MoonPod 策略（可选）

MoonPod 是 MoonBit 的通用策略核心。MoonGate 提供一个兼容层，把 MoonPod 的 JSON 策略子集转换后在 MCP 边界执行：

```sh
node bin/moongate.mjs import-policy --format moonpod \
  --in examples/policy.moonpod.json --out runs/imported.json
node bin/moongate.mjs check --policy runs/imported.json
```

支持的字段、明确的失败关闭项与语义差异见 [docs/MOONPOD.md](docs/MOONPOD.md)。这不是依赖或 fork：MoonGate 不引用 MoonPod 代码，输出仍是普通的 MoonGate 策略。

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

被拒绝的调用返回 `-32001`，带规则、原因和血缘证据；被保护的返回值是占位符。

### 2. 作为服务端内的守卫（第二执行点）

```js
import * as gate from 'moongate/dist/engine.js';
import { readFileSync } from 'node:fs';

const guard = JSON.parse(gate.guard_create(readFileSync('policy.json', 'utf8'))).handle;

const verdict = JSON.parse(gate.guard_check(guard, 'fs.delete', JSON.stringify(args)));
if (verdict.decision === 'deny') {
  return { isError: true, content: [{ type: 'text', text: `blocked by ${verdict.rule}` }] };
}
```

`approval` 在 guard 里是 `allow`：审批有状态，归网关管。策略加载失败时服务端拒绝所有工具调用（失败关闭）。

## 策略与语义

规则按声明顺序匹配，第一条命中生效，未命中落到 `default_decision`（默认拒绝）。参数条件支持 glob、前缀、取反和路径规范化：

```jsonc
{ "id": "deny-escape", "tool": "fs.*", "decision": "deny",
  "when": [{ "arg": "path", "normalize": "path", "prefix": ["..", "/", "C:/", "~"] }] }
```

`normalize: "path"` 先解析 `.` 与 `..`，所以 `reports/../../etc/passwd` 不会被 `reports/*` 误放行。

密钥替身另有两段配置：

```jsonc
{
  "mask_secrets": true,
  "sensitive": [{ "tool": "fs.read", "when": [{ "arg": "path", "glob": ["**/*.env"] }] }],
  "reveal": [{ "id": "internal", "tool": "net.post",
               "when": [{ "arg": "url", "glob": ["**/internal/**"] }] }]
}
```

会话配额独立于频率限制，按整场会话累计：

```jsonc
{ "budget": { "max_calls": 80, "max_arg_bytes": 262144, "max_reveals": 5 } }
```

`max_reveals` 限制密钥被换回真值的次数——即使目的地都合法，也不允许无限取用。审批与 `(工具名, 参数)` 的规范化 SHA-256 绑定，换参数、重放、超时都会失效。

## 账本

每行 JSONL 包含 `prev` 与 `hash`：

```
hash_n = SHA-256(prev_hash + "\n" + canonical(event_without_hash))
```

`canonical` 递归排序键，任何一行被改动都会让 `verify` 失败并指出序号。账本只记录工具名、参数键名、摘要、值指纹和替换次数，不记录参数值或明文。

## 工程证据

- `moon test --deny-warn`：42 个单元测试（策略顺序、血缘误报、路径规范化、guard、替身替换、审批一次性、账本篡改）
- `node --test`：18 个 Node 测试（10 个进程测试 + 2 个 MoonPod 兼容层测试 + 6 个材料校验测试）
- `interop/`：官方 SDK 客户端 + 官方 filesystem 服务端，4/4 通过
- Mooncakes：`moon add zhangbowen2006/moongate@0.6.1`，已在空工程中安装并调用 `guard_decision` 验证
- 申报材料校验：`npm run check:submission -- SUBMISSION.md`，6 个测试覆盖格式/披露/场景数量
- CI：Linux / macOS / Windows 三平台，含演示与互操作

## 边界

- 服务端没有嵌入 guard 时，绕过网关就失去保护；不是沙箱
- 替身只覆盖工具结果里的字符串叶子；如果明文从别的通道进入上下文，不会被替换
- 替换目标由策略决定，策略写错就会把密钥发给错误的人
- 血缘与替身都是精确值匹配，编码、分片、改写可绕过
- 路径规范化是词法的，不解析符号链接
- 审批台无身份认证，只适合单机
- 只实现 stdio 传输；多服务端模式只合并 tools

完整威胁模型与失败模式：[docs/SEMANTICS.md](docs/SEMANTICS.md)。

## 许可

MIT。MoonBit 核心库以 Apache-2.0 分发，许可证与 NOTICE 随 `dist/` 保留，见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。项目为独立新项目，无既有项目代码复用、无第三方项目移植；AI 辅助范围见 [PROVENANCE](docs/PROVENANCE.md)。
