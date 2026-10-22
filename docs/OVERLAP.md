# 与现有项目的关系

> 这份文档是必读材料。6 封历史驳回信里有 4 封的原因是“和已有项目重叠，申报书没有说明关系”。MoonGate 主动把这件事查清、写清，而不是等初审来问。

## 我们怎么查的

2026-10-22，用 Mooncakes 官方检索与 GitHub 检索，关键字：`mcp`、`policy`、`gateway`、`guard`、`audit`、`security`。原始结果保存在 [`registry-scan.json`](registry-scan.json)（80 个模块，含版本、下载量、仓库地址）。

```sh
moon search mcp --json --limit 15
moon search policy --json --limit 15
moon search gateway --json --limit 15
moon search guard --json --limit 15
moon search audit --json --limit 15
moon search security --json --limit 15
```

## Mooncakes 上的同类模块

| 模块 | 它做什么 | 与 MoonGate 的重合 | MoonGate 的不同 | 代码关系 |
| --- | --- | --- | --- | --- |
| `yadidyc/moonpod@0.2.0` | 传输无关的策略核心：Allow/Deny/Approval、调用与字节预算、审计事件 JSON/JSONL | 策略、预算、审批、审计这些**概念** | MoonGate 是 MCP 运行时：解析 JSON-RPC、裁剪 `tools/list`、跨调用/跨服务端血缘、密钥替身、哈希链账本、服务端第二执行点 | 无复用、无依赖、无移植 |
| `eisem/moon_policy@0.1.0` | RBAC 授权引擎：角色继承、属性条件、deny-by-default、lint | 规则求值与默认拒绝 | MoonGate 不实现 RBAC，也不做通用授权；规则只服务于 MCP 工具调用 | 无复用 |
| `geniuszby/moon-policy-diff@0.2.0` | 策略回归、租户隔离、发布风险审查 | 策略变更审查 | MoonGate 不做策略 diff；它做运行时拦截 | 无复用 |
| `123123213weqw/moon_policyforge@0.10.0` | 类型化规则求值、决策表、SHA-256 决策指纹 | 规则求值、指纹 | MoonGate 的指纹用于值血缘与账本链，不是决策表 | 无复用 |
| `123123213weqw/moon_scrub@0.5.2` | 离线敏感数据检测、脱敏、JSON/流式管道 | 敏感值识别与脱敏 | MoonGate 在 MCP 结果与参数边界做**可逆替身**，按目的地 `reveal`，并与血缘、审批、账本联动 | 无复用 |
| `colmugx/mcp@0.18.1` | MCP 服务端/客户端/宿主 SDK（stdio、HTTP） | 都涉及 MCP 协议 | MoonGate 不是 SDK，不帮人写服务端；它拦在客户端与服务端之间，并嵌入服务端做第二次判定 | 无复用；可用它写被保护的 server |
| `marianoguerra/mcp@0.10.1` 及 `mcp-server` / `mcp-client` | MCP 协议类型、JSON-RPC 编解码、传输 | 协议层 | MoonGate 自带最小协议层，重点是判定与证据，不是协议库 | 无复用 |
| `wzzc-dev/moui_agent_mcp@0.2.2` | 把 MoUI AgentHost 暴露为 MCP 的 JSON-RPC 路由 | 都是 MCP 进程 | MoonGate 做策略/血缘/审批/账本；它做路由 | 无复用 |
| `minie135/moon-audit@0.5.0-dev` | MoonBit 项目静态安全扫描 | 都是安全工具 | 静态扫描 vs 运行时拦截 | 无复用 |
| `chenzehaoo/moon_guard@0.1.11` | 包签名、清单完整性、typosquat | 都是“guard” | 供应链完整性 vs 工具调用边界 | 无复用 |
| `oyjh0381/moonmime` | MIME 解析与入站邮件网关 | 都有“gateway” | 邮件内容网关 vs MCP 工具网关 | 无复用 |

## Mooncakes 之外的同类项目

| 项目 | 它做什么 | MoonGate 的不同 |
| --- | --- | --- |
| MCP Shield | 策略、密钥脱敏、跨工具外泄链、审批、哈希链审计 | 单代理；MoonGate 增加服务端第二执行点与 MCP 边界的可逆替身 |
| MCPKernel / MCPGuard | 策略、污点、沙箱、签名审计 | MoonGate 不做沙箱；差异在双点执行与替身 |
| mcp-firewall | 策略、审批、哈希链、仪表盘 | 同上 |
| taintMCP | 输出污点标记、来源追踪、首匹配策略 | MoonGate 把替身与审批也纳入同一条数据流 |
| AgentPerms | 录制会话后推断最小权限 | MoonGate 不做策略推断；做运行时执行与跨服务端路由 |
| Authsome / OneCLI | 凭据代理：占位符在 HTTP 出口替换 | MoonGate 在 MCP 参数与结果边界替换，占位符可跨工具/跨服务端流转 |
| MCP Airlock（同名项目） | 能力租约 + 哈希链溯源 | 我们原名为 Airlock，发现重名后已改名 MoonGate；无代码关系 |

## 明确声明

1. **没有代码复用。** 本项目没有复制、移植、改写上述任何项目的代码；`moon.mod` 没有对它们的依赖。
2. **不声称首创。** 策略、审批、污点、审计这些机制在 MCP 安全领域和 MoonBit 生态里都已存在。
3. **产品定位不同。** MoonGate 不是通用策略引擎，而是 **MCP 工具调用的执行边界**：协议拦截、工具清单裁剪、跨调用/跨服务端血缘、密钥替身、哈希链账本、服务端内嵌 guard。
4. **评审如果只接受“没有任何相似项目”，本项目不满足。** 我们选择披露关系并说明差异，而不是隐藏。

## 如果只需要其中一部分

- 只要通用策略判定：用 `yadidyc/moonpod` 或 `eisem/moon_policy` 更合适。
- 只要写 MCP 服务端：用 `colmugx/mcp`。
- 只要离线脱敏：用 `moon_scrub`。
- 要在 MCP 边界做执行前拦截、密钥替身与双点执行：用 MoonGate。
