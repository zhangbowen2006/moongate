# 项目事实清单

供本人写申报书、答评审提问时核对。所有数字可在仓库中复现。

## 规模

| 部分 | 行数 | 说明 |
| --- | --- | --- |
| MoonBit 引擎 | 约 2680 | `protocol.mbt` `policy.mbt` `lineage.mbt` `paths.mbt` `engine.mbt` `report.mbt` `sha256.mbt` `json_util.mbt` `glob.mbt` |
| MoonBit 测试 | 约 780 | 29 个用例 |
| Node 宿主 | 约 760 | `src/` + `bin/`，含审批台页面 |
| 演示与测试 | 约 1010 | `demo/` + `test/` |

判定逻辑全部在 MoonBit；Node 侧不含策略分支。服务端 guard 也调用同一份 MoonBit 代码。

## 能力

- MCP stdio（换行分隔 JSON-RPC 2.0）透明代理
- 请求/响应关联、通知透传、服务端反向请求默认拒绝
- 有序规则、参数 glob/前缀/取反/路径规范化、默认拒绝、频率限制
- `tools/list` 能力裁剪
- 值级血缘：提取、指纹、来源、外发匹配、证据
- 一次性审批：参数摘要、TTL、消费后失效
- 哈希链账本、离线校验、HTML 报告
- 服务端内嵌 guard：同一份策略的第二个执行点，绕过网关仍生效
- CLI：`run` / `check` / `verify` / `report` / `version`

## 可复现命令

```sh
moon check --deny-warn
moon test --deny-warn              # 29 passed
node scripts/build.mjs
node --test test/*.test.mjs        # 8 passed
node demo/run.mjs                  # 9 个场景，含绕过网关
cd interop && npm install && node client.mjs   # 4/4
node bin/moongate.mjs verify --ledger runs/demo.jsonl
node bin/moongate.mjs report --ledger runs/demo.jsonl
```

## 与现有方案的差异（评审可能追问）

通用 MCP 策略网关已有多个开源实现（MCP Shield、MCPKernel、mcp-firewall、taintMCP），AgentPerms 也做了会话录制后推断策略。本项目**不声称发明**这些机制。

差异是部署模型：

- 现有方案是单个代理进程；代理被绕过即失效。
- MoonGate 把同一份 MoonBit 策略编译进服务端，工具函数执行前再判一次；演示里直连服务端仍被拒绝。
- 判定核心一套代码，网关与 guard 共用；MoonBit 可编译到 JS/Wasm，不绑定解释器运行时。

## 与上一版的差异

| 维度 | AgentCanary（未通过） | MoonGate |
| --- | --- | --- |
| 数据来源 | 外部提供的调用记录 | 网关实时观察的会话 |
| 判定时机 | 事后，对记录评分 | 转发前，决定是否执行 |
| 能否阻止副作用 | 不能 | 能，上游收不到被拒调用 |
| 执行点 | 无 | 网关 + 服务端 guard |
| 核心机制 | 规则匹配 + 回归比较 | 策略 + 值级血缘 + 一次性审批 + 第二执行点 |
| 验证方式 | 合成样例 | 真实进程、真实文件、HTTP 计数、绕过场景、第三方互操作 |
| 代码关系 | — | 无复用，独立仓库 |

## 已知问题（主动说明，避免被问倒）

1. 服务端未嵌入 guard 时，绕过网关不受保护；
2. 血缘是精确值匹配，Base64/分片/改写可绕过；
3. 路径规范化是词法的，不解析符号链接；
4. 审批台无身份认证，仅适合单机；
5. 账本逐条落盘，吞吐不是强项；
6. 只实现 stdio 传输，HTTP/SSE 未覆盖。

## 许可

MIT。MoonBit 核心库 Apache-2.0，许可证与 NOTICE 随 `dist/` 分发。
