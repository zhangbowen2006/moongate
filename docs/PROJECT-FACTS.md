# 项目事实清单

供本人写申报书、答评审提问时核对。所有数字可在仓库中复现。

## 规模

| 部分 | 行数 | 说明 |
| --- | --- | --- |
| MoonBit 引擎 | 约 2600 | `protocol.mbt` `policy.mbt` `lineage.mbt` `engine.mbt` `ledger/report` `sha256.mbt` `json_util.mbt` `glob.mbt` |
| MoonBit 测试 | 约 705 | 26 个用例 |
| Node 宿主 | 约 760 | `src/` + `bin/`，含审批台页面 |
| 演示与测试客户端 | 约 730 | `demo/` |
| 集成测试 | 188 | `test/` |

判定逻辑全部在 MoonBit；Node 侧不含策略分支。

## 能力

- MCP stdio（换行分隔 JSON-RPC 2.0）透明代理
- 请求/响应关联、通知透传、服务端反向请求默认拒绝
- 有序规则、参数 glob/前缀/取反、默认拒绝、频率限制
- `tools/list` 能力裁剪
- 值级血缘：提取、指纹、来源、外发匹配、证据
- 一次性审批：参数摘要、TTL、消费后失效
- 哈希链账本、离线校验、HTML 报告
- CLI：`run` / `check` / `verify` / `report` / `version`

## 可复现命令

```sh
moon check --deny-warn
moon test --deny-warn              # 26 passed
node scripts/build.mjs
node --test test/*.test.mjs        # 6 passed
node demo/run.mjs                  # 8 个场景，全部断言
cd interop && npm install && node client.mjs   # 4/4
node bin/airlock.mjs verify --ledger runs/demo.jsonl
node bin/airlock.mjs report --ledger runs/demo.jsonl
```

## 与上一版的差异（评审可能追问）

| 维度 | AgentCanary（未通过） | Airlock |
| --- | --- | --- |
| 数据来源 | 外部提供的调用记录 | 网关实时观察的会话 |
| 判定时机 | 事后，对记录评分 | 转发前，决定是否执行 |
| 能否阻止副作用 | 不能 | 能，上游收不到被拒调用 |
| 核心机制 | 规则匹配 + 回归比较 | 策略 + 值级血缘 + 一次性审批 |
| 验证方式 | 合成样例 | 真实进程、真实文件、HTTP 计数、第三方互操作 |
| 代码关系 | — | 无复用，独立仓库 |

## 已知问题（主动说明，避免被问倒）

1. 血缘是精确值匹配，Base64/分片/改写可绕过；
2. 不经过网关的调用不受保护；
3. 审批台无身份认证，仅适合单机；
4. 账本逐条落盘，吞吐不是强项；
5. 只实现 stdio 传输，HTTP/SSE 未覆盖。

## 许可

MIT。MoonBit 核心库 Apache-2.0，许可证与 NOTICE 随 `dist/` 分发。
