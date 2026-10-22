# Changelog

## 0.2.0 — 2026-10-22

定位从“单一网关”改为“双点执行边界”。原因：通用 MCP 策略网关已有多个实现，仅靠功能无法形成差异。

### 新增

- 服务端内嵌 guard：`guard_create` / `guard_check`，与网关共用同一份 MoonBit 策略；只执行硬拒绝，`approval` 交给网关
- 演示第 9 步：绕过网关直连服务端，`fs.delete` 与路径穿越仍被拒绝
- 路径词法规范化：`normalize: "path"`，关闭 `reports/../../etc/passwd` 这类前缀绕过
- 29 个单元测试、9 个进程级测试（新增路径穿越、绕过网关）

### 变更

- 项目更名：Airlock → MoonGate，仓库迁移到 `zhangbowen2006/moongate`
- 文档新增“与现有方案的关系”，如实列出 MCP Shield / MCPKernel / mcp-firewall / taintmcp / AgentPerms 的重合点


## 0.1.0 — 2026-10-22

首个版本。定位是 Agent 与 MCP 服务端之间的运行时网关：判定发生在转发之前，被拒绝的调用不会产生副作用。

### 引擎（MoonBit）

- MCP stdio 传输的 JSON-RPC 2.0 解析与请求/响应关联
- 会话状态机：客户端行、服务端行、审批解析、超时驱动
- 策略模型：有序规则、`when` 参数条件（glob / 前缀 / 取反）、默认判定、频率限制
- 能力裁剪：按策略过滤 `tools/list`
- 值级数据血缘：密钥形状提取、SHA-256 指纹、来源追踪、外发匹配与证据
- 一次性审批：参数规范化摘要、TTL、消费后失效
- 哈希链账本：规范化 JSON、逐条提交前序哈希
- 账本校验与聚合报告

### 宿主（Node）

- `moongate run`：拉起上游 MCP 服务端，泵送两个方向的协议行，执行引擎动作
- 本地审批台：`127.0.0.1` 随机端口，批准/拒绝，实时倒计时
- `moongate verify`：离线校验账本
- `moongate report`：从账本生成自包含 HTML 报告
- `moongate check`：策略校验、生效规则、遮蔽警告
- 8 MiB 单行上限、上游崩溃处理、失败关闭

### 演示与验证

- `demo/run.mjs`：真实进程、真实文件、真实 HTTP 接收端，8 个场景带断言
- `interop/client.mjs`：官方 SDK 客户端 + 官方文件服务端互操作
- `demo/agent-llm.mjs`：OpenAI 兼容模型驱动（可选）
- 26 个 MoonBit 单元测试、6 个 Node 进程级集成测试
- CI：Linux / macOS / Windows

### 文档

- README、策略语法、架构、语义与信任边界、验收对照、驳回意见回应、演示脚本、来源与 AI 使用说明
