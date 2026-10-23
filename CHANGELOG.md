# Changelog

## 0.7.0 — 2026-10-24

面向「现有 MCP 生态」的一次实质扩展：不改服务端代码就能保护它，并补上变形外泄与 HTTP 传输。

### 新增

- `moongate serve --policy <file> -- node <entry>`：Node `--import` loader 在服务端进程内拦截 `tools/call`，服务端源码零修改；已用官方 `@modelcontextprotocol/server-filesystem` 验证 `write_file` 被拒且目标文件未创建
- Streamable HTTP 传输：`run --http [port]` 在 `/mcp` 提供 POST（单条 JSON-RPC）与 GET（SSE 流），同一套引擎判定
- 变形外泄检测：拆分隔符、改大小写、Base64、URL-safe Base64 归一化匹配
- 新增 `test/http.test.mjs`（2 项）、`variant_wbtest.mbt`（5 项）

### 变更

- 主叙事从「双点执行」改为「零改造的 MCP 执行边界」：第二执行点不再要求服务端主动集成
- 47 个 MoonBit 单元测试、20 个 Node 测试

## 0.6.1 — 2026-10-22

修复与文档校准，不引入新能力。

### 修复

- 路径规范化只把 `[A-Za-z]:` 当作 Windows 盘符；`1:` 之类不再被误判为盘符
- 补充盘符根不可被 `..` 逃逸的回归断言（`C:/foo/../../secret` → `C:/secret`）

### 文档

- 统一测试数量为实测值：42 个 MoonBit 单元测试 + 18 个 Node 测试
- 修正 `PROJECT-FACTS.md` 各模块行数、重复编号
- 删除一个未跟踪、无断言的实验测试文件，消除本地/CI 计数差异

## 0.6.0 — 2026-10-22

新增 MoonPod 策略兼容层，把“同类项目”关系从竞争改为可验证的上层复用。

### 新增

- `moongate import-policy --format moonpod`：把 MoonPod JSON 策略转换为 MoonGate 策略
- 映射 `allowed_tools`、`read_roots`、`write_roots`、`protected_paths`、`network_rules`、`approval_required_tools`、`max_calls`、`max_operation_bytes`
- 对 `command_rules`、`resource_rules`、`tool_quotas`、`max_io_bytes`、`process.run` 失败关闭
- `budget.max_single_bytes`：单次操作参数字节上限（用于对齐 MoonPod 的 `max_operation_bytes`）
- 42 个单元测试（新增 3 个适配器测试、1 个单次字节测试）；18 个 Node 测试


## 0.5.1 — 2026-10-22

材料合规补丁，运行时代码不变。针对 8 月 6 封驳回信中的“重叠未披露、作者归属、申报书格式”。

### 新增

- `docs/OVERLAP.md`：逐个列出 Mooncakes/GitHub 同类项目、重合点、差异、代码关系
- `docs/registry-scan.json`：2026-10-22 的 `moon search` 原始结果（80 个模块）
- `docs/AUTHORSHIP.md`：36 个提交的作者/提交者审计，确认无他人提交
- `docs/REJECTION-PATTERNS.md`：6 封驳回信的逐条对照
- `SUBMISSION.md`：一页 Markdown 骨架，含强制的“与现有项目的关系”
- `scripts/check-submission.mjs` + 6 个测试：检查长度、章节、场景数、同类项目披露、占位符、HTML
- `docs/SUBMISSION-CHECKLIST.md`：提交前逐项清单


## 0.5.0 — 2026-10-22

新增多服务端模式：一个网关同时带多个 MCP 服务端，工具清单合并、调用按归属路由，血缘与密钥替身跨进程生效。

### 新增

- `--servers servers.json`：字段 `name` / `command` / `args` / `env`
- 启动时初始化每个服务端并学习工具归属；工具重名自动加 `服务端名.` 前缀
- `tools/list` 合并后仍由引擎按策略裁剪
- `tools/call` 按归属路由；审批、配额、替换预算在跨服务端会话内共享
- 演示改为四个真实进程（客户端、网关、文件服务端、网络服务端）
- 1 个多服务端进程级测试

### 变更

- 版本 0.5.0；38 个单元测试、10 个进程测试
- 多服务端模式目前只合并 tools；resources/prompts 路由到第一个服务端


## 0.4.0 — 2026-10-22

补齐执行边界的“总量”维度，并把双点一致性变成可验证的测试。

### 新增

- 会话配额 `budget`：`max_calls`、`max_arg_bytes`、`max_reveals`，`0` 表示不限制
- 审批批准时复检替换配额，避免多个待批请求合计超限
- 两点判定一致性穷举测试：工具 × 参数交叉组合，断言网关与 guard 的硬判定一致
- `moongate check` 告警：默认放行、全工具 allow、无目的地的 reveal、关闭脱敏但存在敏感规则
- `moongate check` 显示配额与 reveal 规则

### 变更

- 版本 0.4.0；38 个单元测试、9 个进程测试


## 0.3.0 — 2026-10-22

新增“密钥替身”：敏感值进入模型上下文之前被替换为占位符，只在策略授权的目的地的转发前换回真值。

### 新增

- `mask_secrets`：工具结果中的密钥形状值替换为 `«mg:<fingerprint>»`，明文只存会话内存 vault
- `reveal` 规则：按工具与参数条件授权替换目标；未授权目的地返回 `secret-reveal`
- 服务端 guard 拒绝未解析的占位符（`unresolved-secret`），防止绕过网关后把占位符当参数执行
- 演示新增“替身发往未授权/已授权地址”，接收端按路径计数验证
- 5 个替身单元测试与 1 个引擎级端到端测试

### 变更

- 版本 0.3.0，准备发布 Mooncakes
- 文档新增“自查：两份驳回信的共性”，逐条对照通用性与基础能力完整性


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
