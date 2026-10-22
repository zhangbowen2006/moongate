# Airlock

**Agent 与工具之间的气闸舱。** 每一次 MCP 工具调用在真正执行之前，先经过策略、数据血缘和人工审批三道检查；被拒绝的调用不会到达上游服务，因此副作用根本不存在，而不是事后被检测出来。

核心决策引擎用 MoonBit 实现，同一套代码可编译到 JavaScript / Wasm。仓库自带已编译引擎，**不装 MoonBit 也能直接运行演示**。

- 在线演示/报告样例：`runs/demo.report.html`（运行演示后生成）
- 驳回意见逐条回应：[docs/REVIEW-RESPONSE.md](docs/REVIEW-RESPONSE.md)
- 验收自查对照：[docs/ACCEPTANCE.md](docs/ACCEPTANCE.md)
- 策略语法：[docs/POLICY.md](docs/POLICY.md) · 信任边界：[docs/SEMANTICS.md](docs/SEMANTICS.md)

---

## 为什么不是又一个“调用日志分析器”

上一版项目做的是离线回放：拿到一份已经发生的调用记录，判断它是否合规。这类工具只能回答“刚才发生了什么”，无法阻止任何事，而且结论完全依赖别人提供的记录是否完整可信。

Airlock 换了一个位置：**它站在 Agent 与 MCP 服务端的进程之间**。协议消息必须经过它，判定发生在转发之前。

```
Agent ──stdio──▶ Airlock ──stdio──▶ MCP Server ──▶ 文件 / 网络 / 数据库
                    │
                    ├─ 策略：这个工具、这组参数，允许吗？
                    ├─ 血缘：参数里是否带着刚才读到的密钥？
                    ├─ 审批：需要人点一下吗？只授权这一次。
                    └─ 账本：哈希链记录，可离线校验
```

它不读取历史记录，也不需要任何人提供“可信的调用数据”。会话本身就是数据源。

## 五分钟运行

只需要 Node.js 22+。仓库已包含编译好的 MoonBit 引擎。

```sh
git clone https://github.com/zhangbowen2006/airlock.git
cd airlock
node demo/run.mjs
```

演示会启动三个真实进程（Agent 客户端、Airlock 网关、MCP 服务端），并在 `runs/` 下产生真实文件、账本和 HTML 报告。它会逐项验证：

| 场景 | 可观测证据 |
| --- | --- |
| 凭据被读取后尝试外发 | 调用被 `egress-taint` 拒绝；本地接收端计数保持 0 |
| 路径逃逸 | 被 `deny-escape` 拒绝，上游未收到请求 |
| 写报告需要审批 | 浏览器审批台出现请求；批准后文件才落盘 |
| 换一份内容再写 | 参数哈希变化，必须重新审批；拒绝后文件保持原样 |
| 删除文件 | 工具未出现在 `tools/list`，强行调用也被拒绝 |
| 账本完整性 | `verify` 逐条重算哈希链 |

```sh
node bin/airlock.mjs verify --ledger runs/demo.jsonl   # 校验哈希链
node bin/airlock.mjs report --ledger runs/demo.jsonl   # 生成 HTML 报告
```

### 从源码构建

需要 [MoonBit](https://www.moonbitlang.com/download/) 0.10.16 或更新版本。

```sh
moon check --deny-warn
moon test --deny-warn
node scripts/build.mjs     # 产出 dist/engine.js
node demo/run.mjs
```

## 接入任何 MCP 客户端

把客户端原来指向服务端的命令，改成指向 Airlock：

```jsonc
// Claude Desktop / Cursor / 任意 MCP 客户端配置
{
  "mcpServers": {
    "workspace": {
      "command": "node",
      "args": [
        "/absolute/path/to/airlock/bin/airlock.mjs",
        "run",
        "--policy", "/absolute/path/to/policy.json",
        "--ledger", "/absolute/path/to/runs/session.jsonl",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/absolute/path/to/workspace"
      ]
    }
  }
}
```

Airlock 对 MCP 是透明的：握手、能力协商、通知、错误码都按协议转发。唯一的变化是，被判为拒绝的调用会收到一个 `-32001` 错误，错误里带有规则编号、原因和血缘证据，Agent 可以据此调整计划。

第三方互操作验证（官方 SDK 客户端 + 官方文件服务端，Airlock 夹在中间）：

```sh
cd interop && npm install && node client.mjs
# 4/4 项通过：工具清单裁剪、正常调用、越界拦截、禁用工具不可执行
```

## 三道检查

### 1. 策略：允许、拒绝、还是问人

规则按声明顺序匹配，第一条命中生效；没有命中则落到 `default_decision`（默认拒绝）。先匹配的设计让“具体规则在前、兜底规则在后”成为可读的约定，`airlock check` 会对被前面规则遮蔽的条目给出警告。

```jsonc
{
  "version": 1,
  "name": "workspace-assistant",
  "default_decision": "deny",
  "rules": [
    { "id": "deny-escape", "tool": "fs.*", "decision": "deny",
      "reason": "path escapes the workspace",
      "when": [{ "arg": "path", "prefix": ["..", "/", "C:\\", "~"] }] },
    { "id": "read-workspace", "tool": "fs.read", "decision": "allow",
      "when": [{ "arg": "path", "prefix": ["..", "/"], "negate": true }] },
    { "id": "write-report", "tool": "fs.write", "decision": "approval",
      "when": [{ "arg": "path", "glob": ["reports/*", "reports/**"] }],
      "approval_ttl_ms": 45000 },
    { "id": "no-delete", "tool": "fs.delete", "decision": "deny" }
  ]
}
```

被无条件拒绝的工具不会出现在 `tools/list` 里。Agent 看不到的能力，不会被排进计划。

### 2. 血缘：值从哪里来

策略把某些工具结果标记为敏感（例如 `fs.read` 读取 `**/*.env`）。Airlock 会从结果文本中提取形似密钥的值，只保存它们的 SHA-256 指纹和 4 字符前缀，然后记住“这个值来自第几次调用”。

之后任何外发工具（`net.*`、`mail.*`）的参数中出现同一个值，调用会被拒绝，证据里写明来源调用编号。判定依据是**值本身**，不是 Agent 声称的标签。

这条路不试图理解自然语言，因此可解释、可复现；代价是它只覆盖“原样携带”这一种泄漏方式。边界写得很清楚：[docs/SEMANTICS.md](docs/SEMANTICS.md)。

### 3. 审批：一次，且只对这一次的参数

需要审批的调用不会立刻转发，而是挂起，并在本地审批台（`127.0.0.1` 随机端口）出现。批准后转发的仍是**原始请求**，但授权与 `(工具名, 参数)` 的规范化 SHA-256 绑定：

- 换一个参数，哈希变化，必须重新审批；
- 同一次批准被消费后立即失效，重放会得到 `unknown approval`；
- 超过 TTL 未处理，客户端收到 `-32002`，上游永远不会看到这次调用。

## 账本与校验

每个事件写入一行 JSONL，并包含 `prev` 和 `hash`：

```
hash_n = SHA-256(prev_hash + "\n" + canonical(event_without_hash))
```

`canonical` 递归排序对象键，所以同样的语义总产生同样的字节。`airlock verify` 从第一条开始重算，任何一行被改动都会定位到具体序号。账本只记录工具名、参数键名、参数摘要和值指纹，不记录参数值本身。

## 工程结构

```
*.mbt                  MoonBit 引擎（协议、策略、血缘、账本、报告）
api/                   JS 导出层（JSON 进，JSON 出）
src/gateway.mjs        进程与管道（不含任何判定逻辑）
src/approval.mjs       本地审批台
src/report.mjs         HTML 报告渲染
bin/airlock.mjs        CLI
demo/                  真实 MCP 服务端、客户端、接收器、演示脚本
interop/               第三方客户端 + 第三方服务端互操作
test/                  进程级集成测试
```

判定逻辑全部在 MoonBit 中。把 `src/` 全部删掉，引擎依然能对每条消息给出正确判定，只是没有人替它搬运字节。

## 工程证据

```sh
moon check --deny-warn
moon test --deny-warn          # 26 个单元测试
node --test test/*.test.mjs    # 6 个真实进程集成测试
```

CI 在 Linux / macOS / Windows 上分别运行 MoonBit 检查、单元测试、构建和集成测试。

## 边界

Airlock 不是操作系统沙箱，不做语义级 DLP，也不阻止不经过它的调用。它假设上游服务端本身可能有漏洞，因此不信任服务端返回的内容；它也不信任 Agent 的自我声明，只看实际协议消息。完整威胁模型与非目标见 [docs/SEMANTICS.md](docs/SEMANTICS.md)。

## 许可与来源

MIT。MoonBit 核心库以 Apache-2.0 分发，其许可证与 NOTICE 随 `dist/` 一同保留，详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。项目为独立新项目，无既有项目代码复用、无第三方项目移植；AI 辅助范围与本人责任说明见 [docs/PROVENANCE.md](docs/PROVENANCE.md)。
