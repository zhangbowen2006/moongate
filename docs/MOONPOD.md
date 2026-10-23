# 复用 MoonPod 策略（兼容层）

MoonPod（`yadidyc/moonpod@0.2.0`）是 MoonBit 里的**通用策略核心**：它把一次操作描述成 Operation，返回 Allow/Deny/Approval，并记录审计事件。MoonGate 是 **MCP 工具调用的执行边界**，两者不在同一层。

为了避免“同类项目各写一套策略”，MoonGate 提供一个**兼容层**：把 MoonPod 的 JSON 策略转换成 MoonGate 策略，在 MCP 边界执行。

```sh
node bin/moongate.mjs import-policy \
  --format moonpod \
  --in examples/policy.moonpod.json \
  --out runs/imported.json
```

这是一个**适配器**，不是 fork、不是依赖：MoonGate 不引用 MoonPod 的代码，输出是普通的 MoonGate 策略，仍由 MoonGate 的解析器校验。

## 映射关系

| MoonPod 字段 | MoonGate 输出 | 说明 |
| --- | --- | --- |
| `allowed_tools` | `allow` 规则 | `fs.read` / `fs.write` / `net.*` 特殊处理，其余工具原样允许 |
| `read_roots` | `fs.read` 的 `path` 前缀允许 | 路径做词法规范化；为空表示不限制 |
| `write_roots` | `fs.write` 的 `path` 前缀允许 | 同上 |
| `protected_paths` | 所有工具的 `path` 前缀拒绝 | 排在 allow 之前，模拟 MoonPod 的 protected 语义 |
| `network_rules` | `net.*` 的 `url` glob 允许 | `*://host:port/*`；80/443 额外生成 `*://host/*` |
| `approval_required_tools` | `approval` 规则 | 排在 allow 之前 |
| `max_calls` | `budget.max_calls` | `0` 会生成一条“拒绝所有调用”的规则，不会变成“无限” |
| `max_operation_bytes` | `budget.max_single_bytes` | 单次参数 UTF-8 字节上限 |

## 明确不支持（失败关闭）

这些字段存在时会直接报错，不会静默忽略：

- `command_rules`：MoonPod 的命令参数前缀语义无法可靠映射到 MCP 工具参数。
- `resource_rules`：MoonGate 没有 `resource` 抽象。
- `tool_quotas`：MoonGate 目前只有会话级配额，没有按工具配额。
- `max_io_bytes`：MoonGate 不统计实际 I/O 字节。
- `allowed_tools` 包含 `process.run`：命令执行需要 `command_rules`，不支持。

## 语义差异（必须知道）

1. **路径**：MoonGate 做词法规范化（`.`/`..`），不解析符号链接；MoonPod 的路径语义以它自己的实现为准。
2. **网络**：MoonGate 用 URL glob 近似 host/port，不做 DNS 解析、IP 检查、重定向检查；`network_rules` 之外的主机不会被允许。
3. **操作字节**：MoonGate 用参数 JSON 的 UTF-8 字节数近似 `byte_cost`，不是 MoonPod 的精确估算。
4. **额外的 MCP 层**：导入后的策略还会经过 MoonGate 的工具清单裁剪、跨调用/跨服务端血缘、密钥替身、哈希链账本；这些 MoonPod 本身不提供。
5. **审批**：MoonGate 的审批绑定工具名 + 参数摘要，单次消费；MoonPod 的审批语义以它自己的会话为准。

## 什么时候用

- 已经在 MoonPod 里维护了策略，想直接用到 MCP 边界；
- 想用 MoonPod 的通用策略语言，同时获得 MoonGate 的替身/血缘/服务端内执行；
- 需要把 MoonPod 的策略作为基线，再在 MoonGate 里加 `reveal`、`sensitive` 等 MCP 专属规则。

如果只需要通用策略判定，直接用 MoonPod 即可；MoonGate 不试图替代它。

## 来源说明

适配器依据 MoonPod 公开的 JSON schema（`schema_version: 1`）实现，没有复制其源码；MoonPod 以 Apache-2.0 发布。示例见 `examples/policy.moonpod.json`，测试见 `pod_adapter_wbtest.mbt`。
