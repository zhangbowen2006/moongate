# 对 2026-10-23 驳回意见的逐条回应

上一轮驳回意见（原文）：

> 本项目的通用性与独立生态价值仍显不足。核心双点防护依赖服务端主动集成，难以直接适用于现有 MCP 生态；敏感信息追踪仅支持精确值匹配，存在明显的绕过局限，且传输仅覆盖 stdio。其余策略、审批与审计能力已有成熟方案。综合来看，尚未形成足够通用、可靠且具有独立生态价值的安全基础设施，本次申报不予通过。

这一版没有再解释“双点为什么重要”，而是把它从“需要服务端配合”改成了“不需要服务端配合”。四条意见逐条对应如下。

## 1. 依赖服务端主动集成 → 现在是零改造

**上一版**：服务端要 `import` MoonGate 的 guard 再调用，等于要求第三方改代码。现实中没人会为你的工具改代码，所以第二执行点在生态里不成立。

**这一版**：`moongate serve` 用 Node 的 `--import` 在服务端模块之前装 loader，拦截官方 SDK 的 `tools/call` 注册。**服务端源码一行不改，客户端配置不动。**

证据：

```sh
cd interop && npm install --no-audit --no-fund
node guard-check.mjs /tmp/mgfs
```

输出：

```
[moongate] zero-touch guard active: 8 rule(s)
list_directory -> allowed: true
write_file -> blocked: Blocked by MoonGate policy (no-write)
side effect present: false
RESULT: guard works
```

关键代码：`src/guard-loader.mjs`、`bin/moongate.mjs` 的 `serve` 子命令。

## 2. 精确值匹配可绕过 → 现在是归一化匹配

**上一版**：只比对完全相同的字符串，Base64 一下、拆成两段、改个大小写就能绕过。

**这一版**：拆分隔符、转小写、Base64、URL-safe Base64 都会归一化后比对；同一个敏感值的不同变形只报一次，不会重复计数。

证据：`variant_wbtest.mbt`（5 个用例，含负例）；`moon test --deny-warn` 47 项。

边界：任意加密、压缩或语义改写仍可能绕过，写在 `SEMANTICS.md`。

## 3. 仅覆盖 stdio → 现在是 stdio 加 Streamable HTTP

**上一版**：只有 stdio。

**这一版**：`moongate run --http <port>` 在 `/mcp` 提供 POST（单条 JSON-RPC）与 GET（SSE 流），复用同一套引擎判定。

证据：`test/http.test.mjs`（2 个用例）；实测 `tools/list` 裁剪掉 `fs.delete`、`fs.delete` 调用被拒。

边界：实现了 Streamable HTTP 的 POST/GET，未覆盖旧版 HTTP+SSE。

## 4. 其余能力已有成熟方案 → 差异是部署模型，不是功能列表

**上一版**：差异说成“双点执行”，但双点依赖服务端配合，等于没有差异。

**这一版**：差异是**零改造**——服务端、客户端、协议都不需要改动，判定就落在服务端的执行路径里。这是部署方式的差异，不是功能清单的差异。

同类项目（MoonPod、MoonPolicy、MCP Shield、mcp-firewall）已逐项对照，见 `OVERLAP.md`；本仓库未复制、移植或依赖它们。

## 现在的能力边界（主动说明，不等追问）

- 零改造注入目前覆盖 Node 实现的 MCP 服务端；Python 等其他语言需要各自的注入方式。
- 血缘是精确值加常见编码的归一化匹配；任意加密或压缩仍可绕过。
- 传输实现了 Streamable HTTP 的 POST/GET，未覆盖旧版 HTTP+SSE。
- 不是沙箱，不限制上游服务端本身的系统权限。
- 审批台没有身份认证，只适合单机单用户。
