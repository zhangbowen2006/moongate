# 三分钟演示脚本

目标：三件事——拒绝发生在执行之前；模型看不到明文密钥；绕过网关，服务端自己也会拒绝。

## 准备

```sh
cd moongate
node --version          # 需要 22+
node demo/run.mjs       # 先跑一遍，确认环境
```

演示会生成 `runs/demo.report.html`，提前在浏览器里打开备用。

## 录制顺序

### 0:00–0:20 问题

> 让 Agent 操作本机文件很方便，但它会把读到的密钥发到哪里，没人知道；而且只要代理被绕过，网关就失效了。
> MoonGate 做两件事：判定放在执行之前；同一份策略，服务端自己也有一份。

### 0:20–0:45 启动

```sh
node demo/run.mjs
```

指出三行：

```
策略 workspace-assistant · 指纹 …
审批台 http://127.0.0.1:…/
账本 ...\runs\demo.jsonl
```

> 三个真实进程：客户端、网关、MCP 服务端。服务端启动时打印 `guard active`，说明它自己也加载了同一份策略。

### 0:45–1:35 密钥替身

第 4 步：

```
[4/10] 读取凭据：模型只看到替身
  ✓ 模型看到 «mg:8b201fda70f4dd1b»，明文没有进入上下文
```

> Agent 读了 `.env`，但模型上下文里只有占位符。明文留在网关内存，账本只记指纹。

第 5 步：

```
[5/10] 把替身发往未授权地址
  ✓ 被拒绝：Blocked by MoonGate policy (secret-reveal)…
```

> 占位符发到外部地址，网关拒绝替换，请求根本没有转发。

第 6 步：

```
[6/10] 把替身发往已授权地址
  ✓ 上游执行成功：posted 33 bytes -> 200
  ✓ 未授权地址 0 次，授权地址 1 次
  ✓ 授权地址收到真实值：替身只在允许的目的地被替换
```

> 同一个占位符，发到策略授权的内部地址，网关在转发前换回真值，任务完成了，模型始终没看到密钥。

### 1:35–2:10 审批

第 8 步停在审批，切到浏览器：

```
fs.write  reports/summary.md
{ "path": "reports/summary.md", "content": "# 周报…" }
[批准一次] [拒绝]
```

点“批准一次”，终端：

```
✓ 批准一次 -> wrote 32 bytes to reports/summary.md
✓ 报告文件确实写入磁盘
✓ 批准已被消费，没有留下可复用的授权
```

第 9 步点“拒绝”：

```
✓ 参数哈希已变化：5a05d2ef5e216175…
✓ 人工拒绝：MoonGate: operator denied fs.write
✓ 文件保持批准时的版本，被拒绝的写入没有落地
```

> 批准绑定这一次的工具名和参数哈希；换内容、重放、超时都会失效。

### 2:10–2:40 绕过网关

第 10 步会**直连服务端**，不经过网关：

```
[10/10] 绕过网关，直连服务端
  ✓ 服务端自己拒绝：Blocked by MoonGate guard (no-delete)…
  ✓ 路径穿越在服务端被拒绝：Blocked by MoonGate guard (deny-escape)…
  ✓ 第二次证明：不经过网关，文件仍在
```

> 现有网关方案都是一个代理进程，代理被绕过就结束；这里服务端嵌了同一个 MoonBit 判定函数，工具函数执行前再判一次。
> 注意 `reports/../../etc/passwd`：只做字符串前缀匹配时它以 `reports/` 开头会被放过；路径规范化之后才命中 `deny-escape`。

### 2:40–3:00 账本

```sh
node bin/moongate.mjs verify --ledger runs/demo.jsonl
# chain intact: 20 entries, head ...
```

改一个字节再校验：

```sh
node -e "const f='runs/demo.jsonl';const fs=require('fs');const l=fs.readFileSync(f,'utf8').split('\n');l[3]=l[3].replace('\"allow\"','\"deny\"');fs.writeFileSync('runs/tampered.jsonl',l.join('\n'))"
node bin/moongate.mjs verify --ledger runs/tampered.jsonl
# chain broken: entry 3 hash mismatch (after 3 entries)
```

> 账本每行都带着前一条的哈希，改任何一行都会断链并指出位置。

## 如果时间充裕

**第三方互操作**（30 秒）：

```sh
cd interop && npm install && node client.mjs
```

> 客户端是官方 SDK，服务端是官方文件服务端。网关对两端透明。

**真实模型**（需要 Key）：

```sh
MOONGATE_LLM_API_KEY=sk-... node demo/agent-llm.mjs
```

## 常见提问

**Q：Agent 不走网关怎么办？**
A：服务端嵌了 guard 就仍然会被拒绝——第 10 步就是这个场景。两端都没有时拦不住，这是部署约束，写在 `docs/SEMANTICS.md`。

**Q：和凭据代理（Authsome、OneCLI）有什么区别？**
A：它们在 HTTP 出口替换 header；MoonGate 在 MCP 的工具参数与结果边界替换，占位符可以跨工具流转，替换目标由策略逐条授权，并且和工具规则分开。

**Q：和现成的 MCP 网关有什么区别？**
A：功能重合很多，不否认。差异是执行点数量（网关 + 服务端）和密钥替身。

**Q：把密钥拆成两段发出去呢？**
A：拦不住。血缘与替身都是精确值匹配，不是语义 DLP。

**Q：为什么不直接做沙箱？**
A：沙箱限制进程能力，网关限制调用语义；两者可以叠加。
