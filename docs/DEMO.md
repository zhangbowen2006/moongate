# 三分钟演示脚本

目标：让评审在三分钟内看到两件事——拒绝发生在执行之前；绕过网关，服务端自己也会拒绝。

## 准备

```sh
cd moongate
node --version          # 需要 22+
node demo/run.mjs       # 先跑一遍，确认环境
```

演示会生成 `runs/demo.report.html`，提前在浏览器里打开备用。

## 录制顺序

### 0:00–0:20 问题

> 让 Agent 操作本机文件很方便，但它会把读到的密钥发到哪里，没人知道。
> 常见做法是看日志、做事后审计——那时候东西已经出去了。
> MoonGate 把检查放在转发之前；而且同一份策略，服务端自己也有一份。

### 0:20–0:45 启动

```sh
node demo/run.mjs
```

指出输出里的三行：

```
策略 workspace-assistant · 指纹 10ca11073f60…
审批台 http://127.0.0.1:62798/
账本 D:\...\runs\demo.jsonl
```

> 三个真实进程：客户端、网关、MCP 服务端。服务端启动时会打印 `guard active`，说明它自己也加载了同一份策略。

### 0:45–1:20 凭据外发被拦

演示自动执行到第 5 步：

```
✓ 被拒绝：Blocked by MoonGate policy (egress-taint): arguments carry 1 value(s) seen in sensitive results
✓ 接收端计数仍为 0：上游服务从未收到这次请求
```

> Agent 先读了 `config/.env`，然后试图把密钥 POST 出去。它用的工具是允许的 `net.post`，参数看起来也正常——拦下它的是值的来源，不是工具名。
> 接收端计数是 0，说明请求没有发出去，不是发出去之后被记了一笔。

### 1:20–1:55 审批

第 7 步停在审批，切到浏览器：

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

第 8 步点“拒绝”：

```
✓ 参数哈希已变化：5a05d2ef5e216175…
✓ 人工拒绝：MoonGate: operator denied fs.write
✓ 文件保持批准时的版本，被拒绝的写入没有落地
```

> 批准绑定这一次的工具名和参数哈希；换内容、重放、超时都会失效。

### 1:55–2:25 绕过网关

第 9 步会**直连服务端**，不经过网关：

```
[9/9] 绕过网关，直连服务端
  ✓ 服务端自己拒绝：Blocked by MoonGate guard (no-delete): deletion is never delegated to an agent
  ✓ 路径穿越在服务端被拒绝：Blocked by MoonGate guard (deny-escape): path escapes the workspace
  ✓ 第二次证明：不经过网关，文件仍在
```

> 这是这一版的重点。现有网关方案都是一个代理进程，代理被绕过就结束；这里服务端嵌了同一个 MoonBit 判定函数，工具函数执行前再判一次。
> 注意 `reports/../../etc/passwd`：如果只做字符串前缀匹配，它以 `reports/` 开头会被放过；路径规范化之后才命中 `deny-escape`。

### 2:25–2:50 账本

```sh
node bin/moongate.mjs verify --ledger runs/demo.jsonl
# chain intact: 18 entries, head ...
```

改一个字节再校验：

```sh
node -e "const f='runs/demo.jsonl';const fs=require('fs');const l=fs.readFileSync(f,'utf8').split('\n');l[3]=l[3].replace('\"allow\"','\"deny\"');fs.writeFileSync('runs/tampered.jsonl',l.join('\n'))"
node bin/moongate.mjs verify --ledger runs/tampered.jsonl
# chain broken: entry 3 hash mismatch (after 3 entries)
```

> 账本每行都带着前一条的哈希。改任何一行都会断链，并指出位置。

### 2:50–3:00 收尾

打开 `runs/demo.report.html`：

> 这是从账本生成的报告：放行、拒绝、审批、血缘标记，以及被拦下的调用和原因。报告本身可以离线复核。

## 如果时间充裕

**第三方互操作**（30 秒）：

```sh
cd interop && npm install && node client.mjs
```

> 客户端是官方 SDK，服务端是官方文件服务端。网关对两端透明，只做它该做的判定。

**真实模型**（需要 Key）：

```sh
MOONGATE_LLM_API_KEY=sk-... node demo/agent-llm.mjs
```

## 常见提问

**Q：Agent 不走网关怎么办？**
A：如果服务端嵌了 guard，它仍然会被拒绝——演示第 9 步就是这个场景。如果两端都没有，拦不住；这是部署约束，写在 `docs/SEMANTICS.md` 里。

**Q：和现成的 MCP 网关有什么区别？**
A：功能上重合很多，不否认。差异是执行点数量：它们是一个代理进程，MoonGate 是网关加服务端 guard，同一份策略。代理被绕过时，差别就出来了。

**Q：把密钥拆成两段发出去呢？**
A：拦不住。血缘是精确值匹配，不是语义 DLP。它的目标是覆盖最常见、最直接的外泄路径，并且做到可解释、可复现。

**Q：为什么不直接做沙箱？**
A：沙箱限制的是进程能力，网关限制的是调用语义；两者可以叠加。这个项目解决的是“工具调用该不该发生”，不是“工具进程能碰什么”。
