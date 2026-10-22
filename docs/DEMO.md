# 三分钟演示脚本

目标：让评审在三分钟内看到“拒绝发生在执行之前”，并且能自己复现。

## 准备

```sh
cd airlock
node --version          # 需要 22+
node demo/run.mjs       # 先跑一遍，确认环境
```

演示会生成 `runs/demo.report.html`，提前在浏览器里打开备用。

## 录制顺序

### 0:00–0:20 问题

> 让 Agent 操作本机文件很方便，但它会把读到的密钥发到哪里，没人知道。
> 常见的做法是看日志、做事后审计——那时候东西已经出去了。
> Airlock 把检查放在转发之前：被拒绝的调用，上游服务端根本收不到。

### 0:20–0:50 启动

```sh
node demo/run.mjs
```

指出输出里的三行：

```
策略 workspace-assistant · 指纹 6ac753b9c1a9…
审批台 http://127.0.0.1:59556/
账本 D:\...\runs\demo.jsonl
```

> 三个真实进程：客户端、网关、MCP 服务端。审批台是本地起的，只监听 127.0.0.1。

### 0:50–1:30 凭据外发被拦

演示自动执行到第 5 步，屏幕上出现：

```
✓ 被拒绝：Blocked by Airlock policy (egress-taint): arguments carry 1 value(s) seen in sensitive results
✓ 接收端计数仍为 0：上游服务从未收到这次请求
```

> Agent 先读了 `config/.env`，然后试图把密钥 POST 出去。注意它用的工具是允许的 `net.post`，参数看起来也正常——拦下它的是值的来源，不是工具名。
> 接收端计数是 0，说明请求没有发出去，不是发出去之后被记了一笔。

### 1:30–2:10 审批

第 7 步会停在审批，切到浏览器：

```
fs.write  reports/summary.md
{ "path": "reports/summary.md", "content": "# 周报…" }
[批准一次] [拒绝]
```

点“批准一次”，终端继续：

```
✓ 批准一次 -> wrote 32 bytes to reports/summary.md
✓ 报告文件确实写入磁盘
✓ 批准已被消费，没有留下可复用的授权
```

> 批准绑定的是这一次的工具名和参数哈希。下一段会换一份内容再写，必须重新审批。

第 8 步点“拒绝”，终端：

```
✓ 参数哈希已变化：5a05d2ef5e216175…
✓ 人工拒绝：Airlock: operator denied fs.write
✓ 文件保持批准时的版本，被拒绝的写入没有落地
```

### 2:10–2:40 账本

```sh
node bin/airlock.mjs verify --ledger runs/demo.jsonl
# chain intact: 18 entries, head a4e2b712d236eda4…
```

改一个字节再校验：

```sh
node -e "const f='runs/demo.jsonl';const fs=require('fs');const l=fs.readFileSync(f,'utf8').split('\n');l[3]=l[3].replace('\"allow\"','\"deny\"');fs.writeFileSync('runs/tampered.jsonl',l.join('\n'))"
node bin/airlock.mjs verify --ledger runs/tampered.jsonl
# chain broken: entry 3 hash mismatch (after 3 entries)
```

> 账本每行都带着前一条的哈希。改任何一行都会断链，并指出位置。

### 2:40–3:00 收尾

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
AIRLOCK_LLM_API_KEY=sk-... node demo/agent-llm.mjs
```

> 模型自己决定调用哪个工具，网关决定这次调用能不能发生。

## 常见提问

**Q：Agent 不走网关怎么办？**
A：拦不住。这是部署约束，写在 `docs/SEMANTICS.md` 里。网关的价值在于把“所有工具调用都必须经过这里”变成一条可审计的规则。

**Q：把密钥拆成两段发出去呢？**
A：拦不住。血缘是精确值匹配，不是语义 DLP。它的目标是覆盖最常见、最直接的外泄路径，并且做到可解释、可复现。

**Q：为什么不用现成的 MCP 网关？**
A：常见网关做认证、路由、日志和工具白名单，判定多发生在调用之后或服务端内部。这个项目的差异是执行前阻断、值级血缘和绑定参数的一次性审批。
