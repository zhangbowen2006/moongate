# 验收自查

对照 2026 MoonBit 黑客松十月赛的六条验收标准，逐条给出可执行的检查方式与对应文件。所有命令均在仓库根目录执行。

| # | 官方标准 | 本项目的满足方式 | 复核命令 |
| --- | --- | --- | --- |
| 01 | MoonBit 为主 | 协议状态机、策略、血缘、账本、报告全部由 MoonBit 实现；JS 只做进程与管道 | `moon test`，见下方代码分布 |
| 02 | 仓库公开 | GitHub 公开仓库，保留连续提交 | 仓库首页 / `git log` |
| 03 | 能够运行 | 预编译引擎 + Node 22，无外部服务；`demo/run.mjs` 一条命令跑完 | `node demo/run.mjs` |
| 04 | 工作有效 | 全新仓库、全新架构；本期从零实现 | `git log --reverse` |
| 05 | 开源合规 | MIT；MoonBit 核心库 Apache-2.0 许可与 NOTICE 随产物保留 | `LICENSE`、`THIRD_PARTY_NOTICES.md`、`dist/` |
| 06 | AI 可解释 | 设计取舍、威胁模型、AI 使用范围与责任边界均成文 | `docs/PROVENANCE.md`、`docs/ARCHITECTURE.md`、`docs/SEMANTICS.md` |

## 01 MoonBit 为主

判定逻辑没有任何一部分在 JavaScript 里。`src/gateway.mjs` 只负责 spawn 子进程、读写管道、执行引擎返回的动作；如果删掉 `src/`，引擎仍能对每条消息给出正确判定（测试就是直接驱动引擎的）。

代码分布（`cloc` 或编辑器统计，仅计源码）：

- MoonBit：`*.mbt`，协议、策略、血缘、账本、报告、测试
- JavaScript：`src/`、`bin/`、`demo/`，传输与演示
- HTML/CSS：仅报告模板与审批台

```sh
moon check --deny-warn
moon test --deny-warn      # 26 个单元测试
moon build api --target js --release --deny-warn
```

## 02 仓库公开

GitHub：<https://github.com/zhangbowen2006/airlock>

提交历史按“协议层 → 策略 → 血缘 → 账本 → 网关 → 演示 → 测试 → 文档”分段，便于逐段审阅；CI 在推送后运行完整检查。

## 03 能够运行

不装 MoonBit 也能运行，仓库带 `dist/engine.js`：

```sh
node demo/run.mjs
```

预期最后几行：

```
chain intact: 18 entries, head ...
report: .../runs/demo.report.html
演示完成。
```

演示内部断言（任一失败则退出码非 0）：

1. `tools/list` 不包含 `fs.delete`；
2. 读取 `config/.env` 后再外发，返回 `egress-taint`；
3. 本地 HTTP 接收端计数为 0；
4. 路径逃逸返回 `deny-escape`；
5. 写文件需审批，批准后文件存在；
6. 换内容再写需重新审批，拒绝后文件未变；
7. 删除被拒绝且文件仍在；
8. 账本哈希链完整。

从源码构建：

```sh
moon check --deny-warn
moon test --deny-warn
node scripts/build.mjs
```

## 04 工作有效

本项目不是 `AgentCanary` 的改名或拆包：上一版是“对已发生记录做离线评分”，本项目是“在真实调用链上做执行前拦截”。两者共享的只有“Agent 工具调用安全”这一个问题域，没有代码复用。

本期完成的实质工作：

- MCP stdio 协议解析与 JSON-RPC 状态机（含请求/响应关联、通知、服务端反向请求）
- 五类策略原语与首匹配求值、工具清单裁剪
- 值级数据血缘（提取、指纹、传播、外发匹配、证据生成）
- 一次性审批租约（参数规范化摘要、TTL、消费）
- 哈希链账本、离线校验、HTML 报告
- 真实进程网关、审批台、CLI
- 26 个单元测试 + 6 个进程级集成测试 + 第三方互操作验证

## 05 开源合规

- 项目自身：MIT（`LICENSE`）
- MoonBit 核心库：Apache-2.0，`third_party/MoonBit-core-LICENSE.txt` 与 `NOTICE`，并随 `dist/` 一起分发
- 无第三方项目代码移植；`interop/` 通过 npm 依赖官方包，仅在开发时安装，不进入发布产物
- 无密钥、无个人数据进入仓库；`runs/` 已被忽略

## 06 AI 可解释

- 为什么把判定放在协议层而不是模型层：`docs/ARCHITECTURE.md`
- 为什么用值级血缘而不是语义分类：`docs/SEMANTICS.md`
- 策略求值顺序与取舍：`docs/POLICY.md`
- AI 参与了哪些部分、本人如何校验、哪些结论不能由 AI 代替：`docs/PROVENANCE.md`

## 提交前清单（需要本人完成）

- [ ] 确认仓库为 public，README 可访问
- [ ] 在报名表中填写仓库地址与一页项目说明
- [ ] 加入赛事交流群，群昵称改为 GitHub ID
- [ ] 录一段 3 分钟演示（脚本见 `docs/DEMO.md`）
- [ ] 如使用真实模型录制，确认 API Key 未出现在录屏与环境变量截图中
