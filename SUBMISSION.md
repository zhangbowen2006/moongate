# MoonGate（月门）：MCP 工具的双点执行边界

> **填写说明（提交前删除本段）**
> 1. 每个小节都要由本人用自己的话写，不能保留括号里的提示。
> 2. 全文不超过一页（约 1500 字），只提交 Markdown，不要上传 PDF/Word。
> 3. 写完后运行 `npm run check:submission -- SUBMISSION.md`，全绿再提交。
> 4. “与现有项目的关系”是必填项，不能只写“无重叠”。

## 项目简介

（待填写：3–4 句，Agent 通过 MCP 调用本机工具时，密钥可能被下一步发出去；现有网关被绕过就失效；MoonGate 把判定放在执行之前，同一份策略同时跑在网关和服务端，并把敏感值替换成占位符，只在策略允许的目的地换回真值。）

## 方向与通用性

（待填写：说明它面向任何 MCP 客户端与服务端，不绑定某个业务；一个网关可带多个服务端；核心以 MoonBit 库发布到 Mooncakes，可被其他 MoonBit 项目直接调用。）

## 使用场景

### 场景一：本地资料整理

（待填写：谁在用、Agent 想做什么、哪一步被拦下或替换、没有网关会怎样。）

### 场景二：多工具协作

（待填写：文件服务端读到凭据，网络服务端尝试外发；跨进程血缘如何生效。）

### 场景三：高风险写操作

（待填写：写文件/删除需要人工批准；一次批准只对这一次参数有效。）

## 核心功能

- 双点执行：网关转发前判定，服务端工具函数入口再判一次。
- 密钥替身：结果中的敏感值变成 `«mg:…»`，按 `reveal` 规则在授权目的地换回真值。
- 跨服务端：合并工具清单、按归属路由，血缘跨进程。
- 配额与审批：调用数、参数字节、替换次数；一次性审批绑定参数摘要。
- 账本：哈希链，可离线校验；报告从账本生成。

## 与现有项目的关系（必填）

（待填写：至少点名 3 个同类项目并说明差异，不能写“没有类似项目”。可参考 docs/OVERLAP.md，但要用自己的话。）

- MoonPod（`yadidyc/moonpod`）：通用策略核心；MoonGate 提供其 JSON 策略子集的导入器，在 MCP 边界执行，无代码复用。
- MoonPolicy（`eisem/moon_policy`）：RBAC 授权引擎；MoonGate 不做 RBAC。
- MCP Shield / mcp-firewall：单代理网关；MoonGate 增加服务端第二执行点与密钥替身。

本仓库未复制、移植或依赖上述项目；完整对照与检索记录见 `docs/OVERLAP.md`。

## 原创与来源

（待填写：原创部分、参考来源、AI 辅助范围与本人责任。可参考 docs/PROVENANCE.md。）

## 仓库与安装

- GitHub：https://github.com/zhangbowen2006/moongate
- Mooncakes：`moon add zhangbowen2006/moongate@0.6.1`
- 运行演示：`node demo/run.mjs`
- 验证账本：`node bin/moongate.mjs verify --ledger runs/demo.jsonl`
