# MoonGate（月门）：现有 MCP 服务端的零改造执行边界

## 项目简介

当 Agent 通过 MCP 协议调用本机工具时，一次普通的「读文件—外发」就可能把密钥或敏感数据带出去，而现有的安全网关一旦被绕过就完全失效。MoonGate 是用 MoonBit 编写的 MCP 工具调用执行边界：用 `moongate serve` 启动现有服务端，同一份策略就在服务端进程内、工具函数执行前生效，服务端源码一行不改；敏感值在进入模型上下文前被替换成占位符，每次判定写入可离线校验的哈希链账本。

## 方向与通用性

面向任何 MCP 客户端与任何 MCP 服务端，不绑定具体业务；一个网关可同时管理多个服务端，跨进程追踪血缘。判定核心以 MoonBit 库发布到 Mooncakes，其他 MoonBit 项目可直接依赖；网关同时支持 stdio 与 Streamable HTTP 两种传输。

## 使用场景

### 场景一：直接保护现成服务端

把官方 filesystem 服务端交给 `moongate serve` 启动，写文件、移动文件按策略拒绝，服务端源码与客户端配置都不变。Agent 想删除文件时，调用在服务端内部被拦下，目标文件不会创建。

### 场景二：多工具协作

Agent 先从文件服务端读到含密钥的配置，再让网络服务端外发。两个服务端是独立进程，网关把密钥记下指纹，跨进程识别出外发意图并在发送前拦截；密钥即使被拆开、改大小写或 Base64 编码，仍会被识别。

### 场景三：高风险写操作

写文件、删除等操作需要人工批准。审批台展示调用内容与参数，操作者批准后才转发；一次批准只对这次调用、这套参数有效，换内容需要重新批准。

## 核心功能

- 零改造服务端内执行：Node loader 在服务端进程内拦截 `tools/call`，服务端不需要引入任何依赖。
- 密钥替身：敏感值变成占位符，按 `reveal` 规则在授权目的地换回真值，模型始终看不到明文。
- 变形外泄检测：拆分、改大小写、Base64、URL-safe 编码都会归一化匹配。
- 策略与配额：有序规则、参数 glob/前缀/路径规范化、默认拒绝、调用数与字节预算、一次性审批、哈希链账本。
- 双传输：stdio 与 Streamable HTTP（POST 加 SSE），同一套引擎。

## 与现有项目的关系

MCP 安全网关已是拥挤赛道，本项目不声称发明这些机制。已对照 Mooncakes 与 GitHub 同类项目（检索记录见 `docs/OVERLAP.md`）：

- MoonPod（`yadidyc/moonpod`）：传输无关的策略核心，含预算、审批、审计。MoonGate 是其 MCP 运行时层，并提供其 JSON 策略子集的导入器，无代码复用。
- MoonPolicy（`eisem/moon_policy`）：RBAC 授权引擎。MoonGate 不做 RBAC，规则只服务于 MCP 工具调用。
- MCP Shield 与 mcp-firewall：单代理网关。MoonGate 不需要把客户端指向代理，判定直接落在服务端进程内。

本仓库未复制、移植或依赖上述任何项目。

## 原创与来源

本项目于 2026 年 10 月从零新建，以 MIT 许可开源，与此前提交的 AgentCanary 无代码复用；判定核心全部用 MoonBit 实现，依赖仅 MoonBit 核心库（Apache-2.0）与 Node 内置模块。开发中借助 AI 起草代码初稿与测试，最终实现均经本人逐行审阅、编译，并通过 47 个单元测试与 21 个 Node 集成测试验证；选题方向、威胁模型边界与对外表述由本人独立确定。

## 仓库与安装

- GitHub（连续提交、开发记录可追踪）：https://github.com/zhangbowen2006/moongate
- Mooncakes：`moon add zhangbowen2006/moongate@0.7.1`
- 运行演示：`node demo/run.mjs`
- 验证账本：`node bin/moongate.mjs verify --ledger runs/demo.jsonl`
