# 第三方组件声明

本项目自身以 MIT 许可证发布（见 `LICENSE`）。

## 随发布产物分发的组件

### MoonBit 核心库

- 用途：编译器运行时、`@json` 解析器、UTF-8 编解码、字符串与集合基础类型
- 许可证：Apache License 2.0
- 版权：International Digital Economy Academy (IDEA)
- 许可证全文：`third_party/MoonBit-core-LICENSE.txt`
- 声明文件：`third_party/MoonBit-core-NOTICE.txt`

`dist/engine.js` 由 MoonBit 源码编译而来，包含 MoonBit 核心库的运行时部分，因此 `dist/` 目录中同时保留上述许可证与 NOTICE。

## 仅在开发/测试时使用，不随产物分发

### MCP 官方包（`interop/`）

- `@modelcontextprotocol/sdk`（MIT）
- `@modelcontextprotocol/server-filesystem`（MIT）

仅用于验证网关与第三方实现的互操作性，通过 `npm install` 安装在 `interop/node_modules/`，不进入 `dist/`，也不被 `bin/` 或 `src/` 引用。

### Node.js

运行时依赖，不随仓库分发。

## 未使用的代码

本项目没有移植或复制其他开源项目的实现。SHA-256 依据 FIPS 180-4 独立实现；glob 匹配、JSON 规范化序列化、JSON-RPC 状态机均为本项目原创。
