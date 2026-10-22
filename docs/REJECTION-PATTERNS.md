# 六封历史驳回信的共性，与 MoonGate 的对照

这 6 封来自 2026 年 8 月的初审，和十月赛的技术驳回不是一类问题。它们集中在**材料与归属**，不是代码能力。逐条拆开，能直接指导这次的提交。

| # | 被拒项目 | 驳回理由（摘要） | 问题类型 |
| --- | --- | --- | --- |
| 1 | CakeCheck | 社区已有非常多类似项目（用 check、audit 等关键字搜索） | 选题重叠，且未证明差异 |
| 2 | ReviewProof | 与近期维护的 constraint-lens 核心功能实质重叠，申报书未披露关系 | 关系未披露 |
| 3 | CapsuleTrace | 与已维护的 harborcheck@0.1.4、reviewproof-kit@0.3.1 功能重叠，未说明扩展关系 | 关系未说明 |
| 4 | RoboPolicy | 核心选题与近一个月可用的 Mooncakes `robots` 项目重叠，未说明扩展关系 | 关系未说明 |
| 5 | moonbit-submit-guard | 仓库中有另一位同学的提交记录，要求说明原因 | 作者归属不清 |
| 6 | bech32-kit | 申报书格式不支持 | 材料格式错误 |

## MoonGate 的自查与整改

### 1–4：重叠与关系披露

**我们有没有类似情况？有。** Mooncakes 上存在 `yadidyc/moonpod`（策略核心，含预算/审批/审计）、`eisem/moon_policy`（RBAC）、`123123213weqw/moon_scrub`（离线脱敏）、`colmugx/mcp`（MCP SDK）等模块；GitHub 上还有 MCP Shield、MCPKernel、mcp-firewall、taintMCP、AgentPerms、Authsome/OneCLI。

**已做的整改：**

- 新增 [`OVERLAP.md`](OVERLAP.md)：逐个模块列出功能、重合点、差异、代码关系；
- 新增 [`registry-scan.json`](registry-scan.json)：2026-10-22 的 `moon search` 原始结果（80 个模块），可复现；
- README 顶部增加“与现有方案的关系”，明确 **不是第一个策略网关、不声称首创、无代码复用**；
- 申报书模板新增**强制章节**“与现有项目的关系”，要求至少列出 3 个同类项目并说明差异；
- 格式校验脚本会检查这一节是否存在、是否点名了至少 2 个同类项目。

**不能回避的事实：** 如果评审的标准是“不能有任何相似项目”，MoonGate 不满足；我们的做法是披露并论证差异，而不是声称没有。

### 5：仓库作者归属

**我们有没有类似情况？没有。** 本仓库 36 个提交的作者与提交者全部是 `zhangbowen2006 <310127449+zhangbowen2006@users.noreply.github.com>`，没有 `Co-authored-by` 或其他账号的提交。

**已做的整改：**

- 新增 [`AUTHORSHIP.md`](AUTHORSHIP.md)，记录审计命令、输出摘要与独立开发声明；
- 本地 git 配置固定为 `zhangbowen2006`，避免后续误用其他账号；
- 提交前检查命令写进 [`SUBMISSION-CHECKLIST.md`](SUBMISSION-CHECKLIST.md)。

### 6：申报书格式

**我们有没有类似情况？风险存在。** 十月表单要求一页以内 Markdown；上传 PDF/Word、超长、缺章节都可能被判“格式不支持”。

**已做的整改：**

- 新增 [`SUBMISSION.md`](../SUBMISSION.md)：一页 Markdown 骨架，章节固定；
- 新增 `scripts/check-submission.mjs`：检查长度、章节、链接、占位符、同类项目披露、场景数量；
- 新增 [`SUBMISSION-CHECKLIST.md`](SUBMISSION-CHECKLIST.md)：提交前逐项打勾；
- CI 增加对该脚本的测试（`test/submission.test.mjs`）。

## 这次的提交顺序

1. 本人写 `SUBMISSION.md`（≤1 页，章节不能删）。
2. 运行 `npm run check:submission -- SUBMISSION.md`，全绿再提交。
3. 检查作者：`git log --format='%an <%ae>' | sort -u` 只应有一个账号。
4. 提交表单前确认：仓库 public、README 首屏有差异说明、Mooncakes 版本可安装。
5. 保留第 3 次提交机会，除非反馈明确指出可修复的问题。
