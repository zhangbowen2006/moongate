# 作者与提交归属

> 历史驳回信里有一封是因为“仓库中有另一位同学的提交记录”。这份文档把 MoonGate 的归属一次说清，并给出可复现的检查命令。

## 结论

- 仓库 `zhangbowen2006/moongate` 的 **36 个提交**，作者与提交者全部是 `zhangbowen2006 <310127449+zhangbowen2006@users.noreply.github.com>`。
- 没有 `Co-authored-by`、`Signed-off-by` 或其他账号的提交。
- Mooncakes 模块 `zhangbowen2006/moongate` 的发布者同为 `zhangbowen2006`。
- 本项目为独立开发，没有把其他同学的仓库、提交或账号并入。

## 审计记录（2026-10-22）

```text
commits=36
first=2026-10-22
last=2026-10-22

authors:
zhangbowen2006 <310127449+zhangbowen2006@users.noreply.github.com>

committers:
zhangbowen2006 <310127449+zhangbowen2006@users.noreply.github.com>

coauthor_trailers=0

local_config:
zhangbowen2006
310127449+zhangbowen2006@users.noreply.github.com
```

## 复现命令

```sh
git rev-list --count HEAD
git log --format='%an <%ae>' | sort -u
git log --format='%cn <%ce>' | sort -u
git log --format='%B' | grep -ci 'co-authored-by'
git config --local user.name
git config --local user.email
```

预期：作者/提交者各只有一行 `zhangbowen2006`，`co-authored-by` 计数为 0。

## 需要主动说明的两点

1. **所有提交发生在同一天。** 本项目是在 2026-10-22 的一次集中开发中完成的，提交按模块拆分，但没有跨越数周的历史。这与“连续提交”的字面要求不完全一致，如实说明，不伪造日期。
2. **AI 参与了实现。** 范围、验证方式与本人责任写在 [`PROVENANCE.md`](PROVENANCE.md)。AI 辅助不等于把其他项目的代码搬进来：本仓库没有移植任何第三方实现，依赖只有 MoonBit 核心库与 Node 内置模块。

## 如果未来有协作者

任何新的提交者出现前，需要：

- 在 `PROVENANCE.md` 增加协作者与分工；
- 在 `AUTHORSHIP.md` 更新审计输出；
- 在申报书中说明团队关系（赛事每队不超过 3 人）。

未披露的第三方提交会被初审直接质疑，这正是历史驳回信 #5 的教训。
