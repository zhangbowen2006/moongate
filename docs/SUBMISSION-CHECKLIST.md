# 提交前检查清单

按顺序做，任何一项不过就不要提交。这张清单直接来自 6 封历史驳回信。

## 1. 申报书

- [ ] 文件是 **Markdown**，不是 PDF/Word/图片。
- [ ] 正文 ≤ 1 页（校验器上限 1800 字，建议 ≤ 1500）。
- [ ] 七个章节齐全：项目简介、方向与通用性、使用场景、核心功能、与现有项目的关系、原创与来源、仓库与安装。
- [ ] 使用场景 **至少 3 个**，每个写清“谁在用、做了什么、哪一步被拦下”。
- [ ] “与现有项目的关系”点名 **至少 2 个** 同类项目，并写明“无代码复用/独立实现”；不能写“没有类似项目”。
- [ ] 删除了 `SUBMISSION.md` 顶部的“填写说明”引用块。
- [ ] 没有“待填写/TODO/请本人填写”等占位。
- [ ] 由本人撰写，不是 AI 直接生成。

```sh
npm run check:submission -- SUBMISSION.md
# 必须输出 OK，退出码 0
```

## 2. 作者归属

```sh
git log --format='%an <%ae>' | sort -u
git log --format='%cn <%ce>' | sort -u
git log --format='%B' | grep -ci 'co-authored-by'
```

- [ ] 作者与提交者各只有 `zhangbowen2006` 一个账号。
- [ ] `co-authored-by` 计数为 0。
- [ ] 仓库没有其他同学的历史提交。若有，必须在申报书说明原因。

## 3. 仓库与差异披露

- [ ] 仓库 public，README 首屏能看到“双点执行 / 密钥替身 / 与现有方案的关系”。
- [ ] `docs/OVERLAP.md` 存在，点名 MoonPod、MoonPolicy、MCP Shield 等，并声明无代码复用。
- [ ] `docs/registry-scan.json` 是最近一次 `moon search` 的结果。
- [ ] 没有把别人的仓库、提交或代码并进来。

## 4. 可运行与可安装

```sh
node demo/run.mjs
moon test --deny-warn
node --test test/*.test.mjs
```

- [ ] 演示 10 个场景全部通过。
- [ ] Mooncakes 版本可安装：

```sh
mkdir -p /tmp/mg-check && cd /tmp/mg-check
# 建一个空 moon.mod 后：
moon add zhangbowen2006/moongate@0.7.0
```

- [ ] 账本校验通过：`node bin/moongate.mjs verify --ledger runs/demo.jsonl`。

## 5. 表单与赛后

- [ ] 表单里仓库地址、Mooncakes 模块名、GitHub ID 三处一致。
- [ ] 加入赛事交流群，群昵称改为 GitHub ID。
- [ ] 保存提交回执。
- [ ] 记住：十月最多 3 次提交，这次是第 2 次；不要为凑次数提交半成品。

## 六封驳回信 → 本清单

| 驳回原因 | 对应检查 |
| --- | --- |
| 社区已有大量类似项目 | 第 3 节 + `docs/OVERLAP.md` |
| 与某项目实质重叠、未披露 | 第 1 节“与现有项目的关系” |
| 与已维护包重叠、未说明扩展 | 第 1 节 + 第 3 节 |
| 与 Mooncakes 项目重叠 | 第 3 节 registry 扫描 |
| 仓库有另一位同学的提交 | 第 2 节作者审计 |
| 申报书格式不支持 | 第 1 节格式校验 |
