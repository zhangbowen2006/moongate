import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { checkSubmission } from '../scripts/check-submission.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CLI = join(ROOT, 'scripts/check-submission.mjs');

const valid = `# MoonGate（月门）

## 项目简介

MoonGate 是 MCP 工具调用的执行边界。它在网关转发前判定，同一份策略也嵌在服务端，并让敏感值以占位符形式进入模型上下文。

## 方向与通用性

任何 MCP 客户端与服务端都可接入；一个网关可带多个服务端；核心发布为 Mooncakes 库。

## 使用场景

### 场景一：本地资料整理

Agent 读取配置后试图外发，网关拒绝，接收端计数为 0。

### 场景二：多工具协作

文件服务端读到凭据，网络服务端尝试发送，跨进程血缘生效。

### 场景三：高风险写操作

写文件进入审批；批准只对这一次参数有效。

## 核心功能

双点执行、密钥替身、跨服务端路由、会话配额、一次性审批、哈希链账本。

## 与现有项目的关系

- MoonPod（yadidyc/moonpod）是通用策略核心，MoonGate 是 MCP 运行时。
- MoonPolicy（eisem/moon_policy）是 RBAC 引擎，MoonGate 不做 RBAC。
- MCP Shield 是单代理网关，MoonGate 增加服务端第二执行点。

本仓库无代码复用，独立实现；详见 docs/OVERLAP.md。

## 原创与来源

协议状态机、双点执行、替身与血缘、账本均为原创；参考 MCP 规范与 SHA-256 标准。

## 仓库与安装

- GitHub：https://github.com/zhangbowen2006/moongate
- Mooncakes：moon add zhangbowen2006/moongate@0.5.0
`;

test('a complete one-page submission passes', () => {
  const result = checkSubmission(valid);
  assert.equal(result.ok, true, JSON.stringify(result.errors));
  assert.ok(result.comparables.length >= 2);
});

test('missing overlap disclosure fails', () => {
  const text = valid.replace(/## 与现有项目的关系[\s\S]*?## 原创与来源/, '## 原创与来源');
  const result = checkSubmission(text);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((error) => error.includes('与现有项目的关系')));
});

test('naming only one comparable project fails', () => {
  const text = valid
    .replace(/- MoonPolicy[\s\S]*?\n/, '')
    .replace(/- MCP Shield[\s\S]*?\n/, '');
  const result = checkSubmission(text);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((error) => error.includes('至少 2 个')));
});

test('placeholders fail', () => {
  const result = checkSubmission(valid.replace('MoonGate 是 MCP', '待填写：MoonGate 是 MCP'));
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((error) => error.includes('占位')));
});

test('fewer than three scenarios fails', () => {
  const text = valid.replace(/### 场景三[\s\S]*?\n\n/, '');
  const result = checkSubmission(text);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((error) => error.includes('至少 3 个')));
});

test('the CLI returns 0 for a complete file and 1 for a template', () => {
  const dir = mkdtempSync(join(tmpdir(), 'moongate-submission-'));
  const good = join(dir, 'good.md');
  const bad = join(dir, 'bad.md');
  writeFileSync(good, valid, 'utf8');
  writeFileSync(bad, valid.replace(/## 与现有项目的关系[\s\S]*?## 原创与来源/, '## 原创与来源'), 'utf8');
  const ok = spawnSync(process.execPath, [CLI, good], { encoding: 'utf8' });
  assert.equal(ok.status, 0, ok.stdout + ok.stderr);
  const fail = spawnSync(process.execPath, [CLI, bad], { encoding: 'utf8' });
  assert.equal(fail.status, 1);
  assert.match(fail.stdout, /FAILED/);
});
