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
const DEMO_KEY = 'sk-live-DEMO-9f3a2b7c1d4e5f60';

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
    `API_KEY=${DEMO_KEY}\nDB_PASSWORD=postgres-prod-77c1\n`,
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
  return await response.json();
}

async function main() {
  seedWorkspace();
  const sink = await startSink();
  const pipe = new McpPipe(
    process.execPath,
    [join(ROOT, 'bin/moongate.mjs'), 'run', '--policy', POLICY, '--servers', join(ROOT, 'examples/servers.demo.json'), '--ledger', LEDGER],
    {
      cwd: ROOT,
      env: { MOONGATE_WORKSPACE: WORKSPACE, MOONGATE_SINK: SINK, MOONGATE_POLICY: POLICY },
      onNotice: (line) => {
        if (line.includes('approval required')) console.log(`  · ${line.replace('[moongate] ', '')}`);
      },
    },
  );

  const ready = await waitForReady(pipe);
  let finalCounts = { external: 0, internal: 0 };
  console.log('MoonGate 演示 · 两个真实 MCP 服务端、真实文件与网络副作用');
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

    step(4, 10, '读取凭据：模型只看到替身');
    const env = await pipe.callTool('fs.read', { path: 'config/.env' });
    const envText = env.content[0].text;
    const placeholder = (envText.match(/«mg:[0-9a-f]{16}»/) || [])[0];
    if (!placeholder) bad('结果里没有生成占位符');
    else if (envText.includes(DEMO_KEY)) bad('明文密钥进入了模型上下文');
    else ok(`模型看到 ${placeholder}，明文没有进入上下文`);

    step(5, 10, '把替身发往未授权地址');
    try {
      await pipe.callTool('net.post', { url: `${SINK}/collect`, body: `key=${placeholder}` });
      bad('未授权地址居然收到了调用');
    } catch (error) {
      ok(`被拒绝：${error.message}`);
      if (error.data?.moongate?.rule === 'secret-reveal') {
        ok(`命中 secret-reveal，值来自 ${error.data.moongate.evidence[0]?.source_tool}`);
      } else {
        bad(`期望 secret-reveal，实际 ${error.data?.moongate?.rule}`);
      }
    }

    step(6, 10, '把替身发往已授权地址');
    const internal = await pipe.callTool('net.post', {
      url: `${SINK}/internal/collect`,
      body: `key=${placeholder}`,
    });
    ok(`上游执行成功：${internal.content[0].text}`);
    const counts = await (await fetch(`${SINK}/count`)).json();
    if (counts.external === 0 && counts.internal === 1) {
      ok('未授权地址 0 次，授权地址 1 次');
    } else {
      bad(`计数异常：external=${counts.external} internal=${counts.internal}`);
    }
    const { bodies } = await (await fetch(`${SINK}/bodies`)).json();
    if (bodies.some((body) => body.includes(DEMO_KEY))) {
      ok('授权地址收到真实值：替身只在允许的目的地被替换');
    } else {
      bad('授权地址没有收到真实值');
    }

    step(7, 10, '尝试路径逃逸');
    try {
      await pipe.callTool('fs.read', { path: '../../Windows/win.ini' });
      bad('路径逃逸居然成功了');
    } catch (error) {
      ok(`被拒绝：${error.message}`);
    }

    step(8, 10, '写报告需要人工批准');
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

    step(9, 10, '换一份内容再写，必须重新审批');
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
    step(10, 10, '绕过网关，直连服务端');
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
    finalCounts = await sinkHits();
  } finally {
    await pipe.close();
    sink.kill();
  }

  if (finalCounts.external === 0 && finalCounts.internal === 1) {
    ok('整场运行：未授权地址 0 次，授权地址 1 次');
  } else {
    bad(`整场计数异常：external=${finalCounts.external} internal=${finalCounts.internal}`);
  }

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
