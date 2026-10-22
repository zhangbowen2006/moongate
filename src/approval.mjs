// Human approval channel.
//
// The gateway cannot prompt on stdin (that is the agent's channel) and should
// not open a network port to the outside world. It binds a control server to
// 127.0.0.1 on a random port and exposes exactly three routes: a small page, a
// JSON state snapshot, and a decision endpoint. The page is self-contained so
// an operator can approve or deny without any extra tooling.
import { createServer } from 'node:http';

const PAGE = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Airlock · 审批</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; font: 15px/1.55 ui-sans-serif, system-ui, "Segoe UI", sans-serif;
         background: #f4f6fb; color: #16202e; }
  header { padding: 22px 28px 16px; border-bottom: 1px solid #dde3ef; background: #fff; }
  h1 { margin: 0 0 4px; font-size: 18px; letter-spacing: .2px; }
  .sub { color: #5d6b82; font-size: 13px; }
  main { max-width: 880px; margin: 0 auto; padding: 24px 20px 60px; }
  .empty { padding: 40px; text-align: center; color: #6b7a90; background: #fff;
           border: 1px dashed #cfd8e8; border-radius: 12px; }
  .card { background: #fff; border: 1px solid #dde3ef; border-radius: 12px;
          padding: 16px 18px; margin-bottom: 14px; box-shadow: 0 1px 2px rgba(20,30,50,.04); }
  .row { display: flex; gap: 12px; align-items: baseline; justify-content: space-between; flex-wrap: wrap; }
  .tool { font: 600 15px/1.4 ui-monospace, SFMono-Regular, Menlo, monospace; }
  .rule { font-size: 12px; color: #6b7a90; }
  .reason { margin: 8px 0 10px; color: #33415a; }
  pre { margin: 10px 0 14px; padding: 12px; background: #f7f9fd; border: 1px solid #e3e9f3;
        border-radius: 8px; font: 12.5px/1.5 ui-monospace, Menlo, monospace; overflow: auto; color: #22304a; }
  .actions { display: flex; gap: 10px; }
  button { border: 1px solid transparent; border-radius: 8px; padding: 8px 16px; font-size: 14px;
           cursor: pointer; }
  .approve { background: #17663a; color: #fff; }
  .deny { background: #fff; color: #a11d2b; border-color: #e3b4ba; }
  button:disabled { opacity: .5; cursor: default; }
  .timer { font-variant-numeric: tabular-nums; color: #8a5a00; font-size: 12px; }
  footer { max-width: 880px; margin: 0 auto; padding: 0 20px 40px; color: #7b8798; font-size: 12px; }
  .dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; background: #17663a; margin-right: 6px; }
</style>
</head>
<body>
<header>
  <h1><span class="dot"></span>Airlock 审批台</h1>
  <div class="sub">每次审批只授权一次调用，参数哈希不同即失效。</div>
</header>
<main id="list"><div class="empty">正在读取状态…</div></main>
<footer id="foot"></footer>
<script>
let busy = new Set();
async function act(call, approved) {
  busy.add(call);
  await fetch('/decision', { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ call, approved }) });
  busy.delete(call);
  await refresh();
}
function esc(s) { return String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
async function refresh() {
  const state = await (await fetch('/state')).json();
  const list = document.getElementById('list');
  if (!state.pending.length) {
    list.innerHTML = '<div class="empty">当前没有待审批的调用。<br/>Agent 的请求会实时出现在这里。</div>';
  } else {
    list.innerHTML = state.pending.map(p => {
      const left = Math.max(0, Math.round((p.expires_at - Date.now()) / 1000));
      return '<div class="card"><div class="row"><span class="tool">' + esc(p.tool) + '</span>' +
        '<span class="rule">规则 ' + esc(p.rule) + ' · ' + esc(p.call) + '</span></div>' +
        '<div class="reason">' + esc(p.reason || '该调用需要人工确认') + '</div>' +
        '<pre>' + esc(JSON.stringify(p.summary, null, 2)) + '</pre>' +
        '<div class="row"><span class="timer">' + left + ' 秒后自动拒绝</span>' +
        '<div class="actions"><button class="approve" ' + (busy.has(p.call) ? 'disabled' : '') +
        ' onclick="act(\\'' + esc(p.call) + '\\', true)">批准一次</button>' +
        '<button class="deny" ' + (busy.has(p.call) ? 'disabled' : '') +
        ' onclick="act(\\'' + esc(p.call) + '\\', false)">拒绝</button></div></div></div>';
    }).join('');
  }
  document.getElementById('foot').textContent =
    '决策 ' + state.counts.allowed + ' 放行 / ' + state.counts.denied + ' 拒绝 / ' +
    state.counts.approvals + ' 审批 · 账本 ' + state.ledger;
}
refresh();
setInterval(refresh, 1000);
</script>
</body>
</html>`;

export function startApprovalBroker({ getState, decide, port = 0, host = '127.0.0.1' }) {
  const server = createServer(async (req, res) => {
    try {
      if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
        res.end(PAGE);
        return;
      }
      if (req.method === 'GET' && req.url.startsWith('/state')) {
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
        res.end(JSON.stringify(getState()));
        return;
      }
      if (req.method === 'POST' && req.url.startsWith('/decision')) {
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
        if (typeof body.call !== 'string' || typeof body.approved !== 'boolean') {
          res.writeHead(400, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'expected {call:string, approved:boolean}' }));
          return;
        }
        const result = decide(body.call, body.approved);
        res.writeHead(result.ok ? 200 : 409, { 'content-type': 'application/json' });
        res.end(JSON.stringify(result));
        return;
      }
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('not found');
    } catch (error) {
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: String(error && error.message) }));
    }
  });

  return new Promise((resolvePromise, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      const address = server.address();
      const url = `http://${host}:${address.port}/`;
      resolvePromise({
        url,
        port: address.port,
        close: () => new Promise((done) => server.close(done)),
      });
    });
  });
}
