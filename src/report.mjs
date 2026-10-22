// Static HTML report.
//
// The report is generated from the ledger, not from in-memory state, so the
// same command works on a run recorded last week or copied from another
// machine. It embeds the machine-readable report as JSON so a reviewer can
// diff a report without scraping the table.
const escapeHtml = (value) =>
  String(value ?? '').replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  })[char]);

const fmtTime = (ms) => {
  if (!ms) return '—';
  const date = new Date(Number(ms));
  return `${date.toISOString().slice(0, 19).replace('T', ' ')}Z`;
};

const badge = (decision) => {
  const cls = decision === 'deny' ? 'bad' : decision === 'allow' ? 'good' : 'warn';
  return `<span class="badge ${cls}">${escapeHtml(decision || 'event')}</span>`;
};

export function renderReport({ report, verify, ledgerPath, policyPath }) {
  const blockedRows = report.blocked.length
    ? report.blocked
        .map(
          (item) => `<tr>
        <td class="mono">${escapeHtml(item.tool)}</td>
        <td>${badge('deny')}</td>
        <td class="mono">${escapeHtml(item.rule)}</td>
        <td>${escapeHtml(item.reason || '—')}</td>
        <td class="mono">${escapeHtml(item.call)}</td>
        <td class="num">${item.evidence || 0}</td>
      </tr>`,
        )
        .join('')
    : '<tr><td colspan="6" class="muted">本次运行没有被拒绝的调用。</td></tr>';

  const timelineRows = report.timeline
    .slice(-200)
    .map((item) => {
      const label =
        item.kind === 'decision'
          ? `${item.tool || ''} ${item.decision || ''}`.trim()
          : item.kind === 'result'
            ? `${item.tool || ''} result`
            : item.kind === 'approval'
              ? `${item.tool || ''} approval ${item.decision || ''}`.trim()
              : item.kind;
      return `<li>
        <span class="seq">#${item.seq}</span>
        <span class="mono label">${escapeHtml(label)}</span>
        ${item.rule ? `<span class="rule">${escapeHtml(item.rule)}</span>` : ''}
        ${item.reason ? `<span class="reason">${escapeHtml(item.reason)}</span>` : ''}
      </li>`;
    })
    .join('');

  const chain = verify.ok
    ? `<span class="pill good">哈希链完整 · ${verify.entries} 条</span>`
    : `<span class="pill bad">哈希链断裂 · ${escapeHtml(verify.reason)}</span>`;

  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>MoonGate 运行报告 · ${escapeHtml(report.policy.name || 'unnamed')}</title>
<style>
  :root { color-scheme: light; --ink:#16202e; --muted:#6b7a90; --line:#dde3ef; --bg:#f4f6fb; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--ink);
         font:15px/1.6 ui-sans-serif, system-ui, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif; }
  .wrap { max-width: 1080px; margin: 0 auto; padding: 36px 24px 64px; }
  header { display:flex; justify-content:space-between; gap:24px; align-items:flex-start; flex-wrap:wrap; }
  h1 { margin:0 0 6px; font-size:24px; letter-spacing:.2px; }
  .sub { color:var(--muted); font-size:13px; }
  .meta { text-align:right; font-size:12.5px; color:var(--muted); line-height:1.8; }
  .meta .mono { color:#33415a; }
  .pill { display:inline-block; padding:3px 10px; border-radius:999px; font-size:12px; border:1px solid; }
  .pill.good { color:#17663a; border-color:#b9dcc7; background:#eef8f2; }
  .pill.bad { color:#a11d2b; border-color:#e3b4ba; background:#fdf0f1; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:14px; margin:26px 0 30px; }
  .card { background:#fff; border:1px solid var(--line); border-radius:12px; padding:16px 18px; }
  .card .k { color:var(--muted); font-size:12.5px; }
  .card .v { font-size:28px; font-weight:650; margin-top:4px; font-variant-numeric:tabular-nums; }
  h2 { font-size:16px; margin:34px 0 12px; }
  table { width:100%; border-collapse:collapse; background:#fff; border:1px solid var(--line); border-radius:12px; overflow:hidden; }
  th, td { text-align:left; padding:11px 14px; border-bottom:1px solid #edf1f7; font-size:13.5px; vertical-align:top; }
  th { background:#f8faff; color:var(--muted); font-weight:600; font-size:12.5px; }
  tr:last-child td { border-bottom:none; }
  .mono { font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12.5px; }
  .num { text-align:right; font-variant-numeric:tabular-nums; }
  .muted { color:var(--muted); text-align:center; padding:22px; }
  .badge { display:inline-block; padding:1px 8px; border-radius:999px; font-size:11.5px; border:1px solid; }
  .badge.good { color:#17663a; border-color:#b9dcc7; background:#eef8f2; }
  .badge.bad { color:#a11d2b; border-color:#e3b4ba; background:#fdf0f1; }
  .badge.warn { color:#8a5a00; border-color:#e6d3a8; background:#fdf8ec; }
  ol.timeline { list-style:none; padding:0; margin:0; background:#fff; border:1px solid var(--line); border-radius:12px; }
  ol.timeline li { display:flex; gap:10px; align-items:baseline; padding:9px 14px; border-bottom:1px solid #edf1f7; font-size:13px; flex-wrap:wrap; }
  ol.timeline li:last-child { border-bottom:none; }
  .seq { color:#8d9ab0; font-size:11.5px; width:44px; font-variant-numeric:tabular-nums; }
  .label { min-width:220px; }
  .rule { color:#5b6b84; font-size:11.5px; background:#f1f5fb; border-radius:5px; padding:1px 6px; }
  .reason { color:var(--muted); font-size:12.5px; }
  footer { margin-top:28px; color:var(--muted); font-size:12px; }
  code { background:#eef2f9; padding:1px 5px; border-radius:4px; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>MoonGate 运行报告</h1>
      <div class="sub">策略 <strong>${escapeHtml(report.policy.name || 'unnamed')}</strong> ·
        指纹 <span class="mono">${escapeHtml((report.policy.digest || '').slice(0, 16))}</span> ·
        ${report.entries} 条账本记录</div>
    </div>
    <div class="meta">
      ${chain}<br/>
      账本 <span class="mono">${escapeHtml(ledgerPath || '')}</span><br/>
      策略文件 <span class="mono">${escapeHtml(policyPath || '—')}</span><br/>
      生成于 ${fmtTime(Date.now())}
    </div>
  </header>

  <section class="cards">
    <div class="card"><div class="k">执行（含审批通过）</div><div class="v">${report.decisions.executed}</div></div>
    <div class="card"><div class="k">拒绝</div><div class="v">${report.decisions.deny}</div></div>
    <div class="card"><div class="k">需要审批</div><div class="v">${report.decisions.approval_required}</div></div>
    <div class="card"><div class="k">新增敏感值</div><div class="v">${report.results.new_sensitive_values}</div></div>
  </section>

  <h2>被拦下的调用</h2>
  <table>
    <thead><tr><th>工具</th><th>判定</th><th>规则</th><th>原因</th><th>调用</th><th class="num">证据</th></tr></thead>
    <tbody>${blockedRows}</tbody>
  </table>

  <h2>审批</h2>
  <p class="sub">批准 ${report.approvals.granted} 次，拒绝或超时 ${report.approvals.rejected} 次。每次批准只对当次调用的参数哈希生效。</p>

  <h2>时间线（最近 200 条）</h2>
  <ol class="timeline">${timelineRows}</ol>

  <footer>
    校验命令：<code>node bin/moongate.mjs verify --ledger ${escapeHtml(ledgerPath || '<run.jsonl>')}</code><br/>
    账本每行都包含前一条的哈希，修改任意一行都会使校验失败。
  </footer>
</div>
<script type="application/json" id="moongate-report">${JSON.stringify({ report, verify }).replace(/</g, '\\u003c')}</script>
</body>
</html>`;
}
