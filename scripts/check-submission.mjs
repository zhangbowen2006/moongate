#!/usr/bin/env node
// Submission format checker.
//
// The August review rejected one project purely because the application format
// was unsupported, and four because the overlap with existing projects was not
// disclosed. This script turns those lessons into a mechanical check: the
// one-page Markdown must exist, stay short, carry every required section, name
// real comparable projects, and never contain a fill-in placeholder.
import { readFileSync } from 'node:fs';

const REQUIRED_SECTIONS = [
  '项目简介',
  '方向与通用性',
  '使用场景',
  '核心功能',
  '与现有项目的关系',
  '原创与来源',
  '仓库与安装',
];

const COMPARABLES = [
  'moonpod',
  'moon_policy',
  'moon-policyforge',
  'moon-policy-diff',
  'moon_scrub',
  'mcp shield',
  'mcpkernel',
  'mcp-firewall',
  'taintmcp',
  'agentperms',
  'authsome',
  'onecli',
  'mcp.mbt',
];

const MAX_CHARS = 1800;
const WARN_CHARS = 1500;

function stripComments(text) {
  return text.replace(/<!--[\s\S]*?-->/g, '');
}

function headings(text) {
  return text
    .split(/\r?\n/)
    .filter((line) => /^##\s+/.test(line))
    .map((line) => line.replace(/^##\s+/, '').trim());
}

function overlapSection(text) {
  const lines = text.split(/\r?\n/);
  let active = false;
  const out = [];
  for (const line of lines) {
    if (/^##\s+/.test(line)) {
      active = line.includes('与现有项目的关系');
      continue;
    }
    if (active) out.push(line);
  }
  return out.join('\n');
}

export function checkSubmission(source) {
  const text = stripComments(source);
  const errors = [];
  const warnings = [];
  if (!text.trim()) errors.push('文件为空');
  const chars = [...text.replace(/\s+/g, '')].length;
  if (chars > MAX_CHARS) errors.push(`正文 ${chars} 字，超过一页上限（${MAX_CHARS}）`);
  else if (chars > WARN_CHARS) warnings.push(`正文 ${chars} 字，接近一页上限（建议 ≤ ${WARN_CHARS}）`);

  const present = headings(text);
  for (const section of REQUIRED_SECTIONS) {
    if (!present.some((heading) => heading.includes(section))) {
      errors.push(`缺少章节：## ${section}`);
    }
  }

  const scenarios = (text.match(/^###\s+.*场景/gm) || []).length;
  if (scenarios < 3) {
    errors.push(`使用场景只有 ${scenarios} 个，要求至少 3 个（用 ### 场景一/二/三 区分）`);
  }

  const overlap = overlapSection(text).toLowerCase();
  const named = COMPARABLES.filter((name) => overlap.includes(name));
  if (named.length < 2) {
    errors.push('“与现有项目的关系”未点名至少 2 个同类项目（如 moonpod、moon_policy、MCP Shield）');
  }
  if (!/未复用|无代码复用|没有复制|独立实现/.test(text)) {
    errors.push('未声明与同类项目的代码关系（需要出现“无代码复用/独立实现”等表述）');
  }

  if (!text.includes('https://github.com/zhangbowen2006/moongate')) {
    errors.push('缺少仓库链接 https://github.com/zhangbowen2006/moongate');
  }
  if (!/mooncakes|moon add zhangbowen2006\/moongate/.test(text)) {
    errors.push('缺少 Mooncakes 安装信息');
  }

  if (/待填写|请本人填写|填写提示|TODO|TBD|XXX|\[填写\]/.test(text)) {
    errors.push('仍有占位提示未替换（待填写/TODO/请本人填写）');
  }
  if (/<(table|img|div|br|p)\b/i.test(text)) {
    errors.push('包含 HTML 标签；表单只接受 Markdown');
  }

  return { ok: errors.length === 0, chars, sections: present, comparables: named, errors, warnings };
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('check-submission.mjs')) {
  const args = process.argv.slice(2);
  const json = args.includes('--json');
  const file = args.find((arg) => !arg.startsWith('--'));
  if (!file) {
    console.error('usage: node scripts/check-submission.mjs <SUBMISSION.md> [--json]');
    process.exit(2);
  }
  let source;
  try {
    source = readFileSync(file, 'utf8');
  } catch (error) {
    console.error(`cannot read ${file}: ${error.message}`);
    process.exit(2);
  }
  const result = checkSubmission(source);
  if (json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`submission: ${file}`);
    console.log(`  length ${result.chars}/${MAX_CHARS} chars`);
    console.log(`  sections ${result.sections.length}`);
    console.log(`  comparables ${result.comparables.join(', ') || '(none)'}`);
    for (const warning of result.warnings) console.log(`  ! ${warning}`);
    for (const error of result.errors) console.log(`  x ${error}`);
    console.log(result.ok ? 'OK' : 'FAILED');
  }
  process.exit(result.ok ? 0 : 1);
}
