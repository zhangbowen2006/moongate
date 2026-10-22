// A minimal MCP stdio client.
//
// It deliberately uses no SDK: the demo should prove that the gateway works on
// the wire, and reading the four message shapes it needs (initialize,
// tools/list, tools/call, error) is clearer than hiding them behind a library.
// Any real client — Claude Desktop, Cursor, an SDK-based agent — speaks the
// same protocol.
import { spawn } from 'node:child_process';

export class McpPipe {
  constructor(command, args, options = {}) {
    this.child = spawn(command, args, {
      cwd: options.cwd,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, ...(options.env || {}) },
      windowsHide: true,
    });
    this.nextId = 1;
    this.pending = new Map();
    this.ready = null;
    this.stderr = '';
    this.onNotice = options.onNotice || (() => {});
    this.onLine = options.onLine || (() => {});

    let buffer = '';
    this.child.stdout.setEncoding('utf8');
    this.child.stdout.on('data', (chunk) => {
      buffer += chunk;
      let index;
      while ((index = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, index).replace(/\r$/, '');
        buffer = buffer.slice(index + 1);
        if (!line.trim()) continue;
        this.dispatch(line);
      }
    });

    let errBuffer = '';
    this.child.stderr.setEncoding('utf8');
    this.child.stderr.on('data', (chunk) => {
      errBuffer += chunk;
      let index;
      while ((index = errBuffer.indexOf('\n')) >= 0) {
        const line = errBuffer.slice(0, index);
        errBuffer = errBuffer.slice(index + 1);
        this.stderr += `${line}\n`;
        const match = line.match(/\[airlock\] ready (\{.*\})/);
        if (match) {
          try {
            this.ready = JSON.parse(match[1]);
          } catch {
            /* keep the raw line for debugging */
          }
        }
        this.onNotice(line);
      }
    });

    this.child.on('exit', (code) => {
      for (const { reject } of this.pending.values()) {
        reject(new Error(`gateway exited with code ${code}`));
      }
      this.pending.clear();
    });
  }

  dispatch(line) {
    this.onLine(line);
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      return;
    }
    if (message.id === undefined || !this.pending.has(message.id)) return;
    const waiter = this.pending.get(message.id);
    this.pending.delete(message.id);
    if (message.error) {
      const error = new Error(message.error.message || 'MCP error');
      error.code = message.error.code;
      error.data = message.error.data;
      waiter.reject(error);
    } else {
      waiter.resolve(message.result);
    }
  }

  request(method, params, timeoutMs = 15000) {
    const id = this.nextId;
    this.nextId += 1;
    const payload = JSON.stringify({ jsonrpc: '2.0', id, method, params });
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`timeout waiting for ${method} (id ${id})`));
      }, timeoutMs);
      this.pending.set(id, {
        resolve: (value) => {
          clearTimeout(timer);
          resolve(value);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
      });
      this.child.stdin.write(`${payload}\n`);
    });
  }

  notify(method, params) {
    this.child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method, params })}\n`);
  }

  async initialize() {
    const result = await this.request('initialize', {
      protocolVersion: '2025-06-18',
      capabilities: { tools: {} },
      clientInfo: { name: 'airlock-demo-client', version: '0.1.0' },
    });
    this.notify('notifications/initialized', {});
    return result;
  }

  async callTool(name, args) {
    return await this.request('tools/call', { name, arguments: args });
  }

  async close() {
    this.child.stdin.end();
    await new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.child.kill();
        resolve();
      }, 5000);
      this.child.on('exit', () => {
        clearTimeout(timer);
        resolve();
      });
    });
  }
}

export async function waitForReady(pipe, timeoutMs = 15000) {
  const started = Date.now();
  while (!pipe.ready) {
    if (Date.now() - started > timeoutMs) throw new Error('gateway did not report ready');
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return pipe.ready;
}

export async function approveOnce(url, { approve = true, matchTool = null } = {}) {
  const state = await (await fetch(new URL('/state', url))).json();
  const target = matchTool ? state.pending.find((item) => item.tool === matchTool) : state.pending[0];
  if (!target) throw new Error('no pending approval to resolve');
  const response = await fetch(new URL('/decision', url), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ call: target.call, approved: approve }),
  });
  return { call: target.call, ok: response.ok, status: response.status, pending: target };
}
