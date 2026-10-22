# MoonGate

**Two enforcement points for MCP tools.** The same MoonBit policy core runs in the gateway *and* inside the MCP server, so a bypassed proxy does not mean an unprotected tool.

The decision engine is MoonBit (compiled to JavaScript for the host). A prebuilt engine ships in `dist/`, so the demo runs with Node 22+ and no MoonBit toolchain.

## Honest positioning

MCP security gateways already exist and overlap heavily: MCP Shield, MCPKernel, mcp-firewall and taintmcp all provide policy, approvals, taint tracking and hash-chained audit logs; AgentPerms even infers a least-privilege policy from a recorded session.

MoonGate does not claim to invent those. Its difference is structural:

1. **Two enforcement points.** Those projects run one proxy process. If the client connects to the server directly, or the server is invoked by something else, the proxy is out of the loop. MoonGate compiles the same policy into the server, which checks again at the tool handler.
2. **One MoonBit core, multiple deployment shapes.** The gateway and the in-server guard call the same `.mbt` code; it can be built to JS/Wasm and embedded rather than requiring a Python or Node sidecar.

## What the second point buys

```
Agent ──stdio──▶ MoonGate gateway ──stdio──▶ MCP server ──▶ files / network
                     │                          │
                     │ check 1                  │ check 2 (embedded guard)
                     │ policy + lineage + human │ same policy, hard denials
                     └──────────────────────────┘
```

The demo includes a deliberate bypass: a client connects straight to the server and calls `fs.delete` and `reports/../../etc/passwd`. Both are refused by the server's own guard; the file is still there.

## Quick start

```sh
git clone https://github.com/zhangbowen2006/moongate.git
cd moongate
node demo/run.mjs
```

The demo starts real processes, touches real files and hits a real HTTP sink. It asserts nine scenarios, including the bypass.

```sh
node bin/moongate.mjs verify --ledger runs/demo.jsonl
node bin/moongate.mjs report --ledger runs/demo.jsonl
```

Build from source (MoonBit 0.10.16+):

```sh
moon check --deny-warn
moon test --deny-warn        # 29 unit tests
node scripts/build.mjs
node --test test/*.test.mjs  # 9 process-level tests
```

## Use it

**As a gateway** — point any MCP client at `moongate run ... -- <original command>`:

```jsonc
{
  "mcpServers": {
    "workspace": {
      "command": "node",
      "args": ["/abs/path/moongate/bin/moongate.mjs", "run",
               "--policy", "/abs/path/policy.json",
               "--ledger", "/abs/path/runs/session.jsonl",
               "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/abs/path/workspace"]
    }
  }
}
```

**As an in-server guard** — three lines before executing a tool:

```js
import * as gate from 'moongate/dist/engine.js';
const guard = JSON.parse(gate.guard_create(policyText)).handle;
const verdict = JSON.parse(gate.guard_check(guard, name, JSON.stringify(args)));
if (verdict.decision === 'deny') return { isError: true, content: [{ type: 'text', text: verdict.rule }] };
```

The guard enforces hard denials only. `approval` is returned as `allow`, because approval state lives in the gateway; otherwise an approved call would be blocked twice.

## Policy, lineage, approvals

- Ordered rules, first match wins, default deny; argument globs, prefixes, negation and lexical path normalization (`reports/../../etc/passwd` is not a `reports/*` path).
- Sensitive results are reduced to SHA-256 fingerprints of secret-shaped values; an egress call carrying one is denied with the source call as evidence.
- Approvals are bound to a canonical digest of `(tool, arguments)`, expire, and are consumed once.
- Denied tools are removed from `tools/list`.
- Every decision is one hash-chained ledger entry; `verify` recomputes the chain.

## Limits

- Without the embedded guard, a bypassed gateway is not protected.
- Lineage is exact-value matching; encoding, splitting or paraphrasing evades it.
- Path normalization is lexical; symlinks are not resolved.
- Not a sandbox; not multi-user; stdio only.

Full threat model: [docs/SEMANTICS.md](docs/SEMANTICS.md). Policy reference: [docs/POLICY.md](docs/POLICY.md).

## License

MIT. MoonBit core is Apache-2.0; its license and NOTICE ship with `dist/`.
