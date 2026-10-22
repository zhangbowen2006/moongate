# Airlock

**A runtime policy gateway between agents and MCP tools.** Every tool call is checked before it is forwarded; a denied call never reaches the server, so the side effect never happens.

The decision engine is written in MoonBit (compiled to JavaScript for the host). A prebuilt engine ships in `dist/`, so the demo runs with Node 22+ and no MoonBit toolchain.

## Why

Observing a trace after the fact tells you what happened, not what almost happened. Airlock sits in the path: it reads each JSON-RPC line, decides, and only then writes to the upstream process.

```
Agent ──stdio──▶ Airlock ──stdio──▶ MCP Server ──▶ files / network / database
                    │
                    ├─ policy: is this tool, with these arguments, allowed?
                    ├─ lineage: do the arguments carry a value read earlier?
                    ├─ approval: a human may grant exactly one call
                    └─ ledger: hash-chained, verifiable offline
```

## Quick start

```sh
git clone https://github.com/zhangbowen2006/airlock.git
cd airlock
node demo/run.mjs
```

The demo starts three real processes, touches real files, and asserts the outcome:

- a credential read from `config/.env` cannot be POSTed out (`egress-taint`), and the local sink stays at zero requests;
- `../` paths are rejected before the server sees them;
- a write requires approval, lands on disk only after it, and a modified retry needs a new approval;
- a denied write leaves the previous file content untouched;
- the ledger chain verifies, and fails after a single byte changes.

## Build from source

Requires MoonBit 0.10.16+.

```sh
moon check --deny-warn
moon test --deny-warn      # 26 unit tests
node scripts/build.mjs
node --test test/*.test.mjs  # 6 process-level tests
```

Third-party interop (official SDK client + official filesystem server):

```sh
cd interop && npm install && node client.mjs
```

## Point any MCP client at it

```jsonc
{
  "mcpServers": {
    "workspace": {
      "command": "node",
      "args": ["/path/to/airlock/bin/airlock.mjs", "run",
               "--policy", "/path/to/policy.json",
               "--ledger", "/path/to/runs/session.jsonl",
               "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/path/to/workspace"]
    }
  }
}
```

Denied calls return JSON-RPC error `-32001` with the rule, reason and lineage evidence, so the agent can adapt instead of retrying blindly.

## Design notes

- Decisions run before forwarding; the host has no policy branches.
- Lineage is exact-value taint with fingerprints, not semantic DLP. It is reproducible and explainable; it does not catch encoded or split payloads.
- Approvals are bound to a canonical digest of the tool and arguments, expire, and are consumed once.
- The ledger commits to its predecessor (`sha256(prev + "\n" + canonical(event))`), so edits are detectable.

Limits, threat model and non-goals: [docs/SEMANTICS.md](docs/SEMANTICS.md). Policy reference: [docs/POLICY.md](docs/POLICY.md). Architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## License

MIT. MoonBit core is Apache-2.0; its license and NOTICE ship with `dist/`.
