///|
/// The gateway state machine.
///
/// The engine is deliberately transport-agnostic: it consumes one protocol
/// line at a time and returns a list of actions for the host to execute. In
/// production the host is a Node process that owns the two pipes; in tests the
/// same engine is driven with plain strings. That split keeps every security
/// decision in MoonBit while the host only performs I/O.
///
/// Invariants the engine maintains:
///
/// - A denied `tools/call` is never forwarded, so the upstream server cannot
///   perform the side effect.
/// - An approval is bound to the canonical digest of the exact tool name and
///   arguments, expires, and is consumed once.
/// - Values from sensitive results are fingerprinted and matched against the
///   arguments of egress tools before any rule is applied.
/// - Every decision produces exactly one hash-chained ledger event.
struct Inflight {
  call : String
  tool : String
  sensitive : Bool
}

///|
struct PendingApproval {
  call : String
  tool : String
  digest : String
  line : String
  key : String
  id : Json?
  rule : String
  expires : Int64
  sensitive : Bool
  revealed : Int32
}

///|
/// A protected value kept in memory for the lifetime of one session. It is
/// never written to the ledger; only `preview` and the fingerprint leave the
/// process.
struct SecretEntry {
  value : String
  preview : String
  call : String
  tool : String
}

///|
pub struct Session {
  id : String
  policy : Policy
  mut seq : Int32
  mut prev_hash : String
  mut call_seq : Int32
  inflight : Map[String, Inflight]
  lists : Map[String, Bool]
  pending : Map[String, PendingApproval]
  taint : Map[String, TaintSource]
  vault : Map[String, SecretEntry]
  mut attempts : Array[Int64]
  mut allowed : Int32
  mut denied : Int32
  mut approval_requests : Int32
  mut forwarded : Int32
  mut tainted_values : Int32
  mut total_calls : Int32
  mut arg_bytes : Int64
  mut reveal_count : Int32
}

///|
pub fn new_session(id : String, policy : Policy) -> Session {
  {
    id,
    policy,
    seq: 0,
    prev_hash: "",
    call_seq: 0,
    inflight: Map([]),
    lists: Map([]),
    pending: Map([]),
    taint: Map([]),
    vault: Map([]),
    attempts: [],
    allowed: 0,
    denied: 0,
    approval_requests: 0,
    forwarded: 0,
    tainted_values: 0,
    total_calls: 0,
    arg_bytes: 0,
    reveal_count: 0,
  }
}

///|
/// First ledger event of a run: which policy governed it, identified by
/// content hash, so a report can be tied to an exact policy revision.
pub fn open_session(session : Session, now : Int64) -> Json {
  ledger_event(session, now, "session_open", [
    ("engine", json_str("0.2.0")),
    ("policy", json_str(session.policy.name)),
    ("policy_digest", json_str(session.policy.digest)),
    ("rules", json_int(session.policy.rules.length())),
    ("default", json_str(session.policy.default_decision)),
    ("rate_window_ms", json_int(session.policy.rate.window_ms)),
    ("rate_max_calls", json_int(session.policy.rate.max_calls)),
    ("approval_ttl_ms", json_int(session.policy.approval_ttl_ms)),
    ("min_secret_len", json_int(session.policy.min_secret_len)),
    ("hide_denied", json_bool(session.policy.hide_denied)),
  ])
}

///|
fn action_upstream(line : String) -> Json {
  json_obj([("kind", json_str("upstream")), ("line", json_str(line))])
}

///|
fn action_client(line : String) -> Json {
  json_obj([("kind", json_str("client")), ("line", json_str(line))])
}

///|
fn action_notice(level : String, message : String) -> Json {
  json_obj([
    ("kind", json_str("notice")),
    ("level", json_str(level)),
    ("message", json_str(message)),
  ])
}

///|
/// Append one event to the hash chain and return the host action that writes
/// it. The chain input is `previous_hash + "\n" + canonical(event)`; the hash
/// itself is excluded, so verification can recompute it from the stored line.
fn ledger_event(
  session : Session,
  now : Int64,
  kind : String,
  fields : Array[(String, Json)],
) -> Json {
  let pairs : Array[(String, Json)] = [
    ("seq", json_int(session.seq)),
    ("ts", json_i64(now)),
    ("session", json_str(session.id)),
    ("kind", json_str(kind)),
  ]
  for field in fields {
    pairs.push(field)
  }
  let chained : Array[(String, Json)] = []
  for pair in pairs {
    chained.push(pair)
  }
  chained.push(("prev", json_str(session.prev_hash)))
  // `prev` is part of the hashed body: verification strips only `hash` and
  // recomputes, so the chain commits to its own predecessor.
  let body = json_obj(chained)
  let hash = sha256_hex(session.prev_hash + "\n" + json_canonical(body))
  chained.push(("hash", json_str(hash)))
  session.prev_hash = hash
  session.seq += 1
  json_obj([
    ("kind", json_str("ledger")),
    ("line", json_str(json_render(json_obj(chained)))),
  ])
}

///|
fn evidence_json(hits : Array[TaintHit]) -> Json {
  let items : Array[Json] = []
  for hit in hits {
    items.push(
      json_obj([
        ("fingerprint", json_str(hit.fingerprint)),
        ("preview", json_str(hit.preview)),
        ("source_call", json_str(hit.source.call)),
        ("source_tool", json_str(hit.source.tool)),
      ]),
    )
  }
  json_arr(items)
}

///|
fn object_keys(value : Json) -> Array[String] {
  let keys : Array[String] = []
  match value {
    Object(fields) =>
      for key, _ in fields {
        keys.push(key)
      }
    _ => ()
  }
  keys
}

///|
/// Canonical digest of a call. Approvals and ledger entries use this value so
/// that a grant for `write reports/a.md` cannot be replayed for
/// `write reports/b.md`.
pub fn call_digest(tool : String, args : Json) -> String {
  sha256_hex(
    json_canonical(json_obj([("tool", json_str(tool)), ("arguments", args)])),
  )
}

///|
priv struct Verdict {
  decision : String
  rule : String
  reason : String
  hits : Array[TaintHit]
  ttl_ms : Int32
}

///|
fn rate_exceeded(session : Session, now : Int64) -> Bool {
  let window_start = now - session.policy.rate.window_ms.to_int64()
  let kept : Array[Int64] = []
  for stamp in session.attempts {
    if stamp > window_start {
      kept.push(stamp)
    }
  }
  session.attempts = kept
  let exceeded = kept.length() >= session.policy.rate.max_calls
  kept.push(now)
  session.attempts = kept
  exceeded
}

///|
/// Decide one call. Order matters and is documented in `docs/POLICY.md`:
/// rate first (cheap, protects the upstream), then data provenance (the
/// strongest guarantee), then the ordered rule list, then the default.
fn decide(
  session : Session,
  tool : String,
  args : Json,
  now : Int64,
) -> Verdict {
  let policy = session.policy
  if rate_exceeded(session, now) {
    return {
      decision: "deny",
      rule: "rate-limit",
      reason: "session exceeded \{policy.rate.max_calls} calls per \{policy.rate.window_ms} ms",
      hits: [],
      ttl_ms: 0,
    }
  }
  let arg_size = @utf8.encode(json_canonical(args)).length().to_int64()
  if policy.budget.max_calls > 0 &&
    session.total_calls >= policy.budget.max_calls {
    return {
      decision: "deny",
      rule: "budget-calls",
      reason: "session call budget exhausted (\{policy.budget.max_calls})",
      hits: [],
      ttl_ms: 0,
    }
  }
  if policy.budget.max_arg_bytes > 0 &&
    session.arg_bytes + arg_size > policy.budget.max_arg_bytes.to_int64() {
    return {
      decision: "deny",
      rule: "budget-bytes",
      reason: "argument budget exhausted (\{session.arg_bytes}/\{policy.budget.max_arg_bytes} bytes)",
      hits: [],
      ttl_ms: 0,
    }
  }
  session.total_calls += 1
  session.arg_bytes += arg_size
  let hits = if is_egress(policy, tool) {
    find_taint(session.taint, collect_strings(args), policy.min_secret_len)
  } else {
    []
  }
  if hits.length() > 0 {
    return {
      decision: policy.on_taint,
      rule: "egress-taint",
      reason: "arguments carry \{hits.length()} value(s) seen in sensitive results",
      hits,
      ttl_ms: policy.approval_ttl_ms,
    }
  }
  match match_rule(policy, tool, args) {
    Some(hit) =>
      return {
        decision: hit.decision,
        rule: hit.id,
        reason: hit.reason,
        hits: [],
        ttl_ms: if hit.ttl_ms > 0 {
          hit.ttl_ms
        } else {
          policy.approval_ttl_ms
        },
      }
    None => ()
  }
  {
    decision: policy.default_decision,
    rule: "default",
    reason: "no rule matched",
    hits: [],
    ttl_ms: policy.approval_ttl_ms,
  }
}

///|
fn denial_message(verdict : Verdict) -> String {
  let detail = if verdict.reason.is_empty() {
    "rule \{verdict.rule}"
  } else {
    verdict.reason
  }
  "Blocked by MoonGate policy (\{verdict.rule}): \{detail}"
}

///|
fn denial_payload(
  verdict : Verdict,
  call : String,
  tool : String,
  digest : String,
) -> Json {
  json_obj([
    ("decision", json_str(verdict.decision)),
    ("rule", json_str(verdict.rule)),
    ("reason", json_str(verdict.reason)),
    ("call", json_str(call)),
    ("tool", json_str(tool)),
    ("digest", json_str(digest)),
    ("evidence", evidence_json(verdict.hits)),
  ])
}

///|
fn deny_response(
  msg : RpcMessage,
  verdict : Verdict,
  call : String,
  tool : String,
  digest : String,
) -> Json {
  error_response(
    msg.id,
    -32001,
    denial_message(verdict),
    Some(json_obj([("moongate", denial_payload(verdict, call, tool, digest))])),
  )
}

///|
fn approval_summary(
  args : Json,
  taint : Map[String, TaintSource],
  min_len : Int32,
) -> Json {
  match args {
    Object(fields) => {
      let pairs : Array[(String, Json)] = []
      for key, value in fields {
        match value {
          String(s) => {
            let hits = find_taint(taint, [s], min_len)
            let shown = if hits.length() > 0 {
              "«redacted»"
            } else if s.length() > 120 {
              s[0:120].to_owned() + "…"
            } else {
              s
            }
            pairs.push((key, json_str(shown)))
          }
          Number(n, ..) => pairs.push((key, Json::number(n)))
          True | False | Null => pairs.push((key, value))
          _ => pairs.push((key, json_str("«object»")))
        }
      }
      json_obj(pairs)
    }
    _ => json_obj([])
  }
}

///|
fn remember_raw(
  session : Session,
  call : String,
  tool : String,
  raws : Array[RawToken],
) -> Int32 {
  let mut count = 0
  for raw in raws {
    if !session.taint.contains(raw.fingerprint) {
      session.taint.set(raw.fingerprint, taint_source(call, tool, raw.preview))
      count += 1
    }
    if !session.vault.contains(raw.fingerprint) {
      session.vault.set(raw.fingerprint, {
        value: raw.value,
        preview: raw.preview,
        call,
        tool,
      })
    }
  }
  session.tainted_values += count
  count
}

///|
fn mask_text(text : String, raws : Array[RawToken]) -> String {
  let mut out = text
  for raw in raws {
    out = out.replace_all(old=raw.value, new=placeholder_for(raw.fingerprint))
  }
  out
}

///|
fn placeholders_evidence(
  session : Session,
  fingerprints : Array[String],
) -> Array[TaintHit] {
  let hits : Array[TaintHit] = []
  for fingerprint in fingerprints {
    match session.vault.get(fingerprint) {
      Some(entry) =>
        hits.push({
          fingerprint,
          preview: entry.preview,
          source: taint_source(entry.call, entry.tool, entry.preview),
        })
      None => ()
    }
  }
  hits
}

///|
fn vault_values(session : Session) -> Map[String, String] {
  let values : Map[String, String] = Map([])
  for fingerprint, entry in session.vault {
    values.set(fingerprint, entry.value)
  }
  values
}

///|
fn rebuild_with_params(msg : RpcMessage, params : Json) -> String {
  match msg.raw {
    Object(fields) => {
      let copy : Map[String, Json] = Map([])
      for key, value in fields {
        copy.set(key, value)
      }
      copy.set("params", params)
      json_render(Json::object(copy))
    }
    _ => json_render(msg.raw)
  }
}

///|
fn decision_ledger(
  session : Session,
  now : Int64,
  tool : String,
  call : String,
  verdict : Verdict,
  digest : String,
  args : Json,
  via : String,
  revealed : Int32,
  reveal_rule : String,
) -> Json {
  ledger_event(session, now, "decision", [
    ("tool", json_str(tool)),
    ("call", json_str(call)),
    ("decision", json_str(verdict.decision)),
    ("rule", json_str(verdict.rule)),
    ("reason", json_str(verdict.reason)),
    ("digest", json_str(digest)),
    ("via", json_str(via)),
    ("args_keys", json_strings(object_keys(args))),
    ("revealed", json_int(revealed)),
    ("reveal_rule", json_str(reveal_rule)),
    ("evidence", evidence_json(verdict.hits)),
  ])
}

///|
fn protocol_error(
  session : Session,
  now : Int64,
  message : String,
  line : String,
) -> Array[Json] {
  let actions : Array[Json] = []
  actions.push(
    ledger_event(session, now, "protocol_error", [
      ("message", json_str(message)),
      ("bytes", json_int(line.length())),
    ]),
  )
  actions.push(
    action_client(
      json_render(
        error_response(None, -32700, "MoonGate: invalid JSON-RPC message", None),
      ),
    ),
  )
  actions
}

///|
fn handle_tool_call(
  session : Session,
  msg : RpcMessage,
  verb : String,
  line : String,
  now : Int64,
) -> Array[Json] {
  let actions : Array[Json] = []
  let tool = if verb == "tools/call" {
    match tool_name_of(msg.params) {
      Some(name) =>
        if name.is_empty() || name.length() > 200 {
          return [
            action_client(
              json_render(
                error_response(
                  msg.id,
                  -32602,
                  "MoonGate: tools/call requires a nonempty params.name",
                  None,
                ),
              ),
            ),
          ]
        } else {
          name
        }
      None =>
        return [
          action_client(
            json_render(
              error_response(
                msg.id,
                -32602,
                "MoonGate: tools/call requires params.name",
                None,
              ),
            ),
          ),
        ]
    }
  } else {
    capability_name(verb)
  }
  let args = capability_args(verb, msg.params)
  let digest = call_digest(tool, args)
  session.call_seq += 1
  let call = "c\{session.call_seq}"
  let fingerprints = placeholders_in(args)
  let mut forward_line = line
  let mut revealed = 0
  let mut reveal_rule = ""
  if !fingerprints.is_empty() {
    match match_reveal(session.policy, tool, args) {
      None => {
        let verdict : Verdict = {
          decision: "deny",
          rule: "secret-reveal",
          reason: "destination is not allowed to receive a protected value",
          hits: placeholders_evidence(session, fingerprints),
          ttl_ms: 0,
        }
        actions.push(
          decision_ledger(
            session, now, tool, call, verdict, digest, args, "client", 0, "",
          ),
        )
        session.denied += 1
        actions.push(
          action_client(
            json_render(deny_response(msg, verdict, call, tool, digest)),
          ),
        )
        return actions
      }
      Some(rule) => {
        reveal_rule = rule.id
        revealed = fingerprints.length()
        if session.policy.budget.max_reveals > 0 &&
          session.reveal_count + revealed > session.policy.budget.max_reveals {
          let verdict : Verdict = {
            decision: "deny",
            rule: "budget-reveals",
            reason: "reveal budget exhausted (\{session.policy.budget.max_reveals})",
            hits: placeholders_evidence(session, fingerprints),
            ttl_ms: 0,
          }
          actions.push(
            decision_ledger(
              session, now, tool, call, verdict, digest, args, "client", 0, "",
            ),
          )
          session.denied += 1
          actions.push(
            action_client(
              json_render(deny_response(msg, verdict, call, tool, digest)),
            ),
          )
          return actions
        }
        let values = vault_values(session)
        let params = map_json_strings(
          match msg.params {
            Some(params) => params
            None => Json::null()
          },
          fn(text) { reveal_placeholders(text, values).0 },
        )
        forward_line = rebuild_with_params(msg, params)
      }
    }
  }
  let verdict = decide(session, tool, args, now)
  actions.push(
    decision_ledger(
      session, now, tool, call, verdict, digest, args, "client", revealed, reveal_rule,
    ),
  )
  match verdict.decision {
    "allow" => {
      session.allowed += 1
      session.forwarded += 1
      let key = id_key(msg.id)
      session.inflight.set(key, {
        call,
        tool,
        sensitive: is_sensitive(session.policy, tool, args),
      })
      session.reveal_count += revealed
      actions.push(action_upstream(forward_line))
    }
    "approval" => {
      session.approval_requests += 1
      let expires = now + verdict.ttl_ms.to_int64()
      session.pending.set(call, {
        call,
        tool,
        digest,
        line: forward_line,
        key: id_key(msg.id),
        id: msg.id,
        rule: verdict.rule,
        expires,
        sensitive: is_sensitive(session.policy, tool, args),
        revealed,
      })
      actions.push(
        json_obj([
          ("kind", json_str("approval")),
          ("call", json_str(call)),
          ("tool", json_str(tool)),
          ("digest", json_str(digest)),
          ("rule", json_str(verdict.rule)),
          ("reason", json_str(verdict.reason)),
          ("expires_at", json_i64(expires)),
          (
            "summary",
            approval_summary(args, session.taint, session.policy.min_secret_len),
          ),
        ]),
      )
    }
    _ => {
      session.denied += 1
      actions.push(
        action_client(
          json_render(deny_response(msg, verdict, call, tool, digest)),
        ),
      )
    }
  }
  actions
}

///|
fn handle_client_message(
  session : Session,
  msg : RpcMessage,
  line : String,
  now : Int64,
) -> Array[Json] {
  match msg.verb {
    None =>
      // A response from the client to a server-initiated request. Forward it
      // and record only its shape.
      [
        action_upstream(line),
        ledger_event(session, now, "client_response", [
          ("id", json_str(id_key(msg.id))),
          ("bytes", json_int(line.length())),
        ]),
      ]
    Some(verb) =>
      if verb == "tools/call" ||
        verb == "resources/read" ||
        verb == "prompts/get" {
        handle_tool_call(session, msg, verb, line, now)
      } else if is_passthrough_method(verb) {
        if verb == "tools/list" && msg.has_id {
          session.lists.set(id_key(msg.id), true)
        }
        session.forwarded += 1
        [
          action_upstream(line),
          ledger_event(session, now, "passthrough", [
            ("method", json_str(verb)),
            ("bytes", json_int(line.length())),
          ]),
        ]
      } else {
        session.denied += 1
        let response = error_response(
          msg.id,
          -32601,
          "MoonGate: method \{verb} is not allowed by policy",
          None,
        )
        [
          ledger_event(session, now, "unsupported", [("method", json_str(verb))]),
          action_client(json_render(response)),
        ]
      }
  }
}

///|
/// Drive one line coming from the agent (client side).
pub fn client_line(
  session : Session,
  line : String,
  now : Int64,
) -> Array[Json] {
  let value = match json_parse_opt(line) {
    Some(value) => value
    None => return protocol_error(session, now, "invalid JSON", line)
  }
  match parse_rpc(value) {
    None => protocol_error(session, now, "not a JSON-RPC message", line)
    Some(msg) => handle_client_message(session, msg, line, now)
  }
}

///|
/// Whether a tool should appear in `tools/list`.
///
/// Hiding is conservative: a tool is hidden only when an unconditional deny
/// rule matches it, or when nothing matches and the default is deny. Tools
/// governed by conditional rules stay visible, because those rules can allow
/// some arguments.
pub fn advertise_tool(policy : Policy, tool : String) -> Bool {
  let mut conditional = false
  for rule in policy.rules {
    if glob_match(rule.tool, tool) {
      if rule.checks.is_empty() {
        return rule.decision != "deny"
      }
      // A conditional *deny* narrows what is allowed; it never grants a
      // capability, so it must not keep an otherwise denied tool visible.
      if rule.decision != "deny" {
        conditional = true
      }
    }
  }
  if conditional {
    return true
  }
  policy.default_decision != "deny"
}

///|
fn filter_tool_list(session : Session, result : Json) -> (Json, Int32) {
  let fields = match json_as_object(result) {
    Some(fields) => fields
    None => return (result, 0)
  }
  let tools = match fields.get("tools") {
    Some(Array(tools)) => tools
    _ => return (result, 0)
  }
  let kept : Array[Json] = []
  let mut hidden = 0
  for tool in tools {
    let name = match json_get(tool, "name") {
      Some(String(name)) => name
      _ => ""
    }
    if name != "" && advertise_tool(session.policy, name) {
      kept.push(tool)
    } else {
      hidden += 1
    }
  }
  if hidden == 0 {
    return (result, 0)
  }
  let rewritten : Map[String, Json] = Map([])
  for key, value in fields {
    rewritten.set(key, value)
  }
  rewritten.set("tools", json_arr(kept))
  (Json::object(rewritten), hidden)
}

///|
fn handle_server_response(
  session : Session,
  msg : RpcMessage,
  line : String,
  now : Int64,
) -> Array[Json] {
  let key = id_key(msg.id)
  if session.lists.contains(key) {
    let _ = session.lists.remove(key)
    let actions : Array[Json] = []
    match msg.result {
      Some(result) => {
        let (rewritten, hidden) = filter_tool_list(session, result)
        if hidden > 0 {
          actions.push(
            action_client(json_render(result_response(msg.id, rewritten))),
          )
          actions.push(
            ledger_event(session, now, "tool_list_filtered", [
              ("hidden", json_int(hidden)),
            ]),
          )
        } else {
          actions.push(action_client(line))
        }
      }
      None => actions.push(action_client(line))
    }
    return actions
  }
  if session.inflight.contains(key) {
    let call = match session.inflight.get(key) {
      Some(call) => call
      None => return [action_client(line)]
    }
    let _ = session.inflight.remove(key)
    let texts = collect_strings(
      match msg.result {
        Some(result) => result
        None => msg.error.unwrap_or(Json::null())
      },
    )
    let raws = if call.sensitive {
      scan_raw(texts, session.policy.min_secret_len)
    } else {
      []
    }
    let added = if call.sensitive {
      remember_raw(session, call.call, call.tool, raws)
    } else {
      0
    }
    let masked = session.policy.mask_secrets && raws.length() > 0
    let outgoing = if masked {
      json_render(map_json_strings(msg.raw, fn(text) { mask_text(text, raws) }))
    } else {
      line
    }
    let is_error = match msg.error {
      Some(_) => true
      None => false
    }
    let actions : Array[Json] = [
      action_client(outgoing),
      ledger_event(session, now, "result", [
        ("tool", json_str(call.tool)),
        ("call", json_str(call.call)),
        ("bytes", json_int(line.length())),
        ("is_error", json_bool(is_error)),
        ("sensitive", json_bool(call.sensitive)),
        ("new_values", json_int(added)),
        ("masked", json_int(if masked { raws.length() } else { 0 })),
      ]),
    ]
    actions
  } else {
    // Response to a request the gateway did not mediate (for example a
    // server-initiated `roots/list` answered by the client). Forward as-is.
    [action_client(line)]
  }
}

///|
fn handle_server_request(
  session : Session,
  msg : RpcMessage,
  line : String,
  now : Int64,
) -> Array[Json] {
  let verb = match msg.verb {
    Some(verb) => verb
    None => ""
  }
  if verb == "roots/list" {
    [
      action_upstream(line),
      ledger_event(session, now, "server_request", [
        ("method", json_str(verb)),
        ("decision", json_str("allow")),
      ]),
    ]
  } else {
    let response = error_response(
      msg.id,
      -32001,
      "MoonGate: server-initiated \{verb} is not permitted",
      None,
    )
    [
      ledger_event(session, now, "server_request", [
        ("method", json_str(verb)),
        ("decision", json_str("deny")),
      ]),
      action_upstream(json_render(response)),
    ]
  }
}

///|
/// Drive one line coming from the upstream MCP server.
pub fn server_line(
  session : Session,
  line : String,
  now : Int64,
) -> Array[Json] {
  let value = match json_parse_opt(line) {
    Some(value) => value
    None => {
      let actions : Array[Json] = []
      actions.push(
        ledger_event(session, now, "protocol_error", [
          ("side", json_str("server")),
          ("message", json_str("invalid JSON")),
          ("bytes", json_int(line.length())),
        ]),
      )
      actions.push(
        action_notice(
          "warn", "MoonGate dropped a malformed line from the upstream server",
        ),
      )
      return actions
    }
  }
  match parse_rpc(value) {
    None =>
      [
        action_notice(
          "warn", "MoonGate dropped a non JSON-RPC line from upstream",
        ),
      ]
    Some(msg) =>
      match msg.verb {
        Some(verb) =>
          if msg.has_id {
            handle_server_request(session, msg, line, now)
          } else {
            [
              action_upstream(line),
              ledger_event(session, now, "server_notification", [
                ("method", json_str(verb)),
              ]),
            ]
          }
        None => handle_server_response(session, msg, line, now)
      }
  }
}

///|
/// Stateless policy check for the in-process guard.
///
/// The guard runs inside the MCP server, where there is no session, no
/// lineage table and no approval queue. It therefore enforces only hard
/// denials: `approval` is reported as `allow` because the gateway decides
/// whether a human approved the call. This is the second enforcement point —
/// if the gateway is bypassed, forbidden tools still do not run.
pub fn guard_decision(policy : Policy, tool : String, args : Json) -> Json {
  if !placeholders_in(args).is_empty() {
    return guard_payload(
      "deny", "unresolved-secret", "a placeholder can only be resolved by the gateway",
    )
  }
  match match_rule(policy, tool, args) {
    Some(hit) => guard_payload(hit.decision, hit.id, hit.reason)
    None => guard_payload(policy.default_decision, "default", "no rule matched")
  }
}

///|
fn guard_payload(decision : String, rule : String, reason : String) -> Json {
  let effective = if decision == "deny" { "deny" } else { "allow" }
  json_obj([
    ("decision", json_str(effective)),
    ("policy_decision", json_str(decision)),
    ("rule", json_str(rule)),
    ("reason", json_str(reason)),
  ])
}

///|
/// Resolve a pending approval. Approving forwards the original request, so the
/// upstream server sees exactly one call; denying answers the client with a
/// policy error. Either way the pending entry is removed, which is what makes
/// a grant single-use.
pub fn resolve_approval(
  session : Session,
  call : String,
  approved : Bool,
  now : Int64,
) -> Array[Json] {
  let pending = match session.pending.get(call) {
    Some(pending) => pending
    None => return [action_notice("warn", "MoonGate: unknown approval \{call}")]
  }
  let _ = session.pending.remove(call)
  let actions : Array[Json] = []
  if now >= pending.expires {
    session.denied += 1
    let response = error_response(
      pending.id,
      -32002,
      "MoonGate: approval for \{pending.tool} expired",
      Some(
        json_obj([
          (
            "moongate",
            json_obj([
              ("decision", json_str("approval_timeout")),
              ("call", json_str(pending.call)),
              ("rule", json_str(pending.rule)),
            ]),
          ),
        ]),
      ),
    )
    actions.push(action_client(json_render(response)))
    actions.push(
      ledger_event(session, now, "approval", [
        ("call", json_str(pending.call)),
        ("tool", json_str(pending.tool)),
        ("decision", json_str("timeout")),
      ]),
    )
    return actions
  }
  if approved {
    if session.policy.budget.max_reveals > 0 &&
      session.reveal_count + pending.revealed >
      session.policy.budget.max_reveals {
      session.denied += 1
      let response = error_response(
        pending.id,
        -32001,
        "MoonGate: reveal budget exhausted",
        Some(
          json_obj([
            (
              "moongate",
              json_obj([
                ("decision", json_str("budget-reveals")),
                ("call", json_str(pending.call)),
              ]),
            ),
          ]),
        ),
      )
      actions.push(action_client(json_render(response)))
      actions.push(
        ledger_event(session, now, "approval", [
          ("call", json_str(pending.call)),
          ("tool", json_str(pending.tool)),
          ("decision", json_str("budget-denied")),
        ]),
      )
      return actions
    }
    session.reveal_count += pending.revealed
    session.allowed += 1
    session.forwarded += 1
    session.inflight.set(pending.key, {
      call: pending.call,
      tool: pending.tool,
      sensitive: pending.sensitive,
    })
    actions.push(action_upstream(pending.line))
    actions.push(
      json_obj([
        ("kind", json_str("approval_resolved")),
        ("call", json_str(pending.call)),
        ("approved", json_bool(true)),
      ]),
    )
    actions.push(
      ledger_event(session, now, "approval", [
        ("call", json_str(pending.call)),
        ("tool", json_str(pending.tool)),
        ("decision", json_str("granted")),
        ("digest", json_str(pending.digest)),
      ]),
    )
  } else {
    session.denied += 1
    let response = error_response(
      pending.id,
      -32001,
      "MoonGate: operator denied \{pending.tool}",
      Some(
        json_obj([
          (
            "moongate",
            json_obj([
              ("decision", json_str("approval_denied")),
              ("call", json_str(pending.call)),
              ("rule", json_str(pending.rule)),
            ]),
          ),
        ]),
      ),
    )
    actions.push(action_client(json_render(response)))
    actions.push(
      json_obj([
        ("kind", json_str("approval_resolved")),
        ("call", json_str(pending.call)),
        ("approved", json_bool(false)),
      ]),
    )
    actions.push(
      ledger_event(session, now, "approval", [
        ("call", json_str(pending.call)),
        ("tool", json_str(pending.tool)),
        ("decision", json_str("denied")),
      ]),
    )
  }
  actions
}

///|
/// Final ledger event: the counters the report reconciles against. Writing
/// them into the chain makes truncation detectable even without replaying the
/// whole run.
pub fn close_session(session : Session, now : Int64) -> Json {
  ledger_event(session, now, "session_close", [
    ("allowed", json_int(session.allowed)),
    ("denied", json_int(session.denied)),
    ("approval_requests", json_int(session.approval_requests)),
    ("forwarded", json_int(session.forwarded)),
    ("tainted_values", json_int(session.tainted_values)),
    ("total_calls", json_int(session.total_calls)),
    ("arg_bytes", json_i64(session.arg_bytes)),
    ("reveal_count", json_int(session.reveal_count)),
  ])
}

///|
/// Expire pending approvals. The host calls this on a timer; expired requests
/// get a policy error so the agent is never left waiting forever.
pub fn expire_approvals(session : Session, now : Int64) -> Array[Json] {
  let expired : Array[String] = []
  for call, pending in session.pending {
    if now >= pending.expires {
      expired.push(call)
    }
  }
  let actions : Array[Json] = []
  for call in expired {
    for action in resolve_approval(session, call, false, now) {
      actions.push(action)
    }
  }
  actions
}
