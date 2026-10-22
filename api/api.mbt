///|
/// JavaScript-facing surface.
///
/// Everything here is a thin adapter over the engine: JSON in, JSON out, no
/// policy logic. The host executable uses only these functions, which keeps the
/// trust boundary honest — the process that owns the pipes cannot make a
/// decision the engine did not make.

///|
let sessions : Array[@moongate.Session?] = []

///|
fn store_session(session : @moongate.Session) -> Int32 {
  let mut index = 0
  let mut slot = -1
  for entry in sessions {
    match entry {
      None => if slot < 0 { slot = index }
      Some(_) => ()
    }
    index += 1
  }
  if slot >= 0 {
    sessions[slot] = Some(session)
    slot
  } else {
    sessions.push(Some(session))
    sessions.length() - 1
  }
}

///|
fn session_at(handle : Int32) -> @moongate.Session? {
  if handle < 0 || handle >= sessions.length() {
    None
  } else {
    sessions[handle]
  }
}

///|
fn render_actions(actions : Array[Json]) -> String {
  @moongate.json_render(@moongate.json_arr(actions))
}

///|
fn failure(message : String) -> String {
  @moongate.json_render(
    @moongate.json_obj([
      ("ok", @moongate.json_bool(false)),
      ("error", @moongate.json_str(message)),
    ]),
  )
}

///|
/// Create a session from a policy document. Returns the handle, a summary of
/// the effective policy and the opening ledger entry.
pub fn create(
  policy_json : String,
  session_id : String,
  now_ms : Int64,
) -> String {
  let policy = @moongate.parse_policy(policy_json) catch {
    @moongate.PolicyError(message) => return failure(message)
  }
  let session = @moongate.new_session(session_id, policy)
  let handle = store_session(session)
  let open = @moongate.open_session(session, now_ms)
  @moongate.json_render(
    @moongate.json_obj([
      ("ok", @moongate.json_bool(true)),
      ("handle", @moongate.json_int(handle)),
      ("policy", policy_summary(session)),
      ("ledger", @moongate.json_arr([open])),
    ]),
  )
}

///|
fn policy_summary(session : @moongate.Session) -> Json {
  session_policy_summary(session)
}

///|
fn session_policy_summary(session : @moongate.Session) -> Json {
  let policy = session.policy
  let reveal_rules : Array[Json] = []
  for rule in policy.reveal {
    reveal_rules.push(
      @moongate.json_obj([
        ("id", @moongate.json_str(rule.id)),
        ("tool", @moongate.json_str(rule.tool)),
        ("conditional", @moongate.json_bool(!rule.checks.is_empty())),
      ]),
    )
  }
  let rules : Array[Json] = []
  for rule in policy.rules {
    rules.push(
      @moongate.json_obj([
        ("id", @moongate.json_str(rule.id)),
        ("tool", @moongate.json_str(rule.tool)),
        ("decision", @moongate.json_str(rule.decision)),
        ("conditional", @moongate.json_bool(!rule.checks.is_empty())),
        ("reason", @moongate.json_str(rule.reason)),
      ]),
    )
  }
  @moongate.json_obj([
    ("name", @moongate.json_str(policy.name)),
    ("digest", @moongate.json_str(policy.digest)),
    ("default", @moongate.json_str(policy.default_decision)),
    ("rules", @moongate.json_arr(rules)),
    ("egress_tools", @moongate.json_strings(policy.egress_tools)),
    ("on_taint", @moongate.json_str(policy.on_taint)),
    ("rule_count", @moongate.json_int(policy.rules.length())),
    ("sensitive_count", @moongate.json_int(policy.sensitive.length())),
    ("mask_secrets", @moongate.json_bool(policy.mask_secrets)),
    ("reveal_count", @moongate.json_int(policy.reveal.length())),
    ("reveal", @moongate.json_arr(reveal_rules)),
    (
      "budget",
      @moongate.json_obj([
        ("max_calls", @moongate.json_int(policy.budget.max_calls)),
        ("max_arg_bytes", @moongate.json_int(policy.budget.max_arg_bytes)),
        ("max_single_bytes", @moongate.json_int(policy.budget.max_single_bytes)),
        ("max_reveals", @moongate.json_int(policy.budget.max_reveals)),
      ]),
    ),
    ("rate_window_ms", @moongate.json_int(policy.rate.window_ms)),
    ("rate_max_calls", @moongate.json_int(policy.rate.max_calls)),
    ("approval_ttl_ms", @moongate.json_int(policy.approval_ttl_ms)),
    ("min_secret_len", @moongate.json_int(policy.min_secret_len)),
    ("hide_denied", @moongate.json_bool(policy.hide_denied)),
  ])
}

///|
pub fn client_line(handle : Int32, line : String, now_ms : Int64) -> String {
  match session_at(handle) {
    Some(session) =>
      render_actions(@moongate.client_line(session, line, now_ms))
    None => failure("unknown session handle")
  }
}

///|
pub fn server_line(handle : Int32, line : String, now_ms : Int64) -> String {
  match session_at(handle) {
    Some(session) =>
      render_actions(@moongate.server_line(session, line, now_ms))
    None => failure("unknown session handle")
  }
}

///|
pub fn resolve_approval(
  handle : Int32,
  call : String,
  approved : Bool,
  now_ms : Int64,
) -> String {
  match session_at(handle) {
    Some(session) =>
      render_actions(
        @moongate.resolve_approval(session, call, approved, now_ms),
      )
    None => failure("unknown session handle")
  }
}

///|
pub fn tick(handle : Int32, now_ms : Int64) -> String {
  match session_at(handle) {
    Some(session) => render_actions(@moongate.expire_approvals(session, now_ms))
    None => failure("unknown session handle")
  }
}

///|
let guards : Array[@moongate.Policy?] = []

///|
pub fn guard_create(policy_json : String) -> String {
  let policy = @moongate.parse_policy(policy_json) catch {
    @moongate.PolicyError(message) => return failure(message)
  }
  guards.push(Some(policy))
  @moongate.json_render(
    @moongate.json_obj([
      ("ok", @moongate.json_bool(true)),
      ("handle", @moongate.json_int(guards.length() - 1)),
      ("digest", @moongate.json_str(policy.digest)),
      ("rules", @moongate.json_int(policy.rules.length())),
    ]),
  )
}

///|
pub fn guard_check(handle : Int32, tool : String, args_json : String) -> String {
  let policy = if handle >= 0 && handle < guards.length() {
    guards[handle]
  } else {
    None
  }
  match policy {
    Some(policy) => {
      let args = match @moongate.json_parse_opt(args_json) {
        Some(value) => value
        None => return failure("arguments must be JSON")
      }
      @moongate.json_render(@moongate.guard_decision(policy, tool, args))
    }
    None => failure("unknown guard handle")
  }
}

///|
pub fn import_policy(source : String, format : String) -> String {
  if format != "moonpod" {
    return failure("unsupported policy format: " + format)
  }
  let policy = @moongate.import_moonpod(source) catch {
    @moongate.PolicyError(message) => return failure(message)
  }
  @moongate.json_render(
    @moongate.json_obj([("ok", @moongate.json_bool(true)), ("policy", policy)]),
  )
}

///|
pub fn close(handle : Int32, now_ms : Int64) -> String {
  match session_at(handle) {
    Some(session) => {
      let action = @moongate.close_session(session, now_ms)
      sessions[handle] = None
      @moongate.json_render(@moongate.json_arr([action]))
    }
    None => failure("unknown session handle")
  }
}

///|
fn parse_lines(source : String) -> Array[String]? {
  match @moongate.json_parse_opt(source) {
    Some(Array(items)) => {
      let lines : Array[String] = []
      for item in items {
        match item {
          String(line) => lines.push(line)
          _ => ()
        }
      }
      Some(lines)
    }
    _ => None
  }
}

///|
pub fn verify(lines_json : String) -> String {
  match parse_lines(lines_json) {
    Some(lines) => @moongate.json_render(@moongate.verify_ledger(lines))
    None => failure("expected a JSON array of ledger lines")
  }
}

///|
pub fn report(lines_json : String) -> String {
  match parse_lines(lines_json) {
    Some(lines) => @moongate.json_render(@moongate.report_ledger(lines))
    None => failure("expected a JSON array of ledger lines")
  }
}

///|
/// Validate a policy without creating a session; used by `moongate check`.
pub fn inspect(policy_json : String) -> String {
  let policy = @moongate.parse_policy(policy_json) catch {
    @moongate.PolicyError(message) => return failure(message)
  }
  let session = @moongate.new_session("inspect", policy)
  @moongate.json_render(
    @moongate.json_obj([
      ("ok", @moongate.json_bool(true)),
      ("policy", session_policy_summary(session)),
    ]),
  )
}

///|
pub fn version() -> String {
  @moongate.json_render(
    @moongate.json_obj([
      ("name", @moongate.json_str("moongate")),
      ("version", @moongate.json_str("0.6.0")),
      ("schema", @moongate.json_int(1)),
    ]),
  )
}
