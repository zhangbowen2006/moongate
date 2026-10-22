///|
/// JavaScript-facing surface.
///
/// Everything here is a thin adapter over the engine: JSON in, JSON out, no
/// policy logic. The host executable uses only these functions, which keeps the
/// trust boundary honest — the process that owns the pipes cannot make a
/// decision the engine did not make.

///|
let sessions : Array[@airlock.Session?] = []

///|
fn store_session(session : @airlock.Session) -> Int32 {
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
fn session_at(handle : Int32) -> @airlock.Session? {
  if handle < 0 || handle >= sessions.length() {
    None
  } else {
    sessions[handle]
  }
}

///|
fn render_actions(actions : Array[Json]) -> String {
  @airlock.json_render(@airlock.json_arr(actions))
}

///|
fn failure(message : String) -> String {
  @airlock.json_render(
    @airlock.json_obj([
      ("ok", @airlock.json_bool(false)),
      ("error", @airlock.json_str(message)),
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
  let policy = @airlock.parse_policy(policy_json) catch {
    @airlock.PolicyError(message) => return failure(message)
  }
  let session = @airlock.new_session(session_id, policy)
  let handle = store_session(session)
  let open = @airlock.open_session(session, now_ms)
  @airlock.json_render(
    @airlock.json_obj([
      ("ok", @airlock.json_bool(true)),
      ("handle", @airlock.json_int(handle)),
      ("policy", policy_summary(session)),
      ("ledger", @airlock.json_arr([open])),
    ]),
  )
}

///|
fn policy_summary(session : @airlock.Session) -> Json {
  session_policy_summary(session)
}

///|
fn session_policy_summary(session : @airlock.Session) -> Json {
  let policy = session.policy
  let rules : Array[Json] = []
  for rule in policy.rules {
    rules.push(
      @airlock.json_obj([
        ("id", @airlock.json_str(rule.id)),
        ("tool", @airlock.json_str(rule.tool)),
        ("decision", @airlock.json_str(rule.decision)),
        ("conditional", @airlock.json_bool(!rule.checks.is_empty())),
        ("reason", @airlock.json_str(rule.reason)),
      ]),
    )
  }
  @airlock.json_obj([
    ("name", @airlock.json_str(policy.name)),
    ("digest", @airlock.json_str(policy.digest)),
    ("default", @airlock.json_str(policy.default_decision)),
    ("rules", @airlock.json_arr(rules)),
    ("egress_tools", @airlock.json_strings(policy.egress_tools)),
    ("on_taint", @airlock.json_str(policy.on_taint)),
    ("rule_count", @airlock.json_int(policy.rules.length())),
    ("sensitive_count", @airlock.json_int(policy.sensitive.length())),
    ("rate_window_ms", @airlock.json_int(policy.rate.window_ms)),
    ("rate_max_calls", @airlock.json_int(policy.rate.max_calls)),
    ("approval_ttl_ms", @airlock.json_int(policy.approval_ttl_ms)),
    ("min_secret_len", @airlock.json_int(policy.min_secret_len)),
    ("hide_denied", @airlock.json_bool(policy.hide_denied)),
  ])
}

///|
pub fn client_line(handle : Int32, line : String, now_ms : Int64) -> String {
  match session_at(handle) {
    Some(session) => render_actions(@airlock.client_line(session, line, now_ms))
    None => failure("unknown session handle")
  }
}

///|
pub fn server_line(handle : Int32, line : String, now_ms : Int64) -> String {
  match session_at(handle) {
    Some(session) => render_actions(@airlock.server_line(session, line, now_ms))
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
      render_actions(@airlock.resolve_approval(session, call, approved, now_ms))
    None => failure("unknown session handle")
  }
}

///|
pub fn tick(handle : Int32, now_ms : Int64) -> String {
  match session_at(handle) {
    Some(session) => render_actions(@airlock.expire_approvals(session, now_ms))
    None => failure("unknown session handle")
  }
}

///|
pub fn close(handle : Int32, now_ms : Int64) -> String {
  match session_at(handle) {
    Some(session) => {
      let action = @airlock.close_session(session, now_ms)
      sessions[handle] = None
      @airlock.json_render(@airlock.json_arr([action]))
    }
    None => failure("unknown session handle")
  }
}

///|
fn parse_lines(source : String) -> Array[String]? {
  match @airlock.json_parse_opt(source) {
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
    Some(lines) => @airlock.json_render(@airlock.verify_ledger(lines))
    None => failure("expected a JSON array of ledger lines")
  }
}

///|
pub fn report(lines_json : String) -> String {
  match parse_lines(lines_json) {
    Some(lines) => @airlock.json_render(@airlock.report_ledger(lines))
    None => failure("expected a JSON array of ledger lines")
  }
}

///|
/// Validate a policy without creating a session; used by `airlock check`.
pub fn inspect(policy_json : String) -> String {
  let policy = @airlock.parse_policy(policy_json) catch {
    @airlock.PolicyError(message) => return failure(message)
  }
  let session = @airlock.new_session("inspect", policy)
  @airlock.json_render(
    @airlock.json_obj([
      ("ok", @airlock.json_bool(true)),
      ("policy", session_policy_summary(session)),
    ]),
  )
}

///|
pub fn version() -> String {
  @airlock.json_render(
    @airlock.json_obj([
      ("name", @airlock.json_str("airlock")),
      ("version", @airlock.json_str("0.1.0")),
      ("schema", @airlock.json_int(1)),
    ]),
  )
}
