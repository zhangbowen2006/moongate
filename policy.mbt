///|
/// Policy model.
///
/// A policy is a small, declarative document with five independent controls:
///
/// 1. `rules` decide per tool call (allow / deny / approval), first match wins.
/// 2. `egress` blocks outbound tools whose arguments carry values that earlier
///    tool results marked sensitive.
/// 3. `sensitive` declares which tool results should be fingerprinted.
/// 4. `rate` caps how many tool calls a session may attempt per window.
/// 5. `advertise` decides whether tools the policy denies are hidden from
///    `tools/list` (so the agent never plans around them).
///
/// Rule order is meaningful on purpose: a firewall-style first-match model is
/// easier to reason about than "most specific wins", and the linter in
/// `docs/POLICY.md` shows how to order rules so broad grants do not shadow
/// narrow denials.
pub struct ArgCheck {
  arg : String
  globs : Array[String]
  prefixes : Array[String]
  negate : Bool
}

///|
pub struct Rule {
  id : String
  tool : String
  decision : String
  reason : String
  checks : Array[ArgCheck]
  approval_ttl_ms : Int32
}

///|
pub struct SensitiveRule {
  id : String
  tool : String
  checks : Array[ArgCheck]
}

///|
pub struct RateLimit {
  window_ms : Int32
  max_calls : Int32
}

///|
pub struct Policy {
  name : String
  digest : String
  default_decision : String
  rules : Array[Rule]
  sensitive : Array[SensitiveRule]
  egress_tools : Array[String]
  on_taint : String
  rate : RateLimit
  approval_ttl_ms : Int32
  min_secret_len : Int32
  hide_denied : Bool
}

///|
pub suberror PolicyError {
  PolicyError(String)
}

///|
fn[T] policy_fail(message : String) -> T raise PolicyError {
  raise PolicyError(message)
}

///|
fn policy_text(
  fields : Map[String, Json],
  key : String,
  path : String,
) -> String raise PolicyError {
  match fields.get(key) {
    Some(String(s)) => s
    Some(_) => policy_fail("\{path}.\{key}: expected string")
    None => policy_fail("\{path}.\{key}: required")
  }
}

///|
fn policy_optional_text(
  fields : Map[String, Json],
  key : String,
  fallback : String,
) -> String {
  match fields.get(key) {
    Some(String(s)) => s
    _ => fallback
  }
}

///|
fn policy_int(
  fields : Map[String, Json],
  key : String,
  path : String,
  fallback? : Int32,
  min? : Int32,
  max? : Int32,
) -> Int32 raise PolicyError {
  let value = match fields.get(key) {
    Some(Number(n, ..)) =>
      if n != n.to_int().to_double() {
        policy_fail("\{path}.\{key}: expected integer")
      } else {
        n.to_int()
      }
    Some(_) => policy_fail("\{path}.\{key}: expected integer")
    None =>
      match fallback {
        Some(v) => v
        None => policy_fail("\{path}.\{key}: required")
      }
  }
  match min {
    Some(low) =>
      if value < low {
        policy_fail("\{path}.\{key}: must be >= \{low}")
      }
    None => ()
  }
  match max {
    Some(high) =>
      if value > high {
        policy_fail("\{path}.\{key}: must be <= \{high}")
      }
    None => ()
  }
  value
}

///|
fn policy_bool(
  fields : Map[String, Json],
  key : String,
  fallback : Bool,
) -> Bool {
  match fields.get(key) {
    Some(True) => true
    Some(False) => false
    _ => fallback
  }
}

///|
fn policy_array(fields : Map[String, Json], key : String) -> Array[Json] {
  match fields.get(key) {
    Some(Array(items)) => items
    _ => []
  }
}

///|
fn parse_checks(
  value : Json,
  path : String,
) -> Array[ArgCheck] raise PolicyError {
  let items = match value {
    Array(items) => items
    _ => policy_fail("\{path}: expected array")
  }
  let checks : Array[ArgCheck] = []
  for item in items {
    match item {
      Object(fields) => {
        let arg = policy_text(fields, "arg", path)
        if arg.is_empty() || arg.length() > 128 {
          policy_fail("\{path}.arg: expected 1..128 characters")
        }
        let globs = string_array(
          match fields.get("glob") {
            Some(v) => v
            None => Json::array([])
          },
        )
        let prefixes = string_array(
          match fields.get("prefix") {
            Some(v) => v
            None => Json::array([])
          },
        )
        if globs.is_empty() && prefixes.is_empty() {
          policy_fail("\{path}: each check needs a glob or prefix list")
        }
        checks.push({
          arg,
          globs,
          prefixes,
          negate: policy_bool(fields, "negate", false),
        })
      }
      _ => policy_fail("\{path}: expected object")
    }
  }
  checks
}

///|
fn parse_rule(value : Json, index : Int32) -> Rule raise PolicyError {
  let path = "rules[\{index}]"
  match value {
    Object(fields) => {
      let id = policy_text(fields, "id", path)
      if id.is_empty() || id.length() > 64 {
        policy_fail("\{path}.id: expected 1..64 characters")
      }
      let tool = policy_text(fields, "tool", path)
      if tool.is_empty() || tool.length() > 200 {
        policy_fail("\{path}.tool: expected 1..200 characters")
      }
      let decision = policy_text(fields, "decision", path)
      if decision != "allow" && decision != "deny" && decision != "approval" {
        policy_fail("\{path}.decision: expected allow, deny or approval")
      }
      let checks = match fields.get("when") {
        Some(v) => parse_checks(v, "\{path}.when")
        None => []
      }
      {
        id,
        tool,
        decision,
        reason: policy_optional_text(fields, "reason", ""),
        checks,
        approval_ttl_ms: policy_int(
          fields,
          "approval_ttl_ms",
          path,
          fallback=45000,
          min=1000,
          max=86400000,
        ),
      }
    }
    _ => policy_fail("\{path}: expected object")
  }
}

///|
fn parse_sensitive(
  value : Json,
  index : Int32,
) -> SensitiveRule raise PolicyError {
  let path = "sensitive[\{index}]"
  match value {
    Object(fields) => {
      let tool = policy_text(fields, "tool", path)
      let checks = match fields.get("when") {
        Some(v) => parse_checks(v, "\{path}.when")
        None => []
      }
      {
        id: policy_optional_text(fields, "id", "sensitive-\{index}"),
        tool,
        checks,
      }
    }
    _ => policy_fail("\{path}: expected object")
  }
}

///|
/// Parse and validate a policy document. Every rejection carries the JSON
/// path of the offending field; no input value is echoed back, because policy
/// files may contain internal tool names that should not end up in logs.
pub fn parse_policy(text : String) -> Policy raise PolicyError {
  let root = match json_parse_opt(text) {
    Some(value) => value
    None => policy_fail("policy: invalid JSON")
  }
  if json_depth(root) > 8 {
    policy_fail("policy: nesting deeper than 8 levels")
  }
  let fields = match root {
    Object(fields) => fields
    _ => policy_fail("policy: expected object")
  }
  let version = policy_int(
    fields,
    "version",
    "policy",
    fallback=1,
    min=1,
    max=1,
  )
  let _ = version
  let default_decision = policy_optional_text(
    fields, "default_decision", "deny",
  )
  if default_decision != "allow" && default_decision != "deny" {
    policy_fail("policy.default_decision: expected allow or deny")
  }
  let rule_items = policy_array(fields, "rules")
  if rule_items.length() > 128 {
    policy_fail("policy.rules: at most 128 rules")
  }
  let rules : Array[Rule] = []
  let seen : Map[String, Bool] = Map([])
  for i, item in rule_items {
    let rule = parse_rule(item, i)
    if seen.contains(rule.id) {
      policy_fail("policy.rules[\{i}].id: duplicate rule id")
    }
    seen.set(rule.id, true)
    rules.push(rule)
  }
  let sensitive_items = policy_array(fields, "sensitive")
  if sensitive_items.length() > 64 {
    policy_fail("policy.sensitive: at most 64 entries")
  }
  let sensitive : Array[SensitiveRule] = []
  for i, item in sensitive_items {
    sensitive.push(parse_sensitive(item, i))
  }
  let egress_tools : Array[String] = []
  let mut on_taint = "deny"
  match fields.get("egress") {
    Some(Object(egress)) => {
      for
        tool in string_array(
          match egress.get("tools") {
            Some(v) => v
            None => Json::array([])
          },
        ) {
        if tool.is_empty() || tool.length() > 200 {
          policy_fail("policy.egress.tools: expected 1..200 characters")
        }
        egress_tools.push(tool)
      }
      on_taint = policy_optional_text(egress, "on_taint", "deny")
      if on_taint != "deny" && on_taint != "approval" {
        policy_fail("policy.egress.on_taint: expected deny or approval")
      }
    }
    Some(_) => policy_fail("policy.egress: expected object")
    None => ()
  }
  let mut rate_window = 60000
  let mut rate_max = 60
  match fields.get("rate") {
    Some(Object(rate)) => {
      rate_window = policy_int(
        rate,
        "window_ms",
        "policy.rate",
        fallback=60000,
        min=1000,
        max=86400000,
      )
      rate_max = policy_int(
        rate,
        "max_calls",
        "policy.rate",
        fallback=60,
        min=1,
        max=100000,
      )
    }
    Some(_) => policy_fail("policy.rate: expected object")
    None => ()
  }
  {
    name: policy_optional_text(fields, "name", "unnamed"),
    digest: sha256_hex(json_canonical(root)),
    default_decision,
    rules,
    sensitive,
    egress_tools,
    on_taint,
    rate: { window_ms: rate_window, max_calls: rate_max, },
    approval_ttl_ms: policy_int(
      fields,
      "approval_ttl_ms",
      "policy",
      fallback=45000,
      min=1000,
      max=86400000,
    ),
    min_secret_len: policy_int(
      fields,
      "min_secret_len",
      "policy",
      fallback=12,
      min=6,
      max=128,
    ),
    hide_denied: policy_bool(fields, "hide_denied", true),
  }
}

///|
/// Evaluate one `when` clause against the call arguments.
fn check_matches(check : ArgCheck, args : Json) -> Bool {
  let value = match json_get(args, check.arg) {
    Some(String(s)) => s
    Some(other) => json_render(other)
    None => ""
  }
  let mut hit = false
  for glob in check.globs {
    if glob_match(glob, value) {
      hit = true
    }
  }
  for prefix in check.prefixes {
    if value.has_prefix(prefix) {
      hit = true
    }
  }
  if check.negate {
    !hit
  } else {
    hit
  }
}

///|
pub fn checks_match(checks : Array[ArgCheck], args : Json) -> Bool {
  for check in checks {
    if !check_matches(check, args) {
      return false
    }
  }
  true
}

///|
pub struct RuleHit {
  id : String
  decision : String
  reason : String
  ttl_ms : Int32
}

///|
/// First matching rule wins. Returns `None` when no rule matches, leaving the
/// decision to `default_decision`.
pub fn match_rule(policy : Policy, tool : String, args : Json) -> RuleHit? {
  for rule in policy.rules {
    if glob_match(rule.tool, tool) && checks_match(rule.checks, args) {
      return Some({
        id: rule.id,
        decision: rule.decision,
        reason: rule.reason,
        ttl_ms: rule.approval_ttl_ms,
      })
    }
  }
  None
}

///|
/// Whether a tool result must be fingerprinted. Sensitive sources are matched
/// against the same arguments that were sent to the tool.
pub fn is_sensitive(policy : Policy, tool : String, args : Json) -> Bool {
  for rule in policy.sensitive {
    if glob_match(rule.tool, tool) && checks_match(rule.checks, args) {
      return true
    }
  }
  false
}

///|
/// Whether a tool can carry data outside the trust boundary.
pub fn is_egress(policy : Policy, tool : String) -> Bool {
  any_glob(policy.egress_tools, tool)
}
