///|
/// Ledger verification and reporting.
///
/// The ledger is the gateway's evidence: a JSONL stream where every entry
/// commits to the previous one. `verify_ledger` recomputes the chain, so a
/// reviewer can check that a run was not edited after the fact. `report_ledger`
/// turns the same stream into the aggregate a human reads: what ran, what was
/// blocked, and why.
pub fn verify_ledger(lines : Array[String]) -> Json {
  let mut prev = ""
  let mut index = 0
  for line in lines {
    if line.trim().is_empty() {
      continue
    }
    let event = match json_parse_opt(line) {
      Some(value) => value
      None =>
        return json_obj([
          ("ok", json_bool(false)),
          ("entries", json_int(index)),
          ("reason", json_str("entry \{index} is not valid JSON")),
        ])
    }
    let recorded_prev = match string_field(event, "prev") {
      Some(value) => value
      None => ""
    }
    let recorded_hash = match string_field(event, "hash") {
      Some(value) => value
      None => ""
    }
    if recorded_prev != prev {
      return json_obj([
        ("ok", json_bool(false)),
        ("entries", json_int(index)),
        ("reason", json_str("entry \{index} does not follow the previous hash")),
      ])
    }
    let body = match json_as_object(event) {
      Some(fields) => {
        let copy : Map[String, Json] = Map([])
        for key, value in fields {
          if key != "hash" {
            copy.set(key, value)
          }
        }
        Json::object(copy)
      }
      None =>
        return json_obj([
          ("ok", json_bool(false)),
          ("entries", json_int(index)),
          ("reason", json_str("entry \{index} is not an object")),
        ])
    }
    let expected = sha256_hex(prev + "\n" + json_canonical(body))
    if expected != recorded_hash {
      return json_obj([
        ("ok", json_bool(false)),
        ("entries", json_int(index)),
        ("reason", json_str("entry \{index} hash mismatch")),
      ])
    }
    prev = recorded_hash
    index += 1
  }
  json_obj([
    ("ok", json_bool(true)),
    ("entries", json_int(index)),
    ("head", json_str(prev)),
    ("reason", json_str("chain intact")),
  ])
}

///|
fn event_reason(event : Json) -> String {
  match string_field(event, "reason") {
    Some(reason) => reason
    None => ""
  }
}

///|
fn event_tool(event : Json) -> String {
  match string_field(event, "tool") {
    Some(tool) => tool
    None => ""
  }
}

///|
fn event_call(event : Json) -> String {
  match string_field(event, "call") {
    Some(call) => call
    None => ""
  }
}

///|
fn event_decision(event : Json) -> String {
  match string_field(event, "decision") {
    Some(decision) => decision
    None => ""
  }
}

///|
fn event_rule(event : Json) -> String {
  match string_field(event, "rule") {
    Some(rule) => rule
    None => ""
  }
}

///|
fn event_seq(event : Json) -> Int32 {
  match int_field(event, "seq") {
    Some(seq) => seq
    None => 0
  }
}

///|
fn event_ts(event : Json) -> Int64 {
  match json_get(event, "ts") {
    Some(Number(n, ..)) => n.to_int64()
    _ => 0L
  }
}

///|
pub fn report_ledger(lines : Array[String]) -> Json {
  let mut allowed = 0
  let mut denied = 0
  let mut approval_requests = 0
  let mut granted = 0
  let mut rejected = 0
  let mut results = 0
  let mut result_bytes = 0
  let mut new_values = 0
  let mut entries = 0
  let mut policy_name = ""
  let mut policy_digest = ""
  let blocked : Array[Json] = []
  let timeline : Array[Json] = []
  for line in lines {
    if line.trim().is_empty() {
      continue
    }
    let event = match json_parse_opt(line) {
      Some(value) => value
      None => continue
    }
    entries += 1
    let kind = match string_field(event, "kind") {
      Some(kind) => kind
      None => ""
    }
    if kind == "session_open" {
      policy_name = match string_field(event, "policy") {
        Some(name) => name
        None => ""
      }
      policy_digest = match string_field(event, "policy_digest") {
        Some(digest) => digest
        None => ""
      }
    }
    if kind == "decision" {
      match event_decision(event) {
        "allow" => allowed += 1
        "approval" => approval_requests += 1
        "deny" => {
          denied += 1
          let evidence = match json_get(event, "evidence") {
            Some(Array(items)) => items.length()
            _ => 0
          }
          blocked.push(
            json_obj([
              ("seq", json_int(event_seq(event))),
              ("ts", json_i64(event_ts(event))),
              ("tool", json_str(event_tool(event))),
              ("call", json_str(event_call(event))),
              ("rule", json_str(event_rule(event))),
              ("reason", json_str(event_reason(event))),
              ("evidence", json_int(evidence)),
            ]),
          )
        }
        _ => ()
      }
    }
    if kind == "approval" {
      match event_decision(event) {
        "granted" => granted += 1
        "denied" | "timeout" => rejected += 1
        _ => ()
      }
    }
    if kind == "result" {
      results += 1
      result_bytes += match int_field(event, "bytes") {
        Some(bytes) => bytes
        None => 0
      }
      new_values += match int_field(event, "new_values") {
        Some(count) => count
        None => 0
      }
    }
    timeline.push(
      json_obj([
        ("seq", json_int(event_seq(event))),
        ("ts", json_i64(event_ts(event))),
        ("kind", json_str(kind)),
        ("tool", json_str(event_tool(event))),
        ("call", json_str(event_call(event))),
        ("decision", json_str(event_decision(event))),
        ("rule", json_str(event_rule(event))),
        ("reason", json_str(event_reason(event))),
      ]),
    )
  }
  json_obj([
    ("entries", json_int(entries)),
    (
      "policy",
      json_obj([
        ("name", json_str(policy_name)),
        ("digest", json_str(policy_digest)),
      ]),
    ),
    (
      "decisions",
      json_obj([
        ("allow", json_int(allowed)),
        ("deny", json_int(denied)),
        ("approval_required", json_int(approval_requests)),
        ("executed", json_int(allowed + granted)),
      ]),
    ),
    (
      "approvals",
      json_obj([
        ("granted", json_int(granted)),
        ("rejected", json_int(rejected)),
      ]),
    ),
    (
      "results",
      json_obj([
        ("count", json_int(results)),
        ("bytes", json_int(result_bytes)),
        ("new_sensitive_values", json_int(new_values)),
      ]),
    ),
    ("blocked", json_arr(blocked)),
    ("timeline", json_arr(timeline)),
    ("chain", verify_ledger(lines)),
  ])
}
