///|
fn[T] option_is_some(value : T?) -> Bool {
  match value {
    Some(_) => true
    None => false
  }
}

///|
test "policy parses the documented shape and fingerprints its content" {
  let policy = parse_policy(
    (
      #|{
      #|  "version": 1,
      #|  "name": "workspace",
      #|  "default_decision": "deny",
      #|  "rules": [
      #|    { "id": "read", "tool": "fs.read", "decision": "allow" },
      #|    { "id": "write", "tool": "fs.write", "decision": "approval", "approval_ttl_ms": 30000 }
      #|  ],
      #|  "egress": { "tools": ["net.*"], "on_taint": "deny" },
      #|  "sensitive": [{ "tool": "fs.read", "when": [{ "arg": "path", "glob": ["**/*.env"] }] }],
      #|  "rate": { "window_ms": 60000, "max_calls": 12 },
      #|  "min_secret_len": 10
      #|}
    ),
  ) catch {
    _ => abort("policy should parse")
  }
  inspect(policy.name, content="workspace")
  inspect(policy.rules.length(), content="2")
  inspect(policy.default_decision, content="deny")
  inspect(policy.rate.max_calls, content="12")
  inspect(policy.min_secret_len, content="10")
  inspect(policy.on_taint, content="deny")
  inspect(policy.digest.length(), content="64")
  // Content hash, not file name: two semantically identical policies built
  // with different whitespace share a digest.
  let again = parse_policy(
    (
      #|{"version":1,"name":"workspace","default_decision":"deny","rules":[{"id":"read","tool":"fs.read","decision":"allow"},{"id":"write","tool":"fs.write","decision":"approval","approval_ttl_ms":30000}],"egress":{"tools":["net.*"],"on_taint":"deny"},"sensitive":[{"tool":"fs.read","when":[{"arg":"path","glob":["**/*.env"]}]}],"rate":{"window_ms":60000,"max_calls":12},"min_secret_len":10}
    ),
  ) catch {
    _ => abort("policy should parse")
  }
  inspect(policy.digest == again.digest, content="true")
}

///|
test "policy rejects unsafe or ambiguous documents" {
  let cases : Array[(String, String)] = [
    ("{\"version\":1,\"default_decision\":\"maybe\"}", "default_decision"),
    (
      "{\"version\":1,\"rules\":[{\"id\":\"a\",\"tool\":\"x\",\"decision\":\"allow\"},{\"id\":\"a\",\"tool\":\"y\",\"decision\":\"deny\"}]}",
      "duplicate rule id",
    ),
    (
      "{\"version\":1,\"rules\":[{\"id\":\"a\",\"tool\":\"x\",\"decision\":\"block\"}]}",
      "decision",
    ),
    (
      "{\"version\":1,\"rules\":[{\"id\":\"a\",\"decision\":\"allow\"}]}", "tool",
    ),
    ("{\"version\":1,\"rate\":{\"window_ms\":10,\"max_calls\":0}}", "max_calls"),
    (
      "{\"version\":1,\"egress\":{\"tools\":[\"net.*\"],\"on_taint\":\"log\"}}",
      "on_taint",
    ),
  ]
  for item in cases {
    let rejected = try {
      let _ = parse_policy(item.0)
      false
    } catch {
      _ => true
    }
    inspect(rejected, content="true")
  }
}

///|
test "first matching rule wins, order is the author's contract" {
  let broad_first = parse_policy(
    (
      #|{"version":1,"rules":[
      #|  {"id":"allow-all","tool":"fs.*","decision":"allow"},
      #|  {"id":"deny-delete","tool":"fs.delete","decision":"deny"}
      #|]}
    ),
  ) catch {
    _ => abort("bad policy")
  }
  let narrow_first = parse_policy(
    (
      #|{"version":1,"rules":[
      #|  {"id":"deny-delete","tool":"fs.delete","decision":"deny"},
      #|  {"id":"allow-all","tool":"fs.*","decision":"allow"}
      #|]}
    ),
  ) catch {
    _ => abort("bad policy")
  }
  let empty = Json::object(Map([]))
  let broad_id = match match_rule(broad_first, "fs.delete", empty) {
    Some(hit) => hit.id
    None => ""
  }
  inspect(broad_id, content="allow-all")
  let narrow_decision = match match_rule(narrow_first, "fs.delete", empty) {
    Some(hit) => hit.decision
    None => ""
  }
  inspect(narrow_decision, content="deny")
}

///|
test "argument checks support globs, prefixes and negation" {
  let policy = parse_policy(
    (
      #|{"version":1,"rules":[
      #|  {"id":"report-write","tool":"fs.write","decision":"allow",
      #|   "when":[{"arg":"path","glob":["reports/*","reports/**"]}]},
      #|  {"id":"local-read","tool":"fs.read","decision":"allow",
      #|   "when":[{"arg":"path","prefix":["..","/"],"negate":true}]}
      #|]}
    ),
  ) catch {
    _ => abort("bad policy")
  }
  let write = Json::object(Map([("path", json_str("reports/q3/summary.md"))]))
  let outside = Json::object(Map([("path", json_str("src/main.mbt"))]))
  let escape = Json::object(Map([("path", json_str("../secrets.txt"))]))
  inspect(option_is_some(match_rule(policy, "fs.write", write)), content="true")
  inspect(
    option_is_some(match_rule(policy, "fs.write", outside)),
    content="false",
  )
  inspect(
    option_is_some(match_rule(policy, "fs.read", escape)),
    content="false",
  )
}

///|
test "advertised tools follow unconditional denials, not default alone" {
  let policy = parse_policy(
    (
      #|{"version":1,"default_decision":"deny","rules":[
      #|  {"id":"deny-delete","tool":"fs.delete","decision":"deny"},
      #|  {"id":"scoped-read","tool":"fs.read","decision":"allow",
      #|   "when":[{"arg":"path","glob":["reports/*"]}]}
      #|]}
    ),
  ) catch {
    _ => abort("bad policy")
  }
  inspect(advertise_tool(policy, "fs.delete"), content="false")
  // Conditional allow: the tool is usable for some arguments, so hiding it
  // would remove a capability the policy explicitly grants.
  inspect(advertise_tool(policy, "fs.read"), content="true")
  // Nothing matches and the default is deny: not advertised.
  inspect(advertise_tool(policy, "mail.send"), content="false")
}

///|
test "sensitive sources and egress tools are matched by glob" {
  let policy = parse_policy(
    (
      #|{"version":1,"egress":{"tools":["net.*","mail.send"]},
      #| "sensitive":[{"tool":"fs.read","when":[{"arg":"path","glob":["**/*.env"]}]},{"tool":"vault.read"}]}
    ),
  ) catch {
    _ => abort("bad policy")
  }
  inspect(is_egress(policy, "net.post"), content="true")
  inspect(is_egress(policy, "mail.send"), content="true")
  inspect(is_egress(policy, "fs.read"), content="false")
  inspect(
    is_sensitive(
      policy,
      "fs.read",
      Json::object(Map([("path", json_str("config/.env"))])),
    ),
    content="true",
  )
  inspect(
    is_sensitive(
      policy,
      "fs.read",
      Json::object(Map([("path", json_str("notes/todo.md"))])),
    ),
    content="false",
  )
  inspect(
    is_sensitive(policy, "vault.read", Json::object(Map([]))),
    content="true",
  )
}
