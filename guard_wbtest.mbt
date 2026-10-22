///|
test "paths are normalized lexically before matching" {
  inspect(normalize_path("reports/../../etc/passwd"), content="../etc/passwd")
  inspect(normalize_path("./notes//todo.md"), content="notes/todo.md")
  inspect(normalize_path("C:\\Windows\\win.ini"), content="C:/Windows/win.ini")
  inspect(normalize_path("/etc/../shadow"), content="/shadow")
  inspect(normalize_path("a/b/../c"), content="a/c")
  inspect(normalize_path(".."), content="..")
  inspect(normalize_path("."), content="")
}

///|
test "normalization closes the prefix-rule bypass" {
  let policy = parse_policy(
    (
      #|{"version":1,"rules":[
      #|  {"id":"allow-workspace","tool":"fs.*","decision":"allow",
      #|   "when":[{"arg":"path","normalize":"path","prefix":["..","/","C:/"],"negate":true}]}
      #|]}
    ),
  ) catch {
    _ => abort("bad policy")
  }
  let traversal = Json::object(
    Map([("path", json_str("reports/../../etc/passwd"))]),
  )
  let inside = Json::object(
    Map([("path", json_str("./reports/../notes/a.md"))]),
  )
  // Without normalization the first path starts with "reports/" and would pass.
  inspect(
    guard_option_some(match_rule(policy, "fs.read", traversal)),
    content="false",
  )
  inspect(
    guard_option_some(match_rule(policy, "fs.read", inside)),
    content="true",
  )
}

///|
test "guard enforces hard denials and defers approvals" {
  let policy = parse_policy(
    (
      #|{"version":1,"default_decision":"deny","rules":[
      #|  {"id":"read","tool":"fs.read","decision":"allow"},
      #|  {"id":"write","tool":"fs.write","decision":"approval"},
      #|  {"id":"no-delete","tool":"fs.delete","decision":"deny"}
      #|]}
    ),
  ) catch {
    _ => abort("bad policy")
  }
  let empty = Json::object(Map([]))
  let denied = guard_decision(policy, "fs.delete", empty)
  inspect(string_field(denied, "decision") == Some("deny"), content="true")
  inspect(string_field(denied, "rule") == Some("no-delete"), content="true")
  let deferred = guard_decision(policy, "fs.write", empty)
  inspect(string_field(deferred, "decision") == Some("allow"), content="true")
  inspect(
    string_field(deferred, "policy_decision") == Some("approval"),
    content="true",
  )
  let unknown = guard_decision(policy, "mail.send", empty)
  inspect(string_field(unknown, "decision") == Some("deny"), content="true")
  inspect(string_field(unknown, "rule") == Some("default"), content="true")
}

///|
fn[T] guard_option_some(value : T?) -> Bool {
  match value {
    Some(_) => true
    None => false
  }
}
