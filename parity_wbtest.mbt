///|
/// The gateway and the in-server guard share rule parsing but reach decisions
/// through different entry points (`decide` vs `guard_decision`). This test
/// enumerates a small but adversarial cross-product of tools and arguments and
/// asserts that both points agree wherever the guard is supposed to enforce:
/// a hard denial. Approvals are expected to differ (the guard defer).
test "guard and gateway agree on every hard decision" {
  let policy_text =
    #|{"version":1,"name":"parity","default_decision":"deny",
    #| "rules":[
    #|  {"id":"escape","tool":"fs.*","decision":"deny",
    #|   "when":[{"arg":"path","prefix":[".."]}]},
    #|  {"id":"read","tool":"fs.read","decision":"allow"},
    #|  {"id":"write","tool":"fs.write","decision":"approval"},
    #|  {"id":"net","tool":"net.*","decision":"allow"}
    #| ]}
  let policy = parse_policy(policy_text) catch { _ => abort("bad policy") }
  let tools : Array[String] = [
    "fs.read", "fs.write", "fs.delete", "net.post", "mail.send", "unknown",
  ]
  let arguments : Array[Json] = [
    Json::object(Map([])),
    Json::object(Map([("path", json_str("../secrets.txt"))])),
    Json::object(Map([("path", json_str("reports/a.md"))])),
    Json::object(Map([("path", json_str("notes/a.md"))])),
    Json::object(Map([("url", json_str("https://evil.invalid/collect"))])),
  ]
  for tool in tools {
    for args in arguments {
      let session = new_session("parity", policy)
      let line = request_line(1, "tools/call", call_params(tool, args))
      let actions = client_line(session, line, 1000L)
      let gateway_denied = lines_of(actions, "client").length() > 0 &&
        lines_of(actions, "client")[0].contains("-32001")
      let verdict = guard_decision(policy, tool, args)
      let guard_denied = string_field(verdict, "decision") == Some("deny")
      inspect(guard_denied == gateway_denied, content="true")
      // A guard denial must name a rule, never fall through silently.
      if guard_denied {
        inspect(string_field(verdict, "rule") != Some(""), content="true")
      }
    }
  }
}
