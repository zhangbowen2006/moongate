///|
fn pod_rejects(source : String) -> Bool {
  try {
    let _ = import_moonpod(source)
    false
  } catch {
    _ => true
  }
}

///|
test "imports a MoonPod policy into a MoonGate policy" {
  let source =
    #|{"schema_version":1,
    #| "allowed_tools":["fs.read","fs.write","net.connect","ticket.create"],
    #| "read_roots":["workspace"],
    #| "write_roots":["reports"],
    #| "protected_paths":["secrets"],
    #| "network_rules":[{"host":"api.internal","allowed_ports":[443]}],
    #| "approval_required_tools":["fs.write"],
    #| "max_calls":25,
    #| "max_operation_bytes":4096}
  let imported = import_moonpod(source) catch {
    PolicyError(message) => abort(message)
  }
  let policy = parse_policy(json_render(imported)) catch {
    PolicyError(message) => abort(message)
  }
  inspect(policy.default_decision, content="deny")
  inspect(policy.budget.max_calls, content="25")
  inspect(policy.budget.max_single_bytes, content="4096")
  inspect(policy.rules.length(), content="6")
  inspect(policy.rules[0].id, content="pod-protected-0")
  inspect(policy.rules[0].decision, content="deny")
  inspect(policy.rules[1].id, content="pod-approval-0")
  inspect(policy.rules[1].decision, content="approval")
  inspect(policy.rules[2].id, content="pod-read-0")
  inspect(policy.rules[2].tool, content="fs.read")
  inspect(policy.rules[4].tool, content="net.*")
}

///|
test "unsupported MoonPod features fail closed" {
  let quotas =
    #|{"schema_version":1,"allowed_tools":["fs.read"],"tool_quotas":[{"tool":"fs.read","max_calls":1}]}
  let resources =
    #|{"schema_version":1,"allowed_tools":["fs.read"],"resource_rules":[{"tool":"x","action":"y","resource_prefix":"z"}]}
  let commands =
    #|{"schema_version":1,"allowed_tools":["process.run"]}
  let io_bytes =
    #|{"schema_version":1,"allowed_tools":["fs.read"],"max_io_bytes":1024}
  let typo =
    #|{"schema_version":1,"allowed_tools":["fs.read"],"typo_field":true}
  let version =
    #|{"schema_version":2,"allowed_tools":["fs.read"]}
  for source in [quotas, resources, commands, io_bytes, typo, version] {
    inspect(pod_rejects(source), content="true")
  }
}

///|
test "zero limits deny every call instead of becoming unlimited" {
  let source =
    #|{"schema_version":1,"allowed_tools":["fs.read"],"max_calls":0}
  let imported = import_moonpod(source) catch {
    PolicyError(message) => abort(message)
  }
  let policy = parse_policy(json_render(imported)) catch {
    PolicyError(message) => abort(message)
  }
  let last = policy.rules[policy.rules.length() - 1]
  inspect(last.decision, content="deny")
  inspect(last.tool, content="*")
}
