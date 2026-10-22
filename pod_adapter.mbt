///|
/// Importer for MoonPod (`yadidyc/moonpod@0.2.0`) JSON policies.
///
/// MoonPod is a transport-neutral policy core; MoonGate is the MCP enforcement
/// runtime. This adapter lets a MoonPod policy be reused at the MCP boundary.
/// It is a compatibility layer, not a fork and not a dependency: MoonGate keeps
/// its own evaluator, and the output is an ordinary MoonGate policy.
///
/// Supported subset:
///   schema_version, allowed_tools, read_roots, write_roots, protected_paths,
///   network_rules, approval_required_tools, max_calls, max_operation_bytes.
///
/// Unsupported fields fail closed with a field name instead of being ignored:
///   command_rules, resource_rules, tool_quotas, max_io_bytes.
pub fn import_moonpod(source : String) -> Json raise PolicyError {
  let root = match json_parse_opt(source) {
    Some(Object(fields)) => fields
    _ => raise PolicyError("moonpod: policy must be a JSON object")
  }
  let known : Array[String] = [
    "schema_version", "allowed_tools", "read_roots", "write_roots", "protected_paths",
    "network_rules", "command_rules", "resource_rules", "tool_quotas", "max_calls",
    "max_operation_bytes", "max_io_bytes", "approval_required_tools",
  ]
  for name, _ in root {
    if !known.contains(name) {
      raise PolicyError("moonpod: unknown field " + name)
    }
  }
  if pod_int(root, "schema_version", 0) != 1 {
    raise PolicyError("moonpod: only schema_version 1 is supported")
  }
  let allowed = pod_texts(root, "allowed_tools")
  let read_roots = pod_texts(root, "read_roots")
  let write_roots = pod_texts(root, "write_roots")
  let protected_paths = pod_texts(root, "protected_paths")
  let approvals = pod_texts(root, "approval_required_tools")
  let network = pod_array(root, "network_rules")
  let rules : Array[Json] = []

  if !pod_array(root, "command_rules").is_empty() {
    raise PolicyError(
      "moonpod: field command_rules is not supported by the adapter",
    )
  }
  if !pod_array(root, "resource_rules").is_empty() {
    raise PolicyError(
      "moonpod: field resource_rules is not supported by the adapter",
    )
  }
  if !pod_array(root, "tool_quotas").is_empty() {
    raise PolicyError(
      "moonpod: field tool_quotas is not supported by the adapter",
    )
  }
  if root.contains("max_io_bytes") {
    raise PolicyError(
      "moonpod: field max_io_bytes is not supported by the adapter",
    )
  }
  if allowed.contains("process.run") {
    raise PolicyError(
      "moonpod: process.run needs command_rules, which the adapter does not support",
    )
  }

  // Protected paths deny first: they override every allow, matching MoonPod.
  for i, path in protected_paths {
    rules.push(
      pod_rule(
        "pod-protected-\{i}",
        "*",
        "deny",
        [pod_path_check(path)],
        "protected path from MoonPod policy",
      ),
    )
  }
  // Approvals come before allows so an approved tool cannot slip through.
  for i, tool in approvals {
    rules.push(
      pod_rule(
        "pod-approval-\{i}",
        tool,
        "approval",
        [],
        "approval required by MoonPod policy",
      ),
    )
  }
  for i, root_path in read_roots {
    rules.push(
      pod_rule(
        "pod-read-\{i}",
        "fs.read",
        "allow",
        [pod_path_check(root_path)],
        "read root from MoonPod policy",
      ),
    )
  }
  if allowed.contains("fs.read") && read_roots.is_empty() {
    rules.push(pod_rule("pod-read-any", "fs.read", "allow", [], "allowed tool"))
  }
  for i, root_path in write_roots {
    rules.push(
      pod_rule(
        "pod-write-\{i}",
        "fs.write",
        "allow",
        [pod_path_check(root_path)],
        "write root from MoonPod policy",
      ),
    )
  }
  if allowed.contains("fs.write") && write_roots.is_empty() {
    rules.push(
      pod_rule("pod-write-any", "fs.write", "allow", [], "allowed tool"),
    )
  }
  for i, entry in network {
    let fields = match entry {
      Object(fields) => fields
      _ => raise PolicyError("moonpod: network_rules[\{i}] must be an object")
    }
    let host = pod_text(fields, "host")
    let ports = pod_int_array(fields, "allowed_ports")
    let globs : Array[Json] = []
    for port in ports {
      globs.push(json_str("*://" + host + ":" + port.to_string() + "/*"))
      if port == 80 || port == 443 {
        globs.push(json_str("*://" + host + "/*"))
      }
    }
    rules.push(
      pod_rule(
        "pod-net-\{i}",
        "net.*",
        "allow",
        [json_obj([("arg", json_str("url")), ("glob", json_arr(globs))])],
        "network rule from MoonPod policy",
      ),
    )
  }
  for tool in allowed {
    if tool == "fs.read" || tool == "fs.write" || tool == "net.connect" {
      continue
    }
    if tool.has_prefix("net.") {
      // Network tools are only reachable through network_rules.
      continue
    }
    rules.push(pod_rule("pod-allow-" + tool, tool, "allow", [], "allowed tool"))
  }

  let max_calls = pod_int(root, "max_calls", 100)
  let max_operation = pod_int(root, "max_operation_bytes", 1048576)
  if max_calls == 0 || max_operation == 0 {
    rules.push(
      pod_rule(
        "pod-zero-budget",
        "*",
        "deny",
        [],
        "MoonPod policy allows zero calls or zero bytes",
      ),
    )
  }
  let policy = json_obj([
    ("version", json_int(1)),
    ("name", json_str("imported-moonpod")),
    ("default_decision", json_str("deny")),
    ("rules", json_arr(rules)),
    (
      "budget",
      json_obj([
        ("max_calls", json_int(max_calls)),
        ("max_single_bytes", json_int(max_operation)),
      ]),
    ),
    ("hide_denied", json_bool(true)),
    ("mask_secrets", json_bool(true)),
  ])
  // Validate the generated document with the same parser the gateway uses.
  let _ = parse_policy(json_render(policy)) catch {
    PolicyError(message) =>
      raise PolicyError("moonpod: generated policy is invalid: " + message)
  }
  policy
}

///|
fn pod_rule(
  id : String,
  tool : String,
  decision : String,
  checks : Array[Json],
  reason : String,
) -> Json {
  let fields : Array[(String, Json)] = [
    ("id", json_str(id)),
    ("tool", json_str(tool)),
    ("decision", json_str(decision)),
  ]
  if !checks.is_empty() {
    fields.push(("when", json_arr(checks)))
  }
  if reason != "" {
    fields.push(("reason", json_str(reason)))
  }
  json_obj(fields)
}

///|
fn pod_path_check(root : String) -> Json {
  json_obj([
    ("arg", json_str("path")),
    ("normalize", json_str("path")),
    ("prefix", json_arr([json_str(root)])),
  ])
}

///|
fn pod_texts(
  fields : Map[String, Json],
  name : String,
) -> Array[String] raise PolicyError {
  match fields.get(name) {
    None => []
    Some(Array(items)) => {
      let out : Array[String] = []
      for item in items {
        match item {
          String(text) => out.push(text)
          _ => raise PolicyError("moonpod: \{name} must be an array of strings")
        }
      }
      out
    }
    Some(_) => raise PolicyError("moonpod: \{name} must be an array of strings")
  }
}

///|
fn pod_array(
  fields : Map[String, Json],
  name : String,
) -> Array[Json] raise PolicyError {
  match fields.get(name) {
    None => []
    Some(Array(items)) => items
    Some(_) => raise PolicyError("moonpod: \{name} must be an array")
  }
}

///|
fn pod_text(
  fields : Map[String, Json],
  name : String,
) -> String raise PolicyError {
  match fields.get(name) {
    Some(String(text)) => text
    _ => raise PolicyError("moonpod: \{name} must be a string")
  }
}

///|
fn pod_int(
  fields : Map[String, Json],
  name : String,
  fallback : Int32,
) -> Int32 raise PolicyError {
  match fields.get(name) {
    Some(Number(value, ..)) => value.to_int()
    None => fallback
    _ => raise PolicyError("moonpod: \{name} must be an integer")
  }
}

///|
fn pod_int_array(
  fields : Map[String, Json],
  name : String,
) -> Array[Int32] raise PolicyError {
  match fields.get(name) {
    Some(Array(items)) => {
      let out : Array[Int32] = []
      for item in items {
        match item {
          Number(value, ..) => out.push(value.to_int())
          _ =>
            raise PolicyError("moonpod: \{name} must be an array of integers")
        }
      }
      out
    }
    _ => raise PolicyError("moonpod: \{name} must be an array of integers")
  }
}
