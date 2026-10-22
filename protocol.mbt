///|
/// JSON-RPC 2.0 envelope handling for the MCP stdio transport.
///
/// MCP's stdio transport delimits messages with newlines (a JSON message may
/// not contain a literal newline), so the transport adapter only splits lines
/// and the engine owns everything else: envelope validation, request/response
/// classification, identifier matching and error synthesis.
pub struct RpcMessage {
  raw : Json
  id : Json?
  has_id : Bool
  verb : String?
  params : Json?
  result : Json?
  error : Json?
}

///|
fn[T] opt_is_none(value : T?) -> Bool {
  match value {
    None => true
    Some(_) => false
  }
}

///|
pub fn parse_rpc(value : Json) -> RpcMessage? {
  let fields = match value {
    Object(fields) => fields
    _ => return None
  }
  let id = fields.get("id")
  let verb = match fields.get("method") {
    Some(String(m)) => Some(m)
    _ => None
  }
  if opt_is_none(id) && opt_is_none(verb) {
    return None
  }
  Some({
    raw: value,
    id,
    has_id: id is Some(_),
    verb,
    params: fields.get("params"),
    result: fields.get("result"),
    error: fields.get("error"),
  })
}

///|
/// Stable key for correlating responses with requests. JSON allows string and
/// number identifiers; both are prefixed so `1` and `"1"` cannot collide.
pub fn id_key(id : Json?) -> String {
  match id {
    Some(String(s)) => "s:" + s
    Some(Number(n, ..)) => "n:" + n.to_int().to_string()
    Some(Null) | None => ""
    Some(other) => "j:" + json_canonical(other)
  }
}

///|
pub fn error_response(
  id : Json?,
  code : Int32,
  message : String,
  data : Json?,
) -> Json {
  let error : Array[(String, Json)] = [
    ("code", json_int(code)),
    ("message", json_str(message)),
  ]
  match data {
    Some(payload) => error.push(("data", payload))
    None => ()
  }
  json_obj([
    ("jsonrpc", json_str("2.0")),
    (
      "id",
      match id {
        Some(v) => v
        None => json_null()
      },
    ),
    ("error", json_obj(error)),
  ])
}

///|
pub fn result_response(id : Json?, result : Json) -> Json {
  json_obj([
    ("jsonrpc", json_str("2.0")),
    (
      "id",
      match id {
        Some(v) => v
        None => json_null()
      },
    ),
    ("result", result),
  ])
}

///|
/// Methods the gateway forwards without a policy decision: the MCP handshake,
/// capability discovery and notifications. Anything that can read or change
/// state goes through `tools/call`, `resources/read` or `prompts/get` and is
/// evaluated.
pub fn is_passthrough_method(verb : String) -> Bool {
  verb == "initialize" ||
  verb == "ping" ||
  verb == "tools/list" ||
  verb == "resources/list" ||
  verb == "resources/templates/list" ||
  verb == "prompts/list" ||
  verb == "logging/setLevel" ||
  verb == "completion/complete" ||
  verb.has_prefix("notifications/")
}

///|
/// Capability name used for policy matching when a client requests a resource
/// or a prompt instead of a tool.
pub fn capability_name(verb : String) -> String {
  if verb == "resources/read" {
    "resources.read"
  } else if verb == "prompts/get" {
    "prompts.get"
  } else if verb == "tools/call" {
    "tools.call"
  } else {
    verb
  }
}

///|
/// Arguments used for policy matching. Tool calls carry `params.arguments`;
/// resource and prompt requests carry their own parameter object.
pub fn capability_args(verb : String, params : Json?) -> Json {
  match params {
    Some(Object(fields)) =>
      if verb == "tools/call" {
        match fields.get("arguments") {
          Some(args) => args
          None => Json::object(Map([]))
        }
      } else {
        Json::object(fields)
      }
    _ => Json::object(Map([]))
  }
}

///|
/// Tool name for a `tools/call` request, or `None` when the request is
/// malformed. The engine answers malformed calls with a JSON-RPC error instead
/// of forwarding them, so an upstream server never sees an invalid request.
pub fn tool_name_of(params : Json?) -> String? {
  match params {
    Some(Object(fields)) =>
      match fields.get("name") {
        Some(String(s)) => Some(s)
        _ => None
      }
    _ => None
  }
}
