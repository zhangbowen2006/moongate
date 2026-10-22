///|
/// JSON helpers shared by the policy parser, the protocol layer and the
/// ledger. Two serializers are provided on purpose:
///
/// - `json_render` keeps insertion order and is used for wire messages, where
///   field order is irrelevant but readability helps debugging.
/// - `json_canonical` sorts object keys recursively and is used for digests
///   and for the hash chain, so semantically identical messages produce
///   identical bytes regardless of how the caller built them.
pub fn json_str(value : String) -> Json {
  Json::string(value)
}

///|
pub fn json_int(value : Int32) -> Json {
  Json::number(value.to_double())
}

///|
pub fn json_i64(value : Int64) -> Json {
  Json::number(value.to_double())
}

///|
pub fn json_bool(value : Bool) -> Json {
  if value {
    Json::boolean(true)
  } else {
    Json::boolean(false)
  }
}

///|
pub fn json_null() -> Json {
  Json::null()
}

///|
pub fn json_obj(pairs : Array[(String, Json)]) -> Json {
  let map : Map[String, Json] = Map([])
  for pair in pairs {
    map.set(pair.0, pair.1)
  }
  Json::object(map)
}

///|
pub fn json_arr(items : Array[Json]) -> Json {
  Json::array(items)
}

///|
pub fn json_strings(items : Array[String]) -> Json {
  let out : Array[Json] = []
  for item in items {
    out.push(Json::string(item))
  }
  Json::array(out)
}

///|
pub fn json_get(value : Json, key : String) -> Json? {
  match value {
    Object(fields) => fields.get(key)
    _ => None
  }
}

///|
pub fn json_as_string(value : Json) -> String? {
  match value {
    String(s) => Some(s)
    _ => None
  }
}

///|
pub fn json_as_int(value : Json) -> Int32? {
  match value {
    Number(n, ..) =>
      if n == n.to_int().to_double() {
        Some(n.to_int())
      } else {
        None
      }
    _ => None
  }
}

///|
pub fn json_as_bool(value : Json) -> Bool? {
  match value {
    True => Some(true)
    False => Some(false)
    _ => None
  }
}

///|
pub fn json_as_array(value : Json) -> Array[Json]? {
  match value {
    Array(items) => Some(items)
    _ => None
  }
}

///|
pub fn json_as_object(value : Json) -> Map[String, Json]? {
  match value {
    Object(fields) => Some(fields)
    _ => None
  }
}

///|
pub fn string_field(value : Json, key : String) -> String? {
  match json_get(value, key) {
    Some(field) => json_as_string(field)
    None => None
  }
}

///|
pub fn int_field(value : Json, key : String) -> Int32? {
  match json_get(value, key) {
    Some(field) => json_as_int(field)
    None => None
  }
}

///|
pub fn bool_field(value : Json, key : String, fallback~ : Bool = false) -> Bool {
  match json_get(value, key) {
    Some(field) =>
      match json_as_bool(field) {
        Some(flag) => flag
        None => fallback
      }
    None => fallback
  }
}

///|
pub fn string_array(value : Json) -> Array[String] {
  let out : Array[String] = []
  match value {
    Array(items) =>
      for item in items {
        match item {
          String(s) => out.push(s)
          _ => ()
        }
      }
    _ => ()
  }
  out
}

///|
fn escape_json_into(out : StringBuilder, text : String) -> Unit {
  out.write_string("\"")
  let len = text.length()
  let mut start = 0
  let mut i = 0
  for ch in text {
    let needs_escape = ch == '"' || ch == '\\' || ch.to_int() < 0x20
    if needs_escape {
      if i > start {
        out.write_string(text[start:i].to_owned())
      }
      match ch {
        '"' => out.write_string("\\\"")
        '\\' => out.write_string("\\\\")
        '\n' => out.write_string("\\n")
        '\r' => out.write_string("\\r")
        '\t' => out.write_string("\\t")
        '\u0008' => out.write_string("\\b")
        '\u000C' => out.write_string("\\f")
        _ => {
          out.write_string("\\u00")
          out.write_string(hex_uint(ch.to_int().reinterpret_as_uint(), width=2))
        }
      }
      start = i + 1
    }
    i += 1
  }
  if start < len {
    out.write_string(text[start:len].to_owned())
  }
  out.write_string("\"")
}

///|
fn number_text(n : Double) -> String {
  if n == n.floor() && n.abs() < 1.0e15 {
    n.to_int64().to_string()
  } else {
    n.to_string()
  }
}

///|
/// Code-unit ordering for canonical keys. MoonBit's `>` on `String` is not a
/// lexicographic comparison, so the serializer owns the order explicitly; the
/// same function therefore runs on every backend and canonical bytes are
/// reproducible.
fn string_less(left : String, right : String) -> Bool {
  let limit = if left.length() < right.length() {
    left.length()
  } else {
    right.length()
  }
  for i in 0..<limit {
    let a = left[i].to_int()
    let b = right[i].to_int()
    if a != b {
      return a < b
    }
  }
  left.length() < right.length()
}

///|
fn render_into(out : StringBuilder, value : Json, canonical : Bool) -> Unit {
  match value {
    Null => out.write_string("null")
    True => out.write_string("true")
    False => out.write_string("false")
    Number(n, ..) => out.write_string(number_text(n))
    String(s) => escape_json_into(out, s)
    Array(items) => {
      out.write_string("[")
      let mut first = true
      for item in items {
        if !first {
          out.write_string(",")
        }
        first = false
        render_into(out, item, canonical)
      }
      out.write_string("]")
    }
    Object(fields) => {
      out.write_string("{")
      let keys : Array[String] = []
      for key, _ in fields {
        keys.push(key)
      }
      if canonical {
        // Insertion sort: object key sets here are tiny (protocol envelopes,
        // policy rules, ledger entries) and this avoids a comparator import.
        for i in 1..<keys.length() {
          let mut j = i
          while j > 0 && string_less(keys[j], keys[j - 1]) {
            let hold = keys[j - 1]
            keys[j - 1] = keys[j]
            keys[j] = hold
            j -= 1
          }
        }
      }
      let mut first = true
      for key in keys {
        if !first {
          out.write_string(",")
        }
        first = false
        escape_json_into(out, key)
        out.write_string(":")
        match fields.get(key) {
          Some(item) => render_into(out, item, canonical)
          None => out.write_string("null")
        }
      }
      out.write_string("}")
    }
  }
}

///|
pub fn json_render(value : Json) -> String {
  let out = StringBuilder()
  render_into(out, value, false)
  out.to_string()
}

///|
pub fn json_canonical(value : Json) -> String {
  let out = StringBuilder()
  render_into(out, value, true)
  out.to_string()
}

///|
/// Parse a JSON document, returning `None` instead of raising so protocol
/// callers can answer a malformed line with a JSON-RPC error.
pub fn json_parse_opt(text : String) -> Json? {
  Some(@json.parse(text)) catch {
    _ => None
  }
}

///|
/// Depth of an object/array tree, used by the policy parser to reject
/// pathological nesting before the engine keeps it in memory.
pub fn json_depth(value : Json) -> Int32 {
  match value {
    Array(items) => {
      let mut best = 0
      for item in items {
        let d = json_depth(item)
        if d > best {
          best = d
        }
      }
      best + 1
    }
    Object(fields) => {
      let mut best = 0
      for _, item in fields {
        let d = json_depth(item)
        if d > best {
          best = d
        }
      }
      best + 1
    }
    _ => 1
  }
}
