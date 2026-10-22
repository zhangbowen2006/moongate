///|
/// Value lineage.
///
/// The gateway does not trust labels the agent attaches to data, and it does
/// not try to understand natural language. It does something narrower and
/// verifiable: when a tool result is declared sensitive by policy, every
/// secret-shaped value in that result is fingerprinted, and any later outbound
/// call whose arguments contain the same value is refused.
///
/// This is exact-value taint, not semantic classification. It catches the
/// common and damaging case — a credential read in one step and shipped out in
/// the next — and it deliberately fails closed: a value that looks like a
/// secret and appears in both places blocks the call even if the agent's
/// intent was benign.
pub struct TaintSource {
  call : String
  tool : String
  preview : String
}

///|
pub fn taint_source(
  call : String,
  tool : String,
  preview : String,
) -> TaintSource {
  { call, tool, preview, }
}

///|
/// A token that survived the shape filter. `preview` is safe to log: four
/// leading characters are enough for a human to recognise which credential is
/// involved, and not enough to reuse it.
pub struct SecretToken {
  fingerprint : String
  preview : String
}

///|
fn is_token_char(ch : Char) -> Bool {
  (ch >= 'a' && ch <= 'z') ||
  (ch >= 'A' && ch <= 'Z') ||
  (ch >= '0' && ch <= '9') ||
  ch == '_' ||
  ch == '-' ||
  ch == '.'
}

///|
fn has_digit(text : String) -> Bool {
  for ch in text {
    if ch >= '0' && ch <= '9' {
      return true
    }
  }
  false
}

///|
fn has_upper(text : String) -> Bool {
  for ch in text {
    if ch >= 'A' && ch <= 'Z' {
      return true
    }
  }
  false
}

///|
fn skip_spaces(chars : Array[Char], from : Int32) -> Int32 {
  let mut index = from
  while index < chars.length() && (chars[index] == ' ' || chars[index] == '\t') {
    index += 1
  }
  index
}

///|
/// Field names are not secrets. A token directly followed by `=` is an
/// environment-style name (`OPENAI_API_KEY`), and a quoted token followed by
/// `:` is a JSON object key. Skipping both keeps the taint set focused on
/// values, which is what actually leaves the machine.
fn looks_like_field_name(
  chars : Array[Char],
  start : Int32,
  end : Int32,
) -> Bool {
  let after = skip_spaces(chars, end)
  if after < chars.length() && chars[after] == '=' {
    return true
  }
  if start > 0 &&
    chars[start - 1] == '"' &&
    after < chars.length() &&
    chars[after] == '"' {
    let colon = skip_spaces(chars, after + 1)
    if colon < chars.length() && chars[colon] == ':' {
      return true
    }
  }
  false
}

///|
/// A raw secret value plus its identifiers. The raw value is only ever kept in
/// the session vault; ledger entries and errors carry the fingerprint and a
/// four-character preview.
pub struct RawToken {
  value : String
  fingerprint : String
  preview : String
}

///|
/// Extract raw secret-shaped values for masking. Callers must not log `value`.
pub fn extract_raw(text : String, min_len : Int32) -> Array[RawToken] {
  let out : Array[RawToken] = []
  let chars = text.to_array()
  let length = chars.length()
  let mut i = 0
  while i < length {
    if is_token_char(chars[i]) {
      let start = i
      while i < length && is_token_char(chars[i]) {
        i += 1
      }
      let end = i
      if end - start >= min_len && !looks_like_field_name(chars, start, end) {
        let token = text[start:end].to_owned()
        if token.length() <= 512 && (has_digit(token) || has_upper(token)) {
          out.push({
            value: token,
            fingerprint: fingerprint_of(token),
            preview: token[0:4].to_owned() + "…",
          })
        }
      }
    } else {
      i += 1
    }
  }
  out
}

///|
/// Extract secret-shaped values from one string.
///
/// The scanner accepts runs of `[A-Za-z0-9_.-]` at least `min_len` long that
/// contain a digit or an uppercase letter. Requiring a digit or uppercase
/// keeps ordinary prose ("application", "workspace") out of the taint set
/// while still admitting API keys, tokens, connection strings and long
/// identifiers. Names on the left of `=` or `:` are excluded on purpose: they
/// are the most common false positive, and a blocked call that only contains a
/// variable name erodes trust in the gateway.
pub fn extract_tokens(text : String, min_len : Int32) -> Array[SecretToken] {
  let unique : Array[SecretToken] = []
  let seen : Map[String, Bool] = Map([])
  for raw in extract_raw(text, min_len) {
    if !seen.contains(raw.fingerprint) {
      seen.set(raw.fingerprint, true)
      unique.push({ fingerprint: raw.fingerprint, preview: raw.preview, })
    }
  }
  unique
}

///|
/// Collect every string leaf of a JSON value. Used on `tools/call` arguments
/// so taint matching sees values, not JSON syntax (keys, punctuation, escapes).
pub fn collect_strings(value : Json) -> Array[String] {
  let out : Array[String] = []
  collect_strings_into(value, out)
  out
}

///|
fn collect_strings_into(value : Json, out : Array[String]) -> Unit {
  match value {
    String(s) => out.push(s)
    Array(items) =>
      for item in items {
        collect_strings_into(item, out)
      }
    Object(fields) =>
      for _, item in fields {
        collect_strings_into(item, out)
      }
    _ => ()
  }
}

///|
/// Fingerprints of every secret-shaped value in the given strings.
pub fn scan_fingerprints(
  texts : Array[String],
  min_len : Int32,
) -> Array[SecretToken] {
  let unique : Array[SecretToken] = []
  let seen : Map[String, Bool] = Map([])
  for text in texts {
    for token in extract_tokens(text, min_len) {
      if !seen.contains(token.fingerprint) {
        seen.set(token.fingerprint, true)
        unique.push(token)
      }
    }
  }
  unique
}

///|
/// One taint hit: the fingerprinted value, plus the tool call that introduced
/// it. This is the evidence the gateway returns to the agent and writes to the
/// ledger.
pub struct TaintHit {
  fingerprint : String
  preview : String
  source : TaintSource
}

///|
pub fn find_taint(
  taint : Map[String, TaintSource],
  texts : Array[String],
  min_len : Int32,
) -> Array[TaintHit] {
  let hits : Array[TaintHit] = []
  for token in scan_fingerprints(texts, min_len) {
    match taint.get(token.fingerprint) {
      Some(source) =>
        hits.push({
          fingerprint: token.fingerprint,
          preview: token.preview,
          source,
        })
      None => ()
    }
  }
  hits
}

///|
/// Placeholder syntax used in tool results and arguments: `«mg:<fingerprint>»`.
/// The delimiters are non-ASCII on purpose so that model-generated prose is
/// unlikely to collide with ordinary content.
pub fn placeholder_for(fingerprint : String) -> String {
  "«mg:" + fingerprint + "»"
}

///|
fn is_hex_lower(ch : Char) -> Bool {
  (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')
}

///|
/// Fingerprints referenced by placeholders in one string.
pub fn find_placeholders(text : String) -> Array[String] {
  let out : Array[String] = []
  let chars = text.to_array()
  let length = chars.length()
  let mut i = 0
  while i < length {
    if chars[i] == '«' && i + 4 <= length {
      let matched = chars[i + 1] == 'm' &&
        chars[i + 2] == 'g' &&
        chars[i + 3] == ':'
      if matched {
        let start = i + 4
        let mut end = start
        while end < length && is_hex_lower(chars[end]) {
          end += 1
        }
        if end - start == 16 && end < length && chars[end] == '»' {
          out.push(text[start:end].to_owned())
          i = end + 1
          continue
        }
      }
    }
    i += 1
  }
  out
}

///|
/// Replace placeholders with their real values. Returns the rewritten string
/// and how many distinct placeholders were substituted. Unknown placeholders
/// are left alone.
pub fn reveal_placeholders(
  text : String,
  vault : Map[String, String],
) -> (String, Int32) {
  let mut result = text
  let mut count = 0
  let seen : Map[String, Bool] = Map([])
  for fingerprint in find_placeholders(text) {
    if seen.contains(fingerprint) {
      continue
    }
    seen.set(fingerprint, true)
    match vault.get(fingerprint) {
      Some(value) => {
        result = result.replace_all(old=placeholder_for(fingerprint), new=value)
        count += 1
      }
      None => ()
    }
  }
  (result, count)
}

///|
/// Rewrite a JSON value by passing every string leaf through `transform`.
pub fn map_json_strings(value : Json, transform : (String) -> String) -> Json {
  match value {
    String(s) => Json::string(transform(s))
    Array(items) => {
      let out : Array[Json] = []
      for item in items {
        out.push(map_json_strings(item, transform))
      }
      Json::array(out)
    }
    Object(fields) => {
      let out : Map[String, Json] = Map([])
      for key, item in fields {
        out.set(key, map_json_strings(item, transform))
      }
      Json::object(out)
    }
    _ => value
  }
}

///|
/// Raw tokens across several strings, deduplicated by fingerprint.
pub fn scan_raw(texts : Array[String], min_len : Int32) -> Array[RawToken] {
  let unique : Array[RawToken] = []
  let seen : Map[String, Bool] = Map([])
  for text in texts {
    for raw in extract_raw(text, min_len) {
      if !seen.contains(raw.fingerprint) {
        seen.set(raw.fingerprint, true)
        unique.push(raw)
      }
    }
  }
  unique
}

///|
/// Distinct placeholder fingerprints anywhere in a JSON value.
pub fn placeholders_in(value : Json) -> Array[String] {
  let unique : Array[String] = []
  let seen : Map[String, Bool] = Map([])
  for text in collect_strings(value) {
    for fingerprint in find_placeholders(text) {
      if !seen.contains(fingerprint) {
        seen.set(fingerprint, true)
        unique.push(fingerprint)
      }
    }
  }
  unique
}
