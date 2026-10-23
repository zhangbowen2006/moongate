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
  let seen : Map[String, Bool] = Map([])
  for text in texts {
    // As written.
    for token in scan_fingerprints([text], min_len) {
      match taint.get(token.fingerprint) {
        Some(source) =>
          push_hit(hits, seen, token.fingerprint, token.preview, source)
        None => ()
      }
    }
    // Separators removed and case folded: catches `sk-abc_123` sent as
    // `skabc123` or `SK ABC 123`.
    let collapsed = collapse_separators(text)
    if collapsed != text {
      for token in scan_fingerprints([collapsed], min_len) {
        match taint.get(token.fingerprint) {
          Some(source) =>
            push_hit(hits, seen, token.fingerprint, token.preview, source)
          None => ()
        }
      }
    }
    // Base64-shaped runs: catches a secret that was encoded before leaving.
    for run in scan_base64_like(text) {
      let fingerprint = fingerprint_of(run)
      match taint.get(fingerprint) {
        Some(source) =>
          push_hit(hits, seen, fingerprint, run[0:4].to_owned() + "…", source)
        None => ()
      }
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

///|
fn to_lower_ascii(ch : Char) -> Char {
  if ch >= 'A' && ch <= 'Z' {
    (ch.to_int() + 32).unsafe_to_char()
  } else {
    ch
  }
}

///|
/// Drop separators and fold case, so `sk-abc_123`, `SK ABC 123` and
/// `skabc123` all collapse to the same string. A secret that is split or
/// re-cased before leaving still matches the collapsed view.
pub fn collapse_separators(text : String) -> String {
  let out = StringBuilder()
  for ch in text {
    if ch == '-' ||
      ch == '_' ||
      ch == '.' ||
      ch == ':' ||
      ch == '/' ||
      ch == ' ' ||
      ch == '\t' ||
      ch == '\n' {
      continue
    }
    out.write_string(to_lower_ascii(ch).to_string())
  }
  out.to_string()
}

///|
fn base64_char(value : Int32) -> Char {
  if value < 26 {
    (65 + value).unsafe_to_char()
  } else if value < 52 {
    (97 + value - 26).unsafe_to_char()
  } else if value < 62 {
    (48 + value - 52).unsafe_to_char()
  } else if value == 62 {
    '+'
  } else {
    '/'
  }
}

///|
/// Standard Base64 for the ASCII token shapes the scanner accepts.
pub fn base64_encode(text : String) -> String {
  let chars = text.to_array()
  let len = chars.length()
  let out = StringBuilder()
  let mut i = 0
  while i + 2 < len {
    let a = chars[i].to_int() & 255
    let b = chars[i + 1].to_int() & 255
    let c = chars[i + 2].to_int() & 255
    out.write_string(base64_char(a >> 2).to_string())
    out.write_string(base64_char(((a & 3) << 4) | (b >> 4)).to_string())
    out.write_string(base64_char(((b & 15) << 2) | (c >> 6)).to_string())
    out.write_string(base64_char(c & 63).to_string())
    i += 3
  }
  let rest = len - i
  if rest == 1 {
    let a = chars[i].to_int() & 255
    out.write_string(base64_char(a >> 2).to_string())
    out.write_string(base64_char((a & 3) << 4).to_string())
    out.write_string("==")
  } else if rest == 2 {
    let a = chars[i].to_int() & 255
    let b = chars[i + 1].to_int() & 255
    out.write_string(base64_char(a >> 2).to_string())
    out.write_string(base64_char(((a & 3) << 4) | (b >> 4)).to_string())
    out.write_string(base64_char((b & 15) << 2).to_string())
    out.write_string("=")
  }
  out.to_string()
}

///|
pub fn base64_urlsafe(text : String) -> String {
  base64_encode(text)
  .replace_all(old="+", new="-")
  .replace_all(old="/", new="_")
}

///|
/// Encoded forms a secret can take on the way out. The gateway stores the
/// fingerprint of each form when the secret is first seen, so a later call
/// that carries any of them is still recognised as the same value.
pub fn variant_values(value : String) -> Array[String] {
  let out : Array[String] = []
  let collapsed = collapse_separators(value)
  if collapsed != value && collapsed.length() >= 6 {
    out.push(collapsed)
  }
  if value.length() >= 8 {
    out.push(base64_encode(value))
    out.push(base64_urlsafe(value))
  }
  out
}

///|
fn is_base64_char(ch : Char) -> Bool {
  (ch >= 'A' && ch <= 'Z') ||
  (ch >= 'a' && ch <= 'z') ||
  (ch >= '0' && ch <= '9') ||
  ch == '+' ||
  ch == '/' ||
  ch == '='
}

///|
/// Runs that look like Base64 and are long enough to be an encoded secret.
/// Requiring alignment and a digit keeps ordinary words out.
fn scan_base64_like(text : String) -> Array[String] {
  let out : Array[String] = []
  let chars = text.to_array()
  let len = chars.length()
  let mut i = 0
  while i < len {
    if is_base64_char(chars[i]) {
      let start = i
      let mut digit = false
      while i < len && is_base64_char(chars[i]) {
        let ch = chars[i]
        if ch >= '0' && ch <= '9' {
          digit = true
        }
        i += 1
      }
      let run = text[start:i].to_owned()
      if digit && run.length() >= 12 && run.length() % 4 == 0 {
        out.push(run)
      }
    } else {
      i += 1
    }
  }
  out
}

///|
fn push_hit(
  hits : Array[TaintHit],
  seen : Map[String, Bool],
  fingerprint : String,
  preview : String,
  source : TaintSource,
) -> Unit {
  // The same secret may be recognised through several views (as written,
  // collapsed, Base64). They all point at one source, so report it once.
  let key = source.call + "|" + source.tool + "|" + source.preview
  if !seen.contains(key) {
    seen.set(key, true)
    hits.push({ fingerprint, preview, source, })
  }
}
