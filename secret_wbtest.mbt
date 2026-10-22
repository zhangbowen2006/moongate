///|
test "placeholders round-trip through the vault" {
  let raw = extract_raw("API_KEY=sk-live-abcd1234efgh", 12)
  inspect(raw.length(), content="1")
  let fingerprint = raw[0].fingerprint
  let placeholder = placeholder_for(fingerprint)
  inspect(placeholder.length(), content="21")
  let vault : Map[String, String] = Map([])
  vault.set(fingerprint, raw[0].value)
  let (revealed, count) = reveal_placeholders(
    "Authorization: Bearer " + placeholder,
    vault,
  )
  inspect(count, content="1")
  inspect(revealed.contains("sk-live-abcd1234efgh"), content="true")
  inspect(revealed.contains("«mg:"), content="false")
}

///|
test "unknown placeholders stay untouched" {
  let vault : Map[String, String] = Map([])
  let (text, count) = reveal_placeholders(
    "value «mg:0000000000000000» stays", vault,
  )
  inspect(count, content="0")
  inspect(text.contains("«mg:0000000000000000»"), content="true")
}

///|
test "placeholder scanning ignores malformed markers" {
  inspect(find_placeholders("«mg:0011223344556677»").length(), content="1")
  inspect(find_placeholders("«mg:0011»").length(), content="0")
  inspect(find_placeholders("«mg:ZZZZZZZZZZZZZZZZ»").length(), content="0")
  inspect(find_placeholders("plain text").length(), content="0")
}

///|
test "masking rewrites every string leaf" {
  let raw = extract_raw("KEY=sk-live-abcd1234efgh", 12)
  let document = match
    json_parse_opt(
      (
        #|{"a":"sk-live-abcd1234efgh","b":["x","sk-live-abcd1234efgh"],"n":1}
      ),
    ) {
    Some(value) => value
    None => abort("bad json")
  }
  let masked = map_json_strings(document, fn(text) {
    let mut out = text
    for token in raw {
      out = out.replace_all(
        old=token.value,
        new=placeholder_for(token.fingerprint),
      )
    }
    out
  })
  let rendered = json_render(masked)
  inspect(rendered.contains("sk-live-abcd1234efgh"), content="false")
  inspect(rendered.contains("«mg:"), content="true")
  inspect(rendered.contains("\"n\":1"), content="true")
}

///|
test "raw values stay out of the fingerprint view" {
  let raw = extract_raw("TOKEN=ABCD1234EFGH5678", 12)
  inspect(raw.length(), content="1")
  inspect(raw[0].value, content="ABCD1234EFGH5678")
  inspect(raw[0].preview, content="ABCD…")
  inspect(raw[0].fingerprint.length(), content="16")
}
