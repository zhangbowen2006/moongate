///|
fn taint_with(value : String) -> Map[String, TaintSource] {
  let taint : Map[String, TaintSource] = Map([])
  let source = taint_source("c1", "fs.read", "sk-l…")
  taint.set(fingerprint_of(value), source)
  for variant in variant_values(value) {
    taint.set(fingerprint_of(variant), source)
  }
  taint
}

///|
test "the original value is still detected" {
  let value = "sk-live-9f3a2c7b41de"
  let hits = find_taint(taint_with(value), [value], 6)
  inspect(hits.length(), content="1")
}

///|
test "a secret split by separators or re-cased is still detected" {
  let value = "sk-live-9f3a2c7b41de"
  let taint = taint_with(value)
  inspect(find_taint(taint, ["sklive9f3a2c7b41de"], 6).length(), content="1")
  inspect(find_taint(taint, ["SK LIVE 9F3A2C7B41DE"], 6).length(), content="1")
  inspect(find_taint(taint, ["sk_live_9f3a2c7b41de"], 6).length(), content="1")
}

///|
test "a Base64-encoded secret is still detected" {
  let value = "sk-live-9f3a2c7b41de"
  let taint = taint_with(value)
  let encoded = base64_encode(value)
  inspect(find_taint(taint, [encoded], 6).length(), content="1")
  let urlsafe = base64_urlsafe(value)
  inspect(find_taint(taint, [urlsafe], 6).length(), content="1")
}

///|
test "ordinary text does not become a hit" {
  let value = "sk-live-9f3a2c7b41de"
  let taint = taint_with(value)
  inspect(
    find_taint(taint, ["hello world, nothing secret here"], 6).length(),
    content="0",
  )
  inspect(
    find_taint(taint, [base64_encode("plain text that is not a secret")], 6).length(),
    content="0",
  )
}

///|
test "base64_encode round-trips the shapes the scanner accepts" {
  inspect(base64_encode("sk-abc123"), content="c2stYWJjMTIz")
  inspect(base64_encode("abc"), content="YWJj")
  inspect(base64_encode("ab"), content="YWI=")
  inspect(base64_encode("a"), content="YQ==")
}
