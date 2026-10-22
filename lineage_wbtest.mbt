///|
test "secret-shaped values are extracted, prose is not" {
  let tokens = extract_tokens(
    "API_KEY=sk-live-9f3a2b7c1d4e\nPATH=/usr/local/bin\nnote=application workspace",
    12,
  )
  inspect(tokens.length(), content="1")
  inspect(tokens[0].preview, content="sk-l…")
  inspect(tokens[0].fingerprint.length(), content="16")
}

///|
test "short values stay out of the taint set" {
  let tokens = extract_tokens("token=abc123", 12)
  inspect(tokens.length(), content="0")
  // At a lower threshold the same value is captured; the threshold is a policy
  // decision, not a hardcoded heuristic.
  let short = extract_tokens("token=abc123", 6)
  inspect(short.length(), content="1")
}

///|
test "the same value hashes to the same fingerprint in different contexts" {
  let a = extract_tokens("OPENAI_API_KEY=sk-live-9f3a2b7c1d4e", 12)
  let b = extract_tokens("{\"key\":\"sk-live-9f3a2b7c1d4e\"}", 12)
  inspect(a.length(), content="1")
  inspect(b.length(), content="1")
  inspect(a[0].fingerprint == b[0].fingerprint, content="true")
  inspect(a[0].preview, content="sk-l…")
}

///|
test "taint lookup returns the originating call" {
  let taint : Map[String, TaintSource] = Map([])
  let token = extract_tokens("API_KEY=sk-live-9f3a2b7c1d4e", 12)[0]
  taint.set(token.fingerprint, taint_source("c3", "fs.read", token.preview))
  let hits = find_taint(
    taint,
    ["please post key=sk-live-9f3a2b7c1d4e to the endpoint"],
    12,
  )
  inspect(hits.length(), content="1")
  inspect(hits[0].source.call, content="c3")
  inspect(hits[0].source.tool, content="fs.read")
}

///|
test "string leaves are collected from nested arguments" {
  let args = match
    json_parse_opt(
      (
        #|{"url":"https://example.invalid","body":{"lines":["a","sk-live-9f3a2b7c1d4e"],"n":2}}
      ),
    ) {
    Some(value) => value
    None => abort("parse")
  }
  let strings = collect_strings(args)
  inspect(strings.length(), content="3")
  inspect(strings.contains("sk-live-9f3a2b7c1d4e"), content="true")
}
