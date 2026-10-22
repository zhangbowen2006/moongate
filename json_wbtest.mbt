///|
test "canonical JSON sorts keys and is stable" {
  let left = json_obj([
    ("b", json_int(1)),
    ("a", json_str("x")),
    ("c", json_str("y")),
  ])
  let right = json_obj([
    ("c", json_str("y")),
    ("a", json_str("x")),
    ("b", json_int(1)),
  ])
  inspect(json_canonical(left), content="{\"a\":\"x\",\"b\":1,\"c\":\"y\"}")
  inspect(json_canonical(left) == json_canonical(right), content="true")
}

///|
test "JSON rendering escapes and round-trips" {
  let original = "a\"b\\c\nd\te\u0001f 中文"
  let rendered = json_render(json_str(original))
  inspect(rendered.contains("\\n"), content="true")
  inspect(rendered.contains("\\t"), content="true")
  inspect(rendered.contains("\\u0001"), content="true")
  let parsed = match json_parse_opt(rendered) {
    Some(String(value)) => value
    _ => ""
  }
  inspect(parsed == original, content="true")
}

///|
test "numbers keep integer form for timestamps" {
  inspect(json_render(json_i64(1761100000000L)), content="1761100000000")
  inspect(json_render(Json::number(1.5)), content="1.5")
  inspect(json_render(json_int(0)), content="0")
}

///|
test "depth guard counts nested containers" {
  let deep = match json_parse_opt("{\"a\":{\"b\":[1,2,{\"c\":3}]}}") {
    Some(value) => value
    None => abort("parse")
  }
  inspect(json_depth(deep), content="5")
}

///|
test "glob matching is anchored and treats * as any run" {
  inspect(glob_match("fs.*", "fs.read"), content="true")
  inspect(glob_match("fs.*", "fs.read.extra"), content="true")
  inspect(glob_match("fs.read", "fs.read.extra"), content="false")
  inspect(glob_match("**/*.env", "config/.env"), content="true")
  inspect(glob_match("**/*.env", "config/.env.local"), content="false")
  inspect(glob_match("reports/?", "reports/a"), content="true")
  inspect(glob_match("reports/?", "reports/ab"), content="false")
  inspect(glob_match("*", ""), content="true")
}
