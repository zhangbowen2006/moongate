///|
/// Whole-string glob matching.
///
/// `*` matches any run of characters (including path separators), `?` matches
/// exactly one character, everything else is literal. There is no escape
/// syntax and no path normalization: `reports/*.md` is compared against the
/// argument exactly as the agent sent it. Backtracking is linear in the text
/// because only the most recent `*` is ever revisited.
pub fn glob_match(pattern : String, text : String) -> Bool {
  let plen = pattern.length()
  let tlen = text.length()
  let mut p = 0
  let mut t = 0
  let mut star = -1
  let mut mark = 0
  while t < tlen {
    if p < plen && (pattern[p] == '?' || pattern[p] == text[t]) {
      p += 1
      t += 1
    } else if p < plen && pattern[p] == '*' {
      star = p
      p += 1
      mark = t
    } else if star >= 0 {
      p = star + 1
      mark += 1
      t = mark
    } else {
      return false
    }
  }
  while p < plen && pattern[p] == '*' {
    p += 1
  }
  p == plen
}

///|
/// True when at least one pattern matches. An empty pattern list matches
/// nothing, which keeps "no rule configured" fail-closed.
pub fn any_glob(patterns : Array[String], text : String) -> Bool {
  for pattern in patterns {
    if glob_match(pattern, text) {
      return true
    }
  }
  false
}
