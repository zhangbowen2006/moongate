///|
/// Lexical path normalization for policy checks.
///
/// Without this, a prefix rule is trivially bypassed: `reports/../../etc/passwd`
/// starts with `reports/` and would pass a naive "must start with reports"
/// check. Normalization resolves `.` and `..` segments before matching, so the
/// comparison sees the path the operating system would actually open.
///
/// This is lexical only: it does not touch the filesystem, resolve symlinks, or
/// decode percent escapes. Symlink escape remains a limitation and is listed in
/// `docs/SEMANTICS.md`.
pub fn normalize_path(input : String) -> String {
  let slashed = input.replace_all(old="\\", new="/")
  let drive = if slashed.length() >= 2 && slashed[1] == ':' {
    slashed[0:2].to_owned()
  } else {
    ""
  }
  let rest = if drive.is_empty() { slashed } else { slashed[2:].to_owned() }
  let absolute = rest.has_prefix("/")
  let segments : Array[String] = []
  for raw in rest.split("/") {
    let part = raw.to_owned()
    if part.is_empty() || part == "." {
      continue
    }
    if part == ".." {
      if segments.length() > 0 && segments[segments.length() - 1] != ".." {
        let _ = segments.pop()
      } else if !absolute {
        segments.push("..")
      }
      continue
    }
    segments.push(part)
  }
  let body = segments.join("/")
  if !drive.is_empty() {
    if absolute {
      drive + "/" + body
    } else {
      drive + body
    }
  } else if absolute {
    "/" + body
  } else {
    body
  }
}
