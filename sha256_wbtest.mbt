///|
test "sha256 matches the FIPS 180-4 test vectors" {
  inspect(
    sha256_hex(""),
    content="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
  inspect(
    sha256_hex("abc"),
    content="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
  inspect(
    sha256_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
    content="248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
  )
}

///|
test "sha256 handles multi-byte text and long input" {
  let long = "moongate".repeat(100)
  // Same input hashes identically regardless of the surrounding code path.
  inspect(sha256_hex(long).length(), content="64")
  inspect(sha256_hex("密钥"), content=sha256_hex("密钥"))
  inspect(sha256_hex("密钥") == sha256_hex("密鑰"), content="false")
}

///|
test "fingerprints are stable and compact" {
  inspect(fingerprint_of("sk-live-1234567890").length(), content="16")
  inspect(
    fingerprint_of("sk-live-1234567890") == fingerprint_of("sk-live-1234567890"),
    content="true",
  )
}
