///|
/// SHA-256 (FIPS 180-4).
///
/// The gateway needs three things from a hash: stable argument digests for
/// approval leases, compact fingerprints of sensitive values that must never
/// be written to the audit log, and a tamper-evident chain over ledger
/// entries. A local implementation keeps the engine dependency-free and makes
/// the same bytes hash the same way on every MoonBit backend.
let sha_k : Array[UInt32] = [
  0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
  0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU,
  0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU,
  0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
  0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
  0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
  0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
  0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
  0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U,
  0xc67178f2U,
]

///|
fn rotr32(x : UInt32, n : Int32) -> UInt32 {
  (x >> n) | (x << (32 - n))
}

///|
/// Lowercase hex, zero-padded to `width` characters.
pub fn hex_uint(value : UInt32, width~ : Int32 = 8) -> String {
  let raw = value.to_string(radix=16)
  let mut out = ""
  for _ in 0..<(width - raw.length()) {
    out = out + "0"
  }
  out + raw
}

///|
/// Hash raw bytes and return 64 lowercase hex characters.
pub fn sha256_hex_bytes(data : BytesView) -> String {
  let len = data.length()
  let blocks = (len + 9 + 63) / 64
  let total = blocks * 64
  let words : Array[Int32] = Array::make(total, 0)
  for i in 0..<len {
    words[i] = data[i].to_int()
  }
  words[len] = 0x80
  // Bit length is written as two big-endian 32-bit words. Doubles carry 53
  // bits of integer precision, far beyond any payload this gateway accepts.
  let bits = len.to_double() * 8.0
  let hi = (bits / 4294967296.0).to_int()
  let lo = (bits - hi.to_double() * 4294967296.0).to_int()
  words[total - 8] = (hi >> 24) & 0xFF
  words[total - 7] = (hi >> 16) & 0xFF
  words[total - 6] = (hi >> 8) & 0xFF
  words[total - 5] = hi & 0xFF
  words[total - 4] = (lo >> 24) & 0xFF
  words[total - 3] = (lo >> 16) & 0xFF
  words[total - 2] = (lo >> 8) & 0xFF
  words[total - 1] = lo & 0xFF
  let mut h0 = 0x6a09e667U
  let mut h1 = 0xbb67ae85U
  let mut h2 = 0x3c6ef372U
  let mut h3 = 0xa54ff53aU
  let mut h4 = 0x510e527fU
  let mut h5 = 0x9b05688cU
  let mut h6 = 0x1f83d9abU
  let mut h7 = 0x5be0cd19U
  let w : Array[UInt32] = Array::make(64, 0U)
  for block in 0..<blocks {
    let base = block * 64
    for i in 0..<16 {
      let o = base + i * 4
      w[i] = (words[o].reinterpret_as_uint() << 24) |
        (words[o + 1].reinterpret_as_uint() << 16) |
        (words[o + 2].reinterpret_as_uint() << 8) |
        words[o + 3].reinterpret_as_uint()
    }
    for i in 16..<64 {
      let s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)
      let s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10)
      w[i] = w[i - 16] + s0 + w[i - 7] + s1
    }
    let mut a = h0
    let mut b = h1
    let mut c = h2
    let mut d = h3
    let mut e = h4
    let mut f = h5
    let mut g = h6
    let mut h = h7
    for i in 0..<64 {
      let s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
      let ch = (e & f) ^ (e.lnot() & g)
      let t1 = h + s1 + ch + sha_k[i] + w[i]
      let s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
      let maj = (a & b) ^ (a & c) ^ (b & c)
      let t2 = s0 + maj
      h = g
      g = f
      f = e
      e = d + t1
      d = c
      c = b
      b = a
      a = t1 + t2
    }
    h0 = h0 + a
    h1 = h1 + b
    h2 = h2 + c
    h3 = h3 + d
    h4 = h4 + e
    h5 = h5 + f
    h6 = h6 + g
    h7 = h7 + h
  }
  hex_uint(h0) +
  hex_uint(h1) +
  hex_uint(h2) +
  hex_uint(h3) +
  hex_uint(h4) +
  hex_uint(h5) +
  hex_uint(h6) +
  hex_uint(h7)
}

///|
/// Hash a UTF-8 string.
pub fn sha256_hex(text : String) -> String {
  sha256_hex_bytes(@utf8.encode(text))
}

///|
/// Short fingerprint used for value lineage and lease digests. 16 hex
/// characters (64 bits) keep log lines compact; the full digest is available
/// wherever a stronger binding is required.
pub fn fingerprint_of(text : String) -> String {
  sha256_hex(text)[0:16].to_owned()
}
