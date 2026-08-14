# RCAN version 2 wire format

## 1. Scope

This document specifies the interoperable byte and text encodings of an RCAN
version 2 delegation. It also specifies signature verification and the
canonicality requirements for decoders.

Capability semantics, attenuation, and proof-chain validation are outside the
wire format. Capability data is opaque to an untyped decoder.

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are to be
interpreted as described in RFC 2119 and RFC 8174.

## 2. Primitive encodings

### 2.1 Unsigned varint

`varint` is unsigned LEB128, equivalent to postcard's unsigned integer
encoding and WebAssembly's `uN` encoding. In each byte, the low seven bits are
payload and the high bit indicates that another byte follows. The least
significant group is encoded first.

Only the shortest representation is valid. Therefore, the last byte of a
multi-byte varint MUST have a nonzero payload. For example, `00` is the only
encoding of zero; `80 00` is invalid.

All integer values in this specification are unsigned. Expiry timestamps are
`u64` values, so their varints are at most ten bytes and MUST not overflow
`u64`.

### 2.2 Keys and signatures

An `ed25519-key` is the 32-byte compressed Edwards-Y public-key encoding from
RFC 8032. The bytes MUST decode as a valid Ed25519 verifying key.

An `ed25519-signature` is exactly 64 bytes: the 32-byte encoded `R` component
followed by the 32-byte little-endian `S` component.

### 2.3 Byte strings

A variable-length byte string is encoded as:

```text
byte-string = varint(length) || length bytes
```

The length varint is canonical as defined in section 2.1.

## 3. Delegation encoding

An RCAN v2 delegation has this layout:

```text
delegation = version || payload || signature

version    = 02

payload    = issuer || audience || origin || expiry || capability
issuer     = ed25519-key
audience   = ed25519-key

origin     = 00
           | 01 || capability-owner
capability-owner = ed25519-key

expiry     = 00
           | 01 || expires-at
expires-at = varint(u64 Unix timestamp in seconds)

capability = byte-string
signature  = ed25519-signature
```

Concatenation is denoted by `||`. There is no padding or alignment between
fields.

The `00` and `01` bytes in `origin` and `expiry` are canonical postcard enum
variant discriminants. Other discriminants are invalid.

### 3.1 Field meanings

- `issuer` identifies the party that created and signed this delegation.
- `audience` identifies the party receiving the delegation.
- `origin = 00` means that `issuer` owns the delegated capability.
- `origin = 01 || capability-owner` means that `issuer` is passing on a
  capability owned by `capability-owner`.
- `expiry = 00` means that the delegation has no expiry time.
- `expiry = 01 || t` means that the delegation is valid through Unix timestamp
  `t`, in whole seconds. In other words, it is valid when `now <= t` and
  expired when `now > t`.
- `capability` is an opaque sequence of bytes. It MAY be empty at the envelope
  layer.

The payload layout is exactly the postcard serialization of the following
logical structure, in field order:

```text
Payload {
    issuer:            [u8; 32],
    audience:          [u8; 32],
    capability_origin: Issuer | Delegation([u8; 32]),
    valid_until:       Never | At(u64),
    capability:        Vec<u8>,
}
```

No postcard framing surrounds the payload.

## 4. Signature

The signature domain-separation tag is the 17 ASCII bytes:

```text
rcan-2-delegation
```

The issuer signs:

```text
signed-message = ASCII("rcan-2-delegation") || payload
```

The version byte and signature itself are not part of `signed-message`.

A verifier MUST verify the signature using `issuer`. Verifiers SHOULD use
strict Ed25519 verification; the reference implementation uses
`ed25519-dalek`'s `verify_strict`, which rejects non-canonical signatures and
small-order components.

## 5. Canonical decoding

There is exactly one accepted byte encoding for a delegation. A conforming
decoder MUST perform checks equivalent to the following:

1. Require a leading version byte. Reject `01` and `20` as unsupported v1
   tokens, and reject every value other than `02` as an unknown version.
2. Decode the five payload fields in order, rejecting invalid keys, invalid
   enum discriminants, malformed or overflowing varints, and truncated fields.
3. Require exactly 64 bytes after the decoded capability. Fewer or more bytes
   are invalid; trailing data is not permitted.
4. Require the payload to be canonical. One sufficient procedure is to
   re-encode the decoded payload and compare it byte-for-byte with the received
   payload. A mismatch MUST be rejected.
5. Verify the signature specified in section 4.

Re-encoding catches overlong varints, including overlong enum discriminants,
expiry values, and capability lengths. Implementations MAY enforce the same
rules directly instead.

Signature verification does not make a non-canonical encoding acceptable,
even if the signature would otherwise verify.

## 6. Capability encoding

The envelope assigns no meaning or type identifier to the capability bytes.
By convention, they contain the canonical postcard encoding of an
application-defined capability value.

A typed decoder MUST decode the entire capability byte string as the expected
type and MUST reject trailing bytes within that string. Applications MUST
ensure that a given capability owner does not issue ambiguous encodings for
different capability types. Types sharing an owner SHOULD be self-identifying
when their byte encodings could otherwise overlap.

Envelope signature verification authenticates the capability bytes; it does
not establish that they have the type expected by an application.

## 7. Text encoding

The standard text form is RFC 4648 base32 of the complete `delegation` byte
sequence, without `=` padding. Encoders MUST emit lowercase ASCII. Decoders
MUST accept ASCII letters case-insensitively and MUST reject padding, invalid
characters, malformed final symbols, or other non-base32 input.

No whitespace, prefix, or separators are part of the text form.

## 8. Serialization inside other formats

When serialized through a human-readable data model, a delegation is its text
form as a string.

When serialized through a binary data model, a delegation is the complete wire
form as a byte sequence, rather than a nested serialization of its fields. Any
length prefix or byte-container framing belongs to the enclosing format. For
example, postcard serializes that byte sequence with its normal vector length
prefix.

Deserialization from either representation MUST run all structural,
canonicality, key, and signature checks above. A typed deserializer MUST also
run the capability check in section 6.

## 9. Test vector

For this vector, `key(n)` is the Ed25519 signing key whose 32-byte seed is
`[n; 32]`.

- issuer: `key(0)`
- audience: `key(1)`
- origin: issuer
- expiry: Unix timestamp `4102444800`
- capability: one byte, `01`

```text
02
3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29
8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
00
01 80ae99a40f
01 01
83461886f14cdfa8b2d60eaab3ce00098761aa2bbf8dd028820fd54211bf2cca
ccfc635242760b1c1d0d1d1c98943556f725c1e2c7edcd94365660e5af929f06
```

The line breaks and spaces above are annotations and are not encoded. The text
form of those bytes is:

```text
ai5wuj54z23killcuounaktpbvzwkmqvo4o6eq5ghlaerimllhnctcui4poxicprsx6vfwznhs5f24wkm4e36hmucin7g5eiag2a6324aaaybluzuqhqcamdiymin4km36ulfvqovkz44aajq5q2uk57rxicraqp2vbbdpzmzlgpyy2sij3awha5buorzgeugvlpojob4ld63tmugzlgbznpskpqm
```

Two examples of invalid, non-canonical substitutions in this vector are:

- replacing expiry varint `80 ae 99 a4 0f` with
  `80 ae 99 a4 8f 00`;
- replacing capability length `01` with `81 00`.

Both replacements encode the same logical values but MUST be rejected.

## 10. References

- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119)
- [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)
- [RFC 8032: Edwards-Curve Digital Signature Algorithm](https://www.rfc-editor.org/rfc/rfc8032)
- [RFC 4648: Base-N Encodings](https://www.rfc-editor.org/rfc/rfc4648)
- [WebAssembly unsigned integer encoding](https://webassembly.github.io/spec/core/binary/values.html#integers)
- [Postcard wire-format specification](https://postcard.jamesmunns.com/wire-format)
