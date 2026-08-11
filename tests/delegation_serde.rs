//! Serde-form tests for delegations. The binary serde form wraps the
//! wire form (`encode()`) as an opaque byte string; human-readable
//! formats use the canonical base32 string. These pin the v2 wire form
//! and the canonical strings, and check the round trips.

use ed25519_dalek::SigningKey;
use rcan::{Delegation, Expires, OpaqueDelegation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Rpc {
    Read,
    ReadWrite,
    All,
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// A deterministic v1 token: service ([0; 32]) grants alice ([1; 32])
/// everything until 4_102_444_800.
fn v1_token() -> OpaqueDelegation {
    let rcan = rcan_v1::Rcan::issuing_builder(&key(0), key(1).verifying_key(), Rpc::All)
        .sign(rcan_v1::Expires::At(4_102_444_800));
    Delegation::<Rpc>::decode(&rcan.encode())
        .unwrap()
        .into_opaque()
}

/// A deterministic v2 token: same keys, ReadWrite, same expiry.
fn v2_token() -> OpaqueDelegation {
    Delegation::issuing_builder(&key(0), key(1).verifying_key(), &Rpc::ReadWrite)
        .sign(Expires::At(4_102_444_800))
        .into()
}

/// Parse an annotated hex dump: `//` starts a comment until end of
/// line, whitespace is ignored. The syntax of hex-literal before 0.4
/// dropped comment support.
fn hexdump(s: &str) -> Vec<u8> {
    let hex: String = s
        .lines()
        .map(|line| line.split("//").next().unwrap())
        .flat_map(|hex| hex.chars())
        .filter(|c| !c.is_whitespace())
        .collect();
    hex::decode(hex).unwrap()
}

const V2_POSTCARD: &str = "
    02                                                               // version: v2
    3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29 // issuer: key(0)
    8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c // audience: key(1)
    00                                                               // capability origin: issuer
    01 80ae99a40f                                                    // valid until: at 4102444800
    01 01                                                            // capability: 1 byte, Rpc::ReadWrite
    83461886f14cdfa8b2d60eaab3ce00098761aa2bbf8dd028820fd54211bf2cca // signature (v2 DST)
    ccfc635242760b1c1d0d1d1c98943556f725c1e2c7edcd94365660e5af929f06
";

const V1_STRING: &str = "ae5wuj54z23killcuounaktpbvzwkmqvo4o6eq5ghlaerimllhnctcui4poxicprsx6vfwznhs5f24wkm4e36hmucin7g5eiag2a6324aaaybluzuqhqcat6bmqcjsxx7vs5hd5gab3gjosfvq3rjw6qavnopfynmya4xpwaiqgtfe7377sw3hvkpxw56ypjf6h3pujhf7n2zebkdw275hhwtgfqi";
const V2_STRING: &str = "ai5wuj54z23killcuounaktpbvzwkmqvo4o6eq5ghlaerimllhnctcui4poxicprsx6vfwznhs5f24wkm4e36hmucin7g5eiag2a6324aaaybluzuqhqcamdiymin4km36ulfvqovkz44aajq5q2uk57rxicraqp2vbbdpzmzlgpyy2sij3awha5buorzgeugvlpojob4ld63tmugzlgbznpskpqm";

#[test]
fn postcard_snapshots() {
    // encode() is the wire form; the binary serde form wraps it behind
    // a postcard length prefix. The v2 wire form is pinned byte-exact.
    assert_eq!(
        hex::encode(v2_token().encode()),
        hex::encode(hexdump(V2_POSTCARD))
    );

    // v2 is C-free, so it round-trips through OpaqueDelegation.
    let v2 = v2_token();
    let serde = postcard::to_stdvec(&v2).unwrap();
    assert!(serde.ends_with(&v2.encode()));
    assert_eq!(
        postcard::from_bytes::<OpaqueDelegation>(&serde).unwrap(),
        v2
    );

    // A v1 token needs its capability type, so it round-trips through
    // the typed Delegation<C>, not the C-free OpaqueDelegation.
    let v1 = Delegation::<Rpc>::decode(&v1_token().encode()).unwrap();
    let serde = postcard::to_stdvec(&v1).unwrap();
    assert!(serde.ends_with(&v1.opaque().encode()));
    assert_eq!(postcard::from_bytes::<Delegation<Rpc>>(&serde).unwrap(), v1);
}

#[test]
fn cbor_roundtrip() {
    // The binary serde form is opaque bytes, so CBOR carries no
    // structure worth pinning; check the round trip in both type layers.
    let v2 = v2_token();
    let mut bytes = Vec::new();
    ciborium::into_writer(&v2, &mut bytes).unwrap();
    assert_eq!(
        ciborium::from_reader::<OpaqueDelegation, _>(&bytes[..]).unwrap(),
        v2
    );

    let v1 = Delegation::<Rpc>::decode(&v1_token().encode()).unwrap();
    let mut bytes = Vec::new();
    ciborium::into_writer(&v1, &mut bytes).unwrap();
    assert_eq!(
        ciborium::from_reader::<Delegation<Rpc>, _>(&bytes[..]).unwrap(),
        v1
    );
}

#[test]
fn string_snapshots() {
    for (token, pinned) in [(v1_token(), V1_STRING), (v2_token(), V2_STRING)] {
        assert_eq!(token.encode_string(), pinned);
        assert_eq!(OpaqueDelegation::decode_string(pinned).unwrap(), token);

        // Human-readable formats emit the canonical string, quoted.
        let quoted = format!("{pinned:?}");
        assert_eq!(serde_json::to_string(&token).unwrap(), quoted);
        let back: OpaqueDelegation = serde_json::from_str(&quoted).unwrap();
        assert_eq!(back, token);

        assert_eq!(ron::to_string(&token).unwrap(), quoted);
        let back: OpaqueDelegation = ron::from_str(&quoted).unwrap();
        assert_eq!(back, token);
    }

    // Tampering with the string fails signature verification on decode.
    let mut bytes = data_encoding::BASE32_NOPAD
        .decode(V2_STRING.to_ascii_uppercase().as_bytes())
        .unwrap();
    let n = bytes.len();
    bytes[n - 1] ^= 1;
    let mut tampered = data_encoding::BASE32_NOPAD.encode(&bytes);
    tampered.make_ascii_lowercase();
    assert!(OpaqueDelegation::decode_string(&tampered).is_err());
}

/// The other payload shapes: a token that never expires. `Never` is a
/// single byte, so the whole valid-until field shrinks to one tag.
#[test]
fn postcard_snapshot_never() {
    const PINNED: &str = "
        02                                                               // version: v2
        3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29 // issuer: key(0)
        8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c // audience: key(1)
        00                                                               // capability origin: issuer
        00                                                               // valid until: never
        01 02                                                            // capability: 1 byte, Rpc::All
        272b3ed3ea9b4d0837c3a3fb4e7a1e234411f5febdaa32b35c499f168bc4199a // signature (v2 DST)
        7e2d4944846a0689ad5c6f89f9cff7283836f78633dd95e896aaa73fd28a490e
    ";
    let token: OpaqueDelegation =
        Delegation::issuing_builder(&key(0), key(1).verifying_key(), &Rpc::All)
            .sign(Expires::Never)
            .into();
    // PINNED is encode() (the wire form); the serde form wraps it.
    assert_eq!(hex::encode(token.encode()), hex::encode(hexdump(PINNED)));
    let serde = postcard::to_stdvec(&token).unwrap();
    assert!(serde.ends_with(&token.encode()));
    assert_eq!(
        postcard::from_bytes::<OpaqueDelegation>(&serde).unwrap(),
        token
    );
}
