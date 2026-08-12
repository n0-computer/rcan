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

const V1_STRING: &str = "aeqdw2rhxthlnjbnmkr2rubkn4gxgzjscv3r3ysduy5masfbrnm5ukjarkeohxlubhyzl7ks3mwtzos5olfgocn7dwkbeg7toseadnapn5oaaaqbqcxjtjappyfsajgk676wlu4puyahmzf2iwwdofg32acvvz4xbvtads56ybca2mut7p76k3m6vj663x3b5exy7n6re4x5xleqfio3l7u462mywba";
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
    // v2 round-trips through the C-free OpaqueDelegation.
    let v2 = v2_token();
    assert_eq!(v2.encode_string(), V2_STRING);
    assert_eq!(OpaqueDelegation::decode_string(V2_STRING).unwrap(), v2);
    let quoted = format!("{V2_STRING:?}");
    assert_eq!(serde_json::to_string(&v2).unwrap(), quoted);
    assert_eq!(
        serde_json::from_str::<OpaqueDelegation>(&quoted).unwrap(),
        v2
    );
    assert_eq!(ron::to_string(&v2).unwrap(), quoted);
    assert_eq!(ron::from_str::<OpaqueDelegation>(&quoted).unwrap(), v2);

    // A v1 token needs its capability type: through Delegation<Rpc>.
    let v1 = Delegation::<Rpc>::decode(&v1_token().encode()).unwrap();
    assert_eq!(v1.opaque().encode_string(), V1_STRING);
    assert_eq!(Delegation::<Rpc>::decode_string(V1_STRING).unwrap(), v1);
    let quoted = format!("{V1_STRING:?}");
    assert_eq!(serde_json::to_string(&v1).unwrap(), quoted);
    assert_eq!(
        serde_json::from_str::<Delegation<Rpc>>(&quoted).unwrap(),
        v1
    );
    assert_eq!(ron::to_string(&v1).unwrap(), quoted);
    assert_eq!(ron::from_str::<Delegation<Rpc>>(&quoted).unwrap(), v1);

    // The C-free OpaqueDelegation cannot read a v1 string.
    assert!(OpaqueDelegation::decode_string(V1_STRING).is_err());

    // Tampering with the string fails on decode.
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

// Non-canonical v2 encodings: the same token value with a non-minimal
// varint somewhere. The signature is the valid one over the canonical
// payload; each is still rejected, because canonicality is a byte check
// against the re-encoding, not a signature check.

const V2_NC_VERSION: &str = "
    82 00                                                            // version: v2 (overlong: 0x82 0x00)
    3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29 // issuer: key(0)
    8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c // audience: key(1)
    00                                                               // capability origin: issuer
    01 80ae99a40f                                                    // valid until: at 4102444800
    01 01                                                            // capability: 1 byte, Rpc::ReadWrite
    83461886f14cdfa8b2d60eaab3ce00098761aa2bbf8dd028820fd54211bf2cca // signature (over the canonical form)
    ccfc635242760b1c1d0d1d1c98943556f725c1e2c7edcd94365660e5af929f06
";
const V2_NC_EXPIRY: &str = "
    02                                                               // version: v2
    3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29 // issuer: key(0)
    8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c // audience: key(1)
    00                                                               // capability origin: issuer
    01 80ae99a48f00                                                  // valid until: at 4102444800 (overlong varint)
    01 01                                                            // capability: 1 byte, Rpc::ReadWrite
    83461886f14cdfa8b2d60eaab3ce00098761aa2bbf8dd028820fd54211bf2cca // signature (over the canonical form)
    ccfc635242760b1c1d0d1d1c98943556f725c1e2c7edcd94365660e5af929f06
";
const V2_NC_CAP_LEN: &str = "
    02                                                               // version: v2
    3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29 // issuer: key(0)
    8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c // audience: key(1)
    00                                                               // capability origin: issuer
    01 80ae99a40f                                                    // valid until: at 4102444800
    81 00 01                                                         // capability: len 1 (overlong 0x81 0x00), Rpc::ReadWrite
    83461886f14cdfa8b2d60eaab3ce00098761aa2bbf8dd028820fd54211bf2cca // signature (over the canonical form)
    ccfc635242760b1c1d0d1d1c98943556f725c1e2c7edcd94365660e5af929f06
";

#[test]
fn v2_rejects_non_canonical() {
    // Sanity: the canonical form decodes, so the vectors below fail on
    // canonicality, not on some unrelated error.
    assert!(OpaqueDelegation::decode(&hexdump(V2_POSTCARD)).is_ok());
    for nc in [V2_NC_VERSION, V2_NC_EXPIRY, V2_NC_CAP_LEN] {
        let err = OpaqueDelegation::decode(&hexdump(nc)).unwrap_err();
        // Rejected on canonicality specifically, not signature or parse.
        assert!(
            err.to_string().contains("canonical"),
            "expected a non-canonical error, got: {err}"
        );
    }
}

// v1 is read as leniently as rcan 0.4 wrote it: a non-minimal varint is
// accepted, because the frozen 0.4 codec does not reject one and we must
// not reject tokens it minted. Same layout as the canonical v1 root, but
// the expiry varint is overlong; the signature is over the canonical
// payload, which v1 verify reconstructs.
const V1_NC_EXPIRY: &str = "
    01                                                                  // version: v1
    20 3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29 // issuer (serdect len + key)
    20 8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c // audience
    00                                                                  // capability origin: issuer
    02                                                                  // capability: Rpc::All (unprefixed)
    01 80ae99a48f00                                                     // valid until: at 4102444800 (overlong varint)
    7e0b2024caf7fd65d38fa6007664ba45ac3714dbd0055ae7970d6601cbbec044   // signature (over the canonical form)
    0d3293fbffe56d9eaa7deddf61e92f8fb7d1272fdbac902a1db5fe9cf6998b04
";

#[test]
fn v1_accepts_non_canonical() {
    let canonical = Delegation::<Rpc>::decode(&v1_token().encode()).unwrap();
    let lenient = Delegation::<Rpc>::decode(&hexdump(V1_NC_EXPIRY)).unwrap();
    assert_eq!(lenient, canonical);
}
