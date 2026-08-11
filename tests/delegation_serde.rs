//! Snapshot tests for the serde forms of [`OpaqueDelegation`] (the top level
//! framing), for a v1 and a v2 token: bytes for postcard and CBOR, text
//! for JSON and RON. These pin the framing the way the pinned vectors
//! pin the v1 wire format.

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

const V1_POSTCARD: &str = "
    01                                                               // version: v1
    3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29 // issuer: key(0)
    8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c // audience: key(1)
    00                                                               // capability origin: issuer
    01 80ae99a40f                                                    // valid until: at 4102444800
    01 02                                                            // capability: 1 byte, Rpc::All
    7e0b2024caf7fd65d38fa6007664ba45ac3714dbd0055ae7970d6601cbbec044 // signature (v1 DST)
    0d3293fbffe56d9eaa7deddf61e92f8fb7d1272fdbac902a1db5fe9cf6998b04
";
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

const V1_CBOR: &str = r#"
    a1                                                               // map(1): the version discriminator
    625631                                                           // key: text "V1"
    a2                                                               // map(2): Signed
    677061796c6f6164                                                 // key: text "payload"
    a5                                                               // map(5): Payload
    66697373756572                                                   // key: text "issuer"
    9820                                                             // array(32)
    183b186a182718bc18ce18b618a4182d186218a318a818d0182a186f0d187318 // key(0) bytes, one CBOR uint each
    651832151877181d18e2184318a6183a18c0184818a1188b185918da1829
    6861756469656e6365                                               // key: text "audience"
    9820                                                             // array(32)
    188a188818e318dd18740918f1189518fd185218db182d183c18ba185d187218 // key(1) bytes, one CBOR uint each
    ca18670918bf181d189412181b18f3187418880118b40f186f185c
    716361706162696c6974795f6f726967696e                             // key: text "capability_origin"
    66497373756572                                                   // unit variant: text "Issuer"
    6b76616c69645f756e74696c                                         // key: text "valid_until"
    a1                                                               // map(1): Expires
    624174                                                           // key: text "At"
    1af4865700                                                       // uint32 4102444800
    6a6361706162696c697479                                           // key: text "capability"
    81                                                               // array(1)
    02                                                               // capability: Rpc::All
    697369676e6174757265                                             // key: text "signature"
    9840                                                             // array(64)
    187e0b1820182418ca18f718fd186518d3188f18a6001876186418ba184518ac // signature bytes, one CBOR uint each
    18371418db18d005185a18e718970d18660118cb18be18c018440d1832189318
    fb18ff18e5186d189e18aa187d18ed18df186118e9182f188f18b718d1182718
    2f18db18ac1890182a181d18b518fe189c18f61899188b04
"#;
const V2_CBOR: &str = r#"
    a1                                                               // map(1): the version discriminator
    625632                                                           // key: text "V2"
    a2                                                               // map(2): Signed
    677061796c6f6164                                                 // key: text "payload"
    a5                                                               // map(5): Payload
    66697373756572                                                   // key: text "issuer"
    9820                                                             // array(32)
    183b186a182718bc18ce18b618a4182d186218a318a818d0182a186f0d187318 // key(0) bytes, one CBOR uint each
    651832151877181d18e2184318a6183a18c0184818a1188b185918da1829
    6861756469656e6365                                               // key: text "audience"
    9820                                                             // array(32)
    188a188818e318dd18740918f1189518fd185218db182d183c18ba185d187218 // key(1) bytes, one CBOR uint each
    ca18670918bf181d189412181b18f3187418880118b40f186f185c
    716361706162696c6974795f6f726967696e                             // key: text "capability_origin"
    66497373756572                                                   // unit variant: text "Issuer"
    6b76616c69645f756e74696c                                         // key: text "valid_until"
    a1                                                               // map(1): Expires
    624174                                                           // key: text "At"
    1af4865700                                                       // uint32 4102444800
    6a6361706162696c697479                                           // key: text "capability"
    81                                                               // array(1)
    01                                                               // capability: Rpc::ReadWrite
    697369676e6174757265                                             // key: text "signature"
    9840                                                             // array(64)
    188318461818188618f1184c18df18a818b218d60e18aa18b318ce0009188718 // signature bytes, one CBOR uint each
    6118aa182b18bf188d18d0182818820f18d518421118bf182c18ca18cc18fc18
    631852184218760b181c181d0d181d181c189818941835185618f7182518c118
    e218c718ed18cd189418361856186018e518af1892189f06
"#;

const V1_STRING: &str = "ae5wuj54z23killcuounaktpbvzwkmqvo4o6eq5ghlaerimllhnctcui4poxicprsx6vfwznhs5f24wkm4e36hmucin7g5eiag2a6324aaaybluzuqhqcat6bmqcjsxx7vs5hd5gab3gjosfvq3rjw6qavnopfynmya4xpwaiqgtfe7377sw3hvkpxw56ypjf6h3pujhf7n2zebkdw275hhwtgfqi";
const V2_STRING: &str = "ai5wuj54z23killcuounaktpbvzwkmqvo4o6eq5ghlaerimllhnctcui4poxicprsx6vfwznhs5f24wkm4e36hmucin7g5eiag2a6324aaaybluzuqhqcamdiymin4km36ulfvqovkz44aajq5q2uk57rxicraqp2vbbdpzmzlgpyy2sij3awha5buorzgeugvlpojob4ld63tmugzlgbznpskpqm";

#[test]
fn postcard_snapshots() {
    for (token, pinned) in [(v1_token(), V1_POSTCARD), (v2_token(), V2_POSTCARD)] {
        let bytes = postcard::to_stdvec(&token).unwrap();
        assert_eq!(hex::encode(&bytes), hex::encode(hexdump(pinned)));
        let back: OpaqueDelegation = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, token);
    }
    // For v2 the serde form equals the wire form; for v1 it does not
    // (the wire form is the original v1 encoding).
    assert_eq!(v2_token().encode(), hexdump(V2_POSTCARD));
    assert_ne!(v1_token().encode(), hexdump(V1_POSTCARD));
}

#[test]
fn cbor_snapshots() {
    for (token, pinned) in [(v1_token(), V1_CBOR), (v2_token(), V2_CBOR)] {
        let mut bytes = Vec::new();
        ciborium::into_writer(&token, &mut bytes).unwrap();
        assert_eq!(hex::encode(&bytes), hex::encode(hexdump(pinned)));
        let back: OpaqueDelegation = ciborium::from_reader(&bytes[..]).unwrap();
        assert_eq!(back, token);
    }
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
    let bytes = postcard::to_stdvec(&token).unwrap();
    assert_eq!(hex::encode(&bytes), hex::encode(hexdump(PINNED)));
    let back: OpaqueDelegation = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(back, token);
}
