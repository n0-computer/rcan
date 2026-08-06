//! Snapshot tests for the serde forms of [`Delegation`] (the top level
//! framing), for a v1 and a v2 token: bytes for postcard and CBOR, text
//! for JSON and RON. These pin the framing the way the pinned vectors
//! pin the v1 wire format.

use ed25519_dalek::SigningKey;
use rcan::{Delegation, Expires};
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
fn v1_token() -> Delegation {
    let rcan = rcan_v1::Rcan::issuing_builder(&key(0), key(1).verifying_key(), Rpc::All)
        .sign(rcan_v1::Expires::At(4_102_444_800));
    Delegation::decode_any::<Rpc>(&rcan.encode()).unwrap()
}

/// A deterministic v2 token: same keys, ReadWrite, same expiry.
fn v2_token() -> Delegation {
    Delegation::issuing_builder(&key(0), key(1).verifying_key(), &Rpc::ReadWrite)
        .sign(Expires::At(4_102_444_800))
        .into()
}

const V1_POSTCARD: &str = "013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da298a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c000180ae99a40f01027e0b2024caf7fd65d38fa6007664ba45ac3714dbd0055ae7970d6601cbbec0440d3293fbffe56d9eaa7deddf61e92f8fb7d1272fdbac902a1db5fe9cf6998b04";
const V2_POSTCARD: &str = "023b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da298a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c000180ae99a40f010183461886f14cdfa8b2d60eaab3ce00098761aa2bbf8dd028820fd54211bf2ccaccfc635242760b1c1d0d1d1c98943556f725c1e2c7edcd94365660e5af929f06";

const V1_CBOR: &str = "a1625631a2677061796c6f6164a5666973737565729820183b186a182718bc18ce18b618a4182d186218a318a818d0182a186f0d187318651832151877181d18e2184318a6183a18c0184818a1188b185918da18296861756469656e63659820188a188818e318dd18740918f1189518fd185218db182d183c18ba185d187218ca18670918bf181d189412181b18f3187418880118b40f186f185c716361706162696c6974795f6f726967696e664973737565726b76616c69645f756e74696ca16241741af48657006a6361706162696c6974798102697369676e61747572659840187e0b1820182418ca18f718fd186518d3188f18a6001876186418ba184518ac18371418db18d005185a18e718970d18660118cb18be18c018440d1832189318fb18ff18e5186d189e18aa187d18ed18df186118e9182f188f18b718d11827182f18db18ac1890182a181d18b518fe189c18f61899188b04";
const V2_CBOR: &str = "a1625632a2677061796c6f6164a5666973737565729820183b186a182718bc18ce18b618a4182d186218a318a818d0182a186f0d187318651832151877181d18e2184318a6183a18c0184818a1188b185918da18296861756469656e63659820188a188818e318dd18740918f1189518fd185218db182d183c18ba185d187218ca18670918bf181d189412181b18f3187418880118b40f186f185c716361706162696c6974795f6f726967696e664973737565726b76616c69645f756e74696ca16241741af48657006a6361706162696c6974798101697369676e61747572659840188318461818188618f1184c18df18a818b218d60e18aa18b318ce00091887186118aa182b18bf188d18d0182818820f18d518421118bf182c18ca18cc18fc18631852184218760b181c181d0d181d181c189818941835185618f7182518c118e218c718ed18cd189418361856186018e518af1892189f06";

const V1_JSON: &str = r#"{"V1":{"payload":{"issuer":"3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29","audience":"8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c","capability_origin":"Issuer","valid_until":{"At":4102444800},"capability":[2]},"signature":"7e0b2024caf7fd65d38fa6007664ba45ac3714dbd0055ae7970d6601cbbec0440d3293fbffe56d9eaa7deddf61e92f8fb7d1272fdbac902a1db5fe9cf6998b04"}}"#;
const V2_JSON: &str = r#"{"V2":{"payload":{"issuer":"3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29","audience":"8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c","capability_origin":"Issuer","valid_until":{"At":4102444800},"capability":[1]},"signature":"83461886f14cdfa8b2d60eaab3ce00098761aa2bbf8dd028820fd54211bf2ccaccfc635242760b1c1d0d1d1c98943556f725c1e2c7edcd94365660e5af929f06"}}"#;

const V1_RON: &str = r#"V1((payload:(issuer:"3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",audience:"8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",capability_origin:Issuer,valid_until:At(4102444800),capability:[2]),signature:"7e0b2024caf7fd65d38fa6007664ba45ac3714dbd0055ae7970d6601cbbec0440d3293fbffe56d9eaa7deddf61e92f8fb7d1272fdbac902a1db5fe9cf6998b04"))"#;
const V2_RON: &str = r#"V2((payload:(issuer:"3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",audience:"8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",capability_origin:Issuer,valid_until:At(4102444800),capability:[1]),signature:"83461886f14cdfa8b2d60eaab3ce00098761aa2bbf8dd028820fd54211bf2ccaccfc635242760b1c1d0d1d1c98943556f725c1e2c7edcd94365660e5af929f06"))"#;

#[test]
fn postcard_snapshots() {
    for (token, pinned) in [(v1_token(), V1_POSTCARD), (v2_token(), V2_POSTCARD)] {
        let bytes = postcard::to_stdvec(&token).unwrap();
        assert_eq!(hex::encode(&bytes), pinned);
        let back: Delegation = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, token);
    }
    // For v2 the serde form equals the wire form; for v1 it does not
    // (the wire form is the original v1 encoding).
    assert_eq!(v2_token().encode(), hex::decode(V2_POSTCARD).unwrap());
    assert_ne!(v1_token().encode(), hex::decode(V1_POSTCARD).unwrap());
}

#[test]
fn cbor_snapshots() {
    for (token, pinned) in [(v1_token(), V1_CBOR), (v2_token(), V2_CBOR)] {
        let mut bytes = Vec::new();
        ciborium::into_writer(&token, &mut bytes).unwrap();
        assert_eq!(hex::encode(&bytes), pinned);
        let back: Delegation = ciborium::from_reader(&bytes[..]).unwrap();
        assert_eq!(back, token);
    }
}

#[test]
fn json_snapshots() {
    for (token, pinned) in [(v1_token(), V1_JSON), (v2_token(), V2_JSON)] {
        assert_eq!(serde_json::to_string(&token).unwrap(), pinned);
        let back: Delegation = serde_json::from_str(pinned).unwrap();
        assert_eq!(back, token);
    }
}

#[test]
fn ron_snapshots() {
    for (token, pinned) in [(v1_token(), V1_RON), (v2_token(), V2_RON)] {
        assert_eq!(ron::to_string(&token).unwrap(), pinned);
        let back: Delegation = ron::from_str(pinned).unwrap();
        assert_eq!(back, token);
    }
}
