//! Tests the v1 compat codec against the real v1 implementation (the
//! last v1 commit, as a renamed git dev-dependency).
//!
//! For a matrix of vocabularies, origins, expiries and keys: build a
//! token with the real v1 crate, then assert that our codec agrees with
//! it byte for byte in every direction.

use ed25519_dalek::SigningKey;
use rcan::{Delegation, Expires, V1Compat};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Rpc {
    Read,
    ReadWrite,
    All,
}

/// A structurally richer vocabulary, to exercise variable length
/// capability bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Scoped {
    topic: String,
    write: bool,
    limit: Option<u64>,
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// Assert that our codec agrees with the real v1 implementation about
/// this token, in every direction.
fn check_against_oracle<C: Serialize + serde::de::DeserializeOwned>(rcan: &rcan_v1::Rcan<C>) {
    let naked = postcard::to_stdvec(rcan).unwrap();
    let versioned = rcan.encode();

    // Both wire forms decode to equal values.
    let delegation = Delegation::decode_any::<C>(&versioned).unwrap();
    let from_naked = Delegation::decode_any::<C>(&naked).unwrap();
    assert_eq!(delegation, from_naked);

    // encode reproduces the versioned form exactly.
    assert_eq!(delegation.encode(), versioned);

    // Envelope accessors agree with the oracle.
    assert_eq!(delegation.issuer().as_bytes(), rcan.issuer().as_bytes());
    assert_eq!(delegation.audience().as_bytes(), rcan.audience().as_bytes());
    assert_eq!(
        delegation.capability_issuer().as_bytes(),
        rcan.capability_issuer().as_bytes()
    );
    let expires = match rcan.expires() {
        rcan_v1::Expires::Never => Expires::Never,
        rcan_v1::Expires::At(at) => Expires::At(*at),
    };
    assert_eq!(delegation.expires(), &expires);
    assert_eq!(
        delegation.capability(),
        postcard::to_stdvec(rcan.capability()).unwrap()
    );

    // V1Compat serializes byte identically to the oracle's naked serde.
    let compat = V1Compat::<C>::try_from(delegation.clone()).unwrap();
    assert_eq!(postcard::to_stdvec(&compat).unwrap(), naked);

    // V1Compat reads what the oracle writes.
    let read: V1Compat<C> = postcard::from_bytes(&naked).unwrap();
    assert_eq!(read.delegation(), &delegation);

    // And the oracle reads what V1Compat writes (trivially, same bytes;
    // this closes the loop through the real deserializer).
    let back: rcan_v1::Rcan<C> = postcard::from_bytes(&naked).unwrap();
    assert_eq!(back.encode(), versioned);

    // The human readable dialect matches too: identical JSON in both
    // directions.
    let oracle_json = serde_json::to_string(rcan).unwrap();
    assert_eq!(serde_json::to_string(&compat).unwrap(), oracle_json);
    let read: V1Compat<C> = serde_json::from_str(&oracle_json).unwrap();
    assert_eq!(read.delegation(), &delegation);
    let back: rcan_v1::Rcan<C> =
        serde_json::from_str(&serde_json::to_string(&compat).unwrap()).unwrap();
    assert_eq!(back.encode(), versioned);

    // CBOR: a binary format that, unlike postcard, is self describing —
    // identical bytes in both directions.
    let mut oracle_cbor = Vec::new();
    ciborium::into_writer(rcan, &mut oracle_cbor).unwrap();
    let mut compat_cbor = Vec::new();
    ciborium::into_writer(&compat, &mut compat_cbor).unwrap();
    assert_eq!(compat_cbor, oracle_cbor);
    let read: V1Compat<C> = ciborium::from_reader(&oracle_cbor[..]).unwrap();
    assert_eq!(read.delegation(), &delegation);
    let back: rcan_v1::Rcan<C> = ciborium::from_reader(&compat_cbor[..]).unwrap();
    assert_eq!(back.encode(), versioned);

    // RON: a human readable format that preserves more structure than
    // JSON — identical strings in both directions.
    let oracle_ron = ron::to_string(rcan).unwrap();
    assert_eq!(ron::to_string(&compat).unwrap(), oracle_ron);
    let read: V1Compat<C> = ron::from_str(&oracle_ron).unwrap();
    assert_eq!(read.delegation(), &delegation);
    let back: rcan_v1::Rcan<C> = ron::from_str(&ron::to_string(&compat).unwrap()).unwrap();
    assert_eq!(back.encode(), versioned);
}

#[test]
fn oracle_rpc_matrix() {
    let expiries = [
        rcan_v1::Expires::Never,
        rcan_v1::Expires::At(0),
        rcan_v1::Expires::At(4_102_444_800),
        rcan_v1::Expires::At(u64::MAX),
    ];
    let caps = [Rpc::Read, Rpc::ReadWrite, Rpc::All];

    for (i, expires) in expiries.iter().enumerate() {
        for (j, cap) in caps.iter().enumerate() {
            let issuer = key(1 + i as u8);
            let audience = key(100 + j as u8).verifying_key();
            let owner = key(200).verifying_key();

            let issued =
                rcan_v1::Rcan::issuing_builder(&issuer, audience, *cap).sign(expires.clone());
            check_against_oracle(&issued);

            let delegated = rcan_v1::Rcan::delegating_builder(&issuer, audience, owner, *cap)
                .sign(expires.clone());
            check_against_oracle(&delegated);
        }
    }
}

#[test]
fn oracle_variable_length_capabilities() {
    for (i, topic) in ["", "a", "some/long/topic/with/segments", &"x".repeat(200)]
        .iter()
        .enumerate()
    {
        let cap = Scoped {
            topic: topic.to_string(),
            write: i % 2 == 0,
            limit: if i % 2 == 0 { None } else { Some(1 << 40) },
        };
        let issuer = key(10 + i as u8);
        let audience = key(50).verifying_key();

        let issued = rcan_v1::Rcan::issuing_builder(&issuer, audience, cap.clone())
            .sign(rcan_v1::Expires::At(1_800_000_000));
        check_against_oracle(&issued);

        let delegated =
            rcan_v1::Rcan::delegating_builder(&issuer, audience, key(60).verifying_key(), cap)
                .sign(rcan_v1::Expires::Never);
        check_against_oracle(&delegated);
    }
}
