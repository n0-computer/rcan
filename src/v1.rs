//! The v1 (rcan 0.4.x) compatibility codec.
//!
//! This module contains everything the crate knows about the v1 wire
//! format, self-contained: no dependency on the old implementation. The
//! v1 layout is frozen forever, so this code never changes; it is
//! verified against pinned wire vectors generated with the real rcan
//! 0.4.x.
//!
//! The v1 payload layout, in order:
//!
//! - issuer: `0x20 ++ 32 key bytes` (serdect length prefixed)
//! - audience: same
//! - capability origin: `0x00` (issuer) or `0x01 ++ 0x20 ++ 32 key bytes`
//! - capability: `postcard(C)`, **no length prefix** — this is why
//!   parsing v1 requires the capability type: only a typed deserialize
//!   can find the capability's end
//! - valid until: postcard `Expires` (identical encoding to ours)
//!
//! A naked v1 token is `payload ++ 64 signature bytes`; the versioned
//! form prefixes `0x01`. The signature covers `DST ++ payload`.

use ed25519_dalek::VerifyingKey;
use n0_error::e;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    append_postcard, read_signed, CapabilityOrigin, DecodeError, Expires, Payload, Signed,
};

/// The v1 domain separation tag.
pub(crate) const DST: &[u8] = b"rcan-1-delegation";

/// Reconstruct the exact v1 payload bytes from a payload: serdect length
/// prefixed keys, capability spliced raw, expiry via postcard.
pub(crate) fn v1_payload_bytes(payload: &Payload, buf: &mut Vec<u8>) {
    buf.push(32);
    buf.extend_from_slice(payload.issuer.as_bytes());
    buf.push(32);
    buf.extend_from_slice(payload.audience.as_bytes());
    match &payload.capability_origin {
        CapabilityOrigin::Issuer => buf.push(0),
        CapabilityOrigin::Delegation(key) => {
            buf.push(1);
            buf.push(32);
            buf.extend_from_slice(key.as_bytes());
        }
    }
    buf.extend_from_slice(&payload.capability);
    append_postcard(&payload.valid_until, buf);
}

pub(crate) fn parse_and_verify<C: Serialize + DeserializeOwned>(
    bytes: &[u8],
) -> Result<Signed, DecodeError> {
    let (payload, signature) = read_signed::<V1Payload<C>>(bytes)?;
    let payload: Payload = payload.into();
    let mut to_verify = DST.to_vec();
    v1_payload_bytes(&payload, &mut to_verify);
    payload
        .issuer
        .verify_strict(&to_verify, &signature)
        .map_err(|_| e!(DecodeError::InvalidSignature))?;
    Ok(Signed { payload, signature })
}

#[derive(Deserialize)]
struct V1Payload<C> {
    #[serde(with = "prefixed_key_serde")]
    issuer: VerifyingKey,
    #[serde(with = "prefixed_key_serde")]
    audience: VerifyingKey,
    capability_origin: V1CapabilityOrigin,
    capability: C,
    valid_until: Expires,
}

impl<C: Serialize> From<V1Payload<C>> for Payload {
    fn from(v1: V1Payload<C>) -> Self {
        Self {
            issuer: v1.issuer,
            audience: v1.audience,
            capability_origin: match v1.capability_origin {
                V1CapabilityOrigin::Issuer => CapabilityOrigin::Issuer,
                V1CapabilityOrigin::Delegation(key) => CapabilityOrigin::Delegation(key),
            },
            capability: postcard::to_stdvec(&v1.capability).expect("vec"),
            valid_until: v1.valid_until,
        }
    }
}

#[derive(Deserialize)]
enum V1CapabilityOrigin {
    Issuer,
    Delegation(#[serde(with = "prefixed_key_serde")] VerifyingKey),
}

/// Deserialize a [`VerifyingKey`] in v1's serdect encoding: length
/// prefixed bytes. Parse only — v1 bytes are emitted by the byte
/// recipes above, not through serde.
mod prefixed_key_serde {
    use ed25519_dalek::VerifyingKey;
    use serde::{de::Error, Deserializer};

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<VerifyingKey, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = VerifyingKey;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("32 key bytes")
            }

            fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                let bytes: [u8; 32] = v
                    .try_into()
                    .map_err(|_| E::invalid_length(v.len(), &self))?;
                VerifyingKey::from_bytes(&bytes).map_err(E::custom)
            }
        }
        deserializer.deserialize_bytes(V)
    }
}
