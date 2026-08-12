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

use ed25519_dalek::{Signature, VerifyingKey};
use n0_error::e;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{CapabilityOrigin, DecodeError, Expires, Payload, SignatureWire, Signed};

/// The v1 domain separation tag.
pub(crate) const DST: &[u8] = b"rcan-1-delegation";

/// Reconstruct the exact v1 payload bytes from a payload: serdect length
/// prefixed keys, capability spliced raw, expiry via postcard.
pub(crate) fn v1_payload_bytes(payload: &Payload) -> Vec<u8> {
    let mut buf = Vec::new();
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
    postcard::to_extend(&payload.valid_until, buf).expect("vec")
}

/// Reconstruct the versioned v1 wire bytes, the `Rcan::encode` form of
/// rcan 0.4.x: `0x01 ++ payload ++ signature`.
pub(crate) fn v1_encode_versioned(signed: &Signed) -> Vec<u8> {
    let mut out = vec![1u8];
    out.extend_from_slice(&v1_payload_bytes(&signed.payload));
    out.extend_from_slice(&signed.signature.to_bytes());
    out
}

/// Verify a v1 signature against the reconstructed signed bytes.
pub(crate) fn v1_verify(signed: &Signed) -> Result<(), DecodeError> {
    let mut to_verify = DST.to_vec();
    to_verify.extend_from_slice(&v1_payload_bytes(&signed.payload));
    signed
        .payload
        .issuer
        .verify_strict(&to_verify, &signed.signature)
        .map_err(|_| e!(DecodeError::InvalidSignature))?;
    Ok(())
}

/// Parse a naked v1 token (`payload ++ signature`, no version byte) and
/// verify its signature: postcard deserialization of [`V1Wire`], plus
/// exact consumption. The capability type is needed to find the end of
/// the capability field.
pub(crate) fn v1_parse<C: Serialize + DeserializeOwned>(
    bytes: &[u8],
) -> Result<Signed, DecodeError> {
    let (wire, leftover) =
        postcard::take_from_bytes::<V1Wire<C>>(bytes).map_err(DecodeError::malformed)?;
    if !leftover.is_empty() {
        return Err(DecodeError::malformed(format_args!(
            "{} trailing bytes",
            leftover.len()
        )));
    }
    // No canonical check: rcan 0.4 parses v1 through lenient postcard
    // and does not reject non-minimal varints, so neither do we — a
    // stricter reader would reject tokens 0.4 minted and accepts.
    wire.into_signed()
}

struct V1VerifyingKey(VerifyingKey);

impl<'de> Deserialize<'de> for V1VerifyingKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = V1VerifyingKey;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("32 key bytes")
            }

            fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                let bytes: [u8; 32] = v
                    .try_into()
                    .map_err(|_| E::invalid_length(v.len(), &self))?;
                VerifyingKey::from_bytes(&bytes)
                    .map(V1VerifyingKey)
                    .map_err(E::custom)
            }
        }
        deserializer.deserialize_bytes(V)
    }
}

#[derive(Deserialize)]
struct V1Wire<C>(V1Payload<C>, SignatureWire);

#[derive(Deserialize)]
struct V1Payload<C> {
    issuer: V1VerifyingKey,
    audience: V1VerifyingKey,
    capability_origin: V1CapabilityOrigin,
    capability: C,
    valid_until: Expires,
}

#[derive(Deserialize)]
enum V1CapabilityOrigin {
    Issuer,
    Delegation(V1VerifyingKey),
}

impl<C: Serialize + DeserializeOwned> V1Wire<C> {
    fn into_signed(self) -> Result<Signed, DecodeError> {
        let Self(payload, signature) = self;
        let signed = Signed {
            payload: Payload {
                issuer: payload.issuer.0,
                audience: payload.audience.0,
                capability_origin: match payload.capability_origin {
                    V1CapabilityOrigin::Issuer => CapabilityOrigin::Issuer,
                    V1CapabilityOrigin::Delegation(key) => CapabilityOrigin::Delegation(key.0),
                },
                valid_until: payload.valid_until,
                capability: postcard::to_stdvec(&payload.capability)
                    .map_err(DecodeError::malformed)?,
            },
            signature: Signature::from_bytes(&signature.0),
        };
        // Verify before yielding, so a deserialized token is always
        // signature checked.
        v1_verify(&signed)?;
        Ok(signed)
    }
}
