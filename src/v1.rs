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

use anyhow::{ensure, Context, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{CapabilityOrigin, Expires, Payload, SignatureWire, Signed};

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
pub(crate) fn v1_verify(signed: &Signed) -> Result<()> {
    let mut to_verify = DST.to_vec();
    to_verify.extend_from_slice(&v1_payload_bytes(&signed.payload));
    signed
        .payload
        .issuer
        .verify_strict(&to_verify, &signed.signature)?;
    Ok(())
}

/// Parse a naked v1 token (`payload ++ signature`, no version byte) and
/// verify its signature: postcard deserialization of [`V1Wire`], plus
/// exact consumption. The capability type is needed to find the end of
/// the capability field.
pub(crate) fn v1_parse<C: Serialize + DeserializeOwned>(bytes: &[u8]) -> Result<Signed> {
    let (wire, leftover) = postcard::take_from_bytes::<V1Wire<C>>(bytes).context("decoding v1")?;
    ensure!(
        leftover.is_empty(),
        "cannot decode v1, {} trailing bytes",
        leftover.len()
    );
    wire.into_signed()
}

/// Serde for a [`VerifyingKey`] in the v1 encoding: length prefixed
/// bytes in binary formats (what serdect produced), lowercase hex in
/// human-readable ones.
mod prefixed_key_serde {
    use ed25519_dalek::VerifyingKey;
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        key: &VerifyingKey,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.collect_str(&format_args!("{}", hex::encode(key.as_bytes())))
        } else {
            serializer.serialize_bytes(key.as_bytes())
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<VerifyingKey, D::Error> {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let mut buf = [0u8; 32];
            hex::decode_to_slice(&s, &mut buf).map_err(D::Error::custom)?;
            VerifyingKey::from_bytes(&buf).map_err(D::Error::custom)
        } else {
            struct V;
            impl serde::de::Visitor<'_> for V {
                type Value = VerifyingKey;

                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("32 key bytes")
                }

                fn visit_bytes<E: Error>(self, v: &[u8]) -> std::result::Result<Self::Value, E> {
                    let bytes: [u8; 32] = v
                        .try_into()
                        .map_err(|_| E::invalid_length(v.len(), &self))?;
                    VerifyingKey::from_bytes(&bytes).map_err(E::custom)
                }
            }
            deserializer.deserialize_bytes(V)
        }
    }
}

/// The exact wire layout of a v1 `Rcan<C>`, as plain derived serde:
/// the same field order and encodings as rcan 0.4.x, with serdect
/// replaced by the wire compatible [`prefixed_key_serde`]. A tuple
/// struct because v1's `Rcan` serialized as a 2-tuple (in JSON: an
/// array of payload and signature).

struct V1Wire<C>(V1Payload<C>, Signature);

/// Manual impls so the serde calls match v1's `Rcan` exactly: a plain
/// 2-tuple, not a tuple struct.
impl<C: Serialize> Serialize for V1Wire<C> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut tup = serializer.serialize_tuple(2)?;
        tup.serialize_element(&self.0)?;
        tup.serialize_element(&SignatureWire(self.1.to_bytes()))?;
        tup.end()
    }
}

impl<'de, C: DeserializeOwned> Deserialize<'de> for V1Wire<C> {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let (payload, SignatureWire(signature)) =
            <(V1Payload<C>, SignatureWire)>::deserialize(deserializer)?;
        Ok(Self(payload, Signature::from_bytes(&signature)))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "Payload")]
struct V1Payload<C> {
    #[serde(with = "prefixed_key_serde")]
    issuer: VerifyingKey,
    #[serde(with = "prefixed_key_serde")]
    audience: VerifyingKey,
    capability_origin: V1CapabilityOrigin,
    capability: C,
    valid_until: Expires,
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "CapabilityOrigin")]
enum V1CapabilityOrigin {
    Issuer,
    Delegation(#[serde(with = "prefixed_key_serde")] VerifyingKey),
}

impl<C: Serialize + DeserializeOwned> V1Wire<C> {
    fn into_signed(self) -> Result<Signed> {
        let Self(payload, signature) = self;
        let signed = Signed {
            payload: Payload {
                issuer: payload.issuer,
                audience: payload.audience,
                capability_origin: match payload.capability_origin {
                    V1CapabilityOrigin::Issuer => CapabilityOrigin::Issuer,
                    V1CapabilityOrigin::Delegation(key) => CapabilityOrigin::Delegation(key),
                },
                valid_until: payload.valid_until,
                capability: postcard::to_stdvec(&payload.capability)?,
            },
            signature,
        };
        // Verify before yielding, so a deserialized token is always
        // signature checked.
        v1_verify(&signed)?;
        Ok(signed)
    }
}
