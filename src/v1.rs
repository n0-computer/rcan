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

use anyhow::{bail, ensure, Context, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{CapabilityOrigin, Delegation, Expires, Payload, Signed, SignatureWire};

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
    let (wire, leftover) =
        postcard::take_from_bytes::<V1Wire<C>>(bytes).context("decoding v1")?;
    ensure!(
        leftover.is_empty(),
        "cannot decode v1, {} trailing bytes",
        leftover.len()
    );
    wire.into_signed()
}

/// A wrapper around [`Delegation`] whose postcard serialization is byte
/// identical to a naked v1 `Rcan` of rcan 0.4.x, for use in message
/// schemas that must stay wire compatible with v1 peers.
///
/// The invariant, enforced at construction: the wrapped token is a v1
/// token whose capability bytes parse in the vocabulary `C`. A v2 token
/// has no v1 signature and cannot be represented; foreign vocabulary
/// bytes would produce a well formed v1 token the receiving `C` typed
/// peer rejects.
///
/// Wire compatibility covers both of v1's serde dialects: postcard
/// (byte identical) and human readable formats like JSON (hex keys and
/// signature, matching serdect's output). Other binary formats are
/// unspecified.
pub struct V1Compat<C>(Delegation, std::marker::PhantomData<C>);

/// Fails if the token is not v1, or if its capability bytes are not a
/// canonical `C` encoding.
impl<C: DeserializeOwned> TryFrom<Delegation> for V1Compat<C> {
    type Error = anyhow::Error;

    fn try_from(delegation: Delegation) -> Result<Self> {
        ensure!(
            delegation.is_v1(),
            "only a v1 token can be serialized in v1 compatible form"
        );
        match postcard::take_from_bytes::<C>(delegation.capability()) {
            Ok((_, [])) => Ok(Self(delegation, std::marker::PhantomData)),
            _ => bail!("capability does not parse in the wrapper's vocabulary"),
        }
    }
}

impl<C> V1Compat<C> {
    pub fn delegation(&self) -> &Delegation {
        &self.0
    }

    pub fn into_inner(self) -> Delegation {
        self.0
    }
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
                    let bytes: [u8; 32] =
                        v.try_into().map_err(|_| E::invalid_length(v.len(), &self))?;
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
///
/// [`V1Compat`] serializes by converting the inner delegation into this
/// struct (parsing the opaque capability bytes as `C`), and
/// deserializes by converting back. Postcard's deterministic encoding
/// makes the round trip through the typed capability byte exact.
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
    fn from_signed(signed: &Signed) -> Result<Self> {
        let (capability, leftover) = postcard::take_from_bytes::<C>(&signed.payload.capability)
            .context("capability does not parse in the wrapper's vocabulary")?;
        ensure!(
            leftover.is_empty(),
            "capability does not parse in the wrapper's vocabulary"
        );
        Ok(Self(
            V1Payload {
                issuer: signed.payload.issuer,
                audience: signed.payload.audience,
                capability_origin: match &signed.payload.capability_origin {
                    CapabilityOrigin::Issuer => V1CapabilityOrigin::Issuer,
                    CapabilityOrigin::Delegation(key) => V1CapabilityOrigin::Delegation(*key),
                },
                capability,
                valid_until: signed.payload.valid_until.clone(),
            },
            signed.signature,
        ))
    }

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

impl<C: Serialize + DeserializeOwned> Serialize for V1Compat<C> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let wire = V1Wire::<C>::from_signed(self.0.signed()).map_err(serde::ser::Error::custom)?;
        wire.serialize(serializer)
    }
}

impl<'de, C: Serialize + DeserializeOwned> Deserialize<'de> for V1Compat<C> {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        use serde::de::Error;
        let wire = V1Wire::<C>::deserialize(deserializer)?;
        let signed = wire.into_signed().map_err(D::Error::custom)?;
        Ok(Self(Delegation::from_v1(signed), std::marker::PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{key, Rpc, V1_LINK_NAKED, V1_LINK_VERSIONED, V1_ROOT_NAKED};

    #[test]
    fn v1_compat_is_byte_identical_to_naked_v1() {
        for naked_hex in [V1_ROOT_NAKED, V1_LINK_NAKED] {
            let naked = hex::decode(naked_hex).unwrap();
            let delegation = Delegation::decode_any::<Rpc>(&naked).unwrap();

            // Serializing through the wrapper is byte identical to what
            // an old codebase produces with naked v1 serde.
            let compat = V1Compat::<Rpc>::try_from(delegation.clone()).unwrap();
            assert_eq!(postcard::to_stdvec(&compat).unwrap(), naked);

            // And the wrapper reads what an old codebase sends.
            let read: V1Compat<Rpc> = postcard::from_bytes(&naked).unwrap();
            assert_eq!(read.delegation(), &delegation);
        }

        // Old style and new style message schemas are wire compatible in
        // both directions: something after the token survives.
        let naked = hex::decode(V1_LINK_NAKED).unwrap();
        let delegation = Delegation::decode_any::<Rpc>(&naked).unwrap();
        let compat = V1Compat::<Rpc>::try_from(delegation.clone()).unwrap();
        let message = postcard::to_stdvec(&(&compat, "hello")).unwrap();
        let mut expected = naked.clone();
        expected.extend_from_slice(&postcard::to_stdvec(&"hello").unwrap());
        assert_eq!(message, expected);
        let (read, note): (V1Compat<Rpc>, String) = postcard::from_bytes(&message).unwrap();
        assert_eq!(read.delegation(), &delegation);
        assert_eq!(note, "hello");

        // A tampered token is rejected on deserialization.
        let mut tampered = hex::decode(V1_ROOT_NAKED).unwrap();
        let capability_offset = 33 + 33 + 1;
        tampered[capability_offset] = 0;
        assert!(postcard::from_bytes::<V1Compat<Rpc>>(&tampered).is_err());
    }

    #[test]
    fn v1_compat_construction_is_checked() {
        // A v2 token cannot be represented in v1 compatible form.
        let v2_token = Delegation::issuing_builder(&key(0), key(1).verifying_key(), &Rpc::All)
            .sign(Expires::Never);
        assert!(V1Compat::<Rpc>::try_from(v2_token).is_err());

        // Nor can a v1 token whose capability bytes are a different
        // vocabulary.
        #[derive(Debug, Serialize, Deserialize)]
        struct OtherVocabulary {
            topic: String,
            write: bool,
        }
        let versioned = hex::decode(V1_LINK_VERSIONED).unwrap();
        let foreign = Delegation::decode_any::<Rpc>(&versioned).unwrap();
        assert!(V1Compat::<OtherVocabulary>::try_from(foreign).is_err());
    }
}
