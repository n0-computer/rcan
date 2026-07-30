use ed25519_dalek::{Signature, SIGNATURE_LENGTH};
use serde::{Deserialize, Serialize};

use crate::{Payload, Rcan, VERSION};

impl<C: Serialize> Serialize for Rcan<C> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeTuple;
        let mut tup = serializer.serialize_tuple(3)?;
        tup.serialize_element(&VERSION)?;
        tup.serialize_element(&self.payload)?;
        tup.serialize_element(&SignatureWire(self.signature.to_bytes()))?;
        tup.end()
    }
}

impl<'de, C: Deserialize<'de> + Serialize> Deserialize<'de> for Rcan<C> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct RcanVisitor<C>(std::marker::PhantomData<C>);

        impl<'de, C: Deserialize<'de> + Serialize> serde::de::Visitor<'de> for RcanVisitor<C> {
            type Value = Rcan<C>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an rcan token (payload, signature)")
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let version: u8 = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                if version != VERSION {
                    return Err(serde::de::Error::custom(format!(
                        "version not supported, got {version}, but only supporting {VERSION}"
                    )));
                }
                let payload: Payload<C> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                let SignatureWire(sig_bytes) = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                let rcan = Rcan {
                    payload,
                    signature: Signature::from_bytes(&sig_bytes),
                };

                // Verify before yielding, so a deserialized `Rcan` is
                // always signature checked. Without this, serde wire
                // formats hand back an unverified token while only
                // `decode` checks the signature.
                rcan.verify_signature().map_err(serde::de::Error::custom)?;

                Ok(rcan)
            }
        }

        deserializer.deserialize_tuple(3, RcanVisitor::<C>(std::marker::PhantomData))
    }
}

/// Stable serde for [`VerifyingKey`]: length-prefixed bytes in binary
/// formats, lowercase hex in human-readable ones. Goes through
/// [`serdect`] for its constant-time hex codec, and pins the wire
/// format independent of [`ed25519_dalek`]'s own serde impl.
pub(crate) mod verifying_key_serde {
    use ed25519_dalek::VerifyingKey;
    use serde::{de::Error, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        key: &VerifyingKey,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serdect::array::serialize_hex_lower_or_bin(key.as_bytes(), serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<VerifyingKey, D::Error> {
        let mut buf = [0u8; 32];
        serdect::array::deserialize_hex_or_bin(&mut buf, deserializer)?;
        VerifyingKey::from_bytes(&buf).map_err(D::Error::custom)
    }
}

/// Wire-format wrapper around an ed25519 [`Signature`] that serializes as
/// a fixed-length tuple of `SIGNATURE_LENGTH` bytes (no length prefix in
/// binary formats like postcard), and as a lowercase hex string in
/// human-readable formats.
struct SignatureWire([u8; SIGNATURE_LENGTH]);

impl Serialize for SignatureWire {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.collect_str(&format_args!("{}", hex::encode(self.0)))
        } else {
            use serde::ser::SerializeTuple;
            let mut tup = serializer.serialize_tuple(SIGNATURE_LENGTH)?;
            for b in &self.0 {
                tup.serialize_element(b)?;
            }
            tup.end()
        }
    }
}

impl<'de> Deserialize<'de> for SignatureWire {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = SignatureWire;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "an ed25519 signature ({} bytes)", SIGNATURE_LENGTH)
            }

            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> std::result::Result<Self::Value, E> {
                let mut bytes = [0u8; SIGNATURE_LENGTH];
                hex::decode_to_slice(v, &mut bytes).map_err(E::custom)?;
                Ok(SignatureWire(bytes))
            }

            fn visit_bytes<E: serde::de::Error>(
                self,
                v: &[u8],
            ) -> std::result::Result<Self::Value, E> {
                if v.len() != SIGNATURE_LENGTH {
                    return Err(E::invalid_length(v.len(), &self));
                }
                let mut bytes = [0u8; SIGNATURE_LENGTH];
                bytes.copy_from_slice(v);
                Ok(SignatureWire(bytes))
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = [0u8; SIGNATURE_LENGTH];
                for (i, slot) in bytes.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(SignatureWire(bytes))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(V)
        } else {
            deserializer.deserialize_tuple(SIGNATURE_LENGTH, V)
        }
    }
}
