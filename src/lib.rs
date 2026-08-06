//! RCANs: really simple user Controlled Authorization Networks.
//!
//! A [`Delegation`] is a [`Payload`] plus the issuer's signature over it.
//! The payload has five fields: issuer, audience, capability origin,
//! expiry, and the capability as opaque, length delimited bytes. The
//! envelope never interprets the capability: typing happens at the
//! edges, via the [`Capability`] trait.
//!
//! The wire format is versioned coarsely by a leading version byte,
//! which doubles as the discriminator of the internal version enum.
//! The current version is 2. Version 1 (the `Rcan<C>` of rcan 0.4.x)
//! can be read via [`Delegation::decode_any`] and represented losslessly;
//! writing the naked v1 serde form for frozen message schemas is done
//! via [`V1Compat`].

mod v1;

pub use v1::V1Compat;

// TODO: better error management (n0-error?)
use anyhow::{bail, ensure, Context, Result};
use ed25519_dalek::{
    ed25519::signature::Signer, Signature, SigningKey, VerifyingKey, SIGNATURE_LENGTH,
};
use n0_future::time::{Duration, SystemTime};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Domain separation tag for v2 signatures.
pub const DST: &[u8] = b"rcan-2-delegation";

/// Stable serde for [`VerifyingKey`]: 32 raw bytes in binary formats (no
/// length prefix — the length is fixed), lowercase hex in human-readable
/// ones. Pins the wire format independent of [`ed25519_dalek`]'s own
/// serde impl.
pub(crate) mod verifying_key_serde {
    use ed25519_dalek::VerifyingKey;
    use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        key: &VerifyingKey,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.collect_str(&format_args!("{}", hex::encode(key.as_bytes())))
        } else {
            key.as_bytes().serialize(serializer)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<VerifyingKey, D::Error> {
        let buf: [u8; 32] = if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let mut buf = [0u8; 32];
            hex::decode_to_slice(&s, &mut buf).map_err(D::Error::custom)?;
            buf
        } else {
            <[u8; 32]>::deserialize(deserializer)?
        };
        VerifyingKey::from_bytes(&buf).map_err(D::Error::custom)
    }
}

/// Wire-format wrapper around an ed25519 [`Signature`] that serializes as
/// a fixed-length tuple of `SIGNATURE_LENGTH` bytes (no length prefix in
/// binary formats like postcard), and as a lowercase hex string in
/// human-readable formats.
pub(crate) struct SignatureWire(pub(crate) [u8; SIGNATURE_LENGTH]);

impl Serialize for SignatureWire {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.collect_str(&format_args!("{}", hex::encode(self.0)))
        } else {
            // A flat tuple of 64 bytes, like v1's SignatureWire: serde
            // has no built-in impls for arrays over 32, hence the loop
            // and the visitor below.
            use serde::ser::SerializeTuple;
            let mut tup = serializer.serialize_tuple(SIGNATURE_LENGTH)?;
            for byte in &self.0 {
                tup.serialize_element(byte)?;
            }
            tup.end()
        }
    }
}

impl<'de> Deserialize<'de> for SignatureWire {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        use serde::de::Error;
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let mut bytes = [0u8; SIGNATURE_LENGTH];
            hex::decode_to_slice(&s, &mut bytes).map_err(D::Error::custom)?;
            Ok(SignatureWire(bytes))
        } else {
            struct V;
            impl<'de> serde::de::Visitor<'de> for V {
                type Value = SignatureWire;

                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    write!(f, "an ed25519 signature ({SIGNATURE_LENGTH} bytes)")
                }

                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut seq: A,
                ) -> std::result::Result<Self::Value, A::Error> {
                    let mut bytes = [0u8; SIGNATURE_LENGTH];
                    for (i, slot) in bytes.iter_mut().enumerate() {
                        *slot = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                    }
                    Ok(SignatureWire(bytes))
                }
            }
            deserializer.deserialize_tuple(SIGNATURE_LENGTH, V)
        }
    }
}

/// Serde for an ed25519 [`Signature`] via [`SignatureWire`], as a field
/// attribute.
pub(crate) mod signature_serde {
    use ed25519_dalek::Signature;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::SignatureWire;

    pub fn serialize<S: Serializer>(
        signature: &Signature,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        SignatureWire(signature.to_bytes()).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Signature, D::Error> {
        let SignatureWire(bytes) = SignatureWire::deserialize(deserializer)?;
        Ok(Signature::from_bytes(&bytes))
    }
}

/// A trait for types that define a capability.
///
/// Capabilities can be compared using [`Capability::permits`], which determines
/// whether one capability grants permission to perform another.
///
/// A common implementation of this trait might be an enum representing different
/// RPC request types.
///
/// The `Capability` type must be serializable so it can be included in the signature
/// payload of a [`Delegation`].
///
/// An issuer key must not sign delegations in more than one capability
/// vocabulary, unless the vocabulary self-discriminates: delegations
/// store capabilities as opaque bytes, so nothing else prevents two
/// vocabularies from colliding on the same encoding.
pub trait Capability: Serialize + DeserializeOwned {
    /// Determines if `self` permits `other`.
    ///
    /// Returns `true` if `self` grants permission to perform the `other` capability,
    /// otherwise returns `false`.
    fn permits(&self, other: &Self) -> bool;
}

/// The potential origins of a capability.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum CapabilityOrigin {
    /// The origin is the issuer itself
    Issuer,
    /// This is a delegation, with this key being the root of the delegation chain.
    Delegation(#[serde(with = "verifying_key_serde")] VerifyingKey),
}

/// When a delegation expires
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, derive_more::Display)]
pub enum Expires {
    /// Never expires
    #[display("never")]
    Never,
    /// Valid until given unix timestamp in seconds
    #[display("{_0}")]
    At(u64),
}

impl Expires {
    pub fn valid_for(duration: Duration) -> Self {
        Self::At(
            (SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("now is after UNIX_EPOCH")
                + duration)
                .as_secs(),
        )
    }

    pub fn is_valid_at(&self, time: SystemTime) -> bool {
        let time = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("time must be after UNIX_EPOCH")
            .as_secs();
        match self {
            Expires::Never => true,
            Expires::At(expiry) => *expiry >= time,
        }
    }
}

/// The signed content of a [`Delegation`].
///
/// One struct serves every version: v1 and v2 tokens differ only in
/// their wire encodings and signature domains, not in their fields. The
/// serde derive is the v2 wire layout; the v1 layout is produced and
/// parsed by the v1 compat recipes.
#[derive(Clone, Serialize, Deserialize, derive_more::Debug, PartialEq, Eq)]
pub struct Payload {
    /// The issuer
    #[debug("{}", hex::encode(issuer))]
    #[serde(with = "verifying_key_serde")]
    pub(crate) issuer: VerifyingKey,
    /// The intended audience
    #[debug("{}", hex::encode(audience))]
    #[serde(with = "verifying_key_serde")]
    pub(crate) audience: VerifyingKey,
    /// The origin of the capability
    pub(crate) capability_origin: CapabilityOrigin,
    /// Valid until unix timestamp in seconds.
    pub(crate) valid_until: Expires,
    /// The capability, as opaque length delimited bytes.
    #[debug("{}", hex::encode(capability))]
    pub(crate) capability: Vec<u8>,
}

impl Payload {
    pub fn issuer(&self) -> &VerifyingKey {
        &self.issuer
    }

    pub fn audience(&self) -> &VerifyingKey {
        &self.audience
    }

    pub fn capability_origin(&self) -> &CapabilityOrigin {
        &self.capability_origin
    }

    pub fn capability_issuer(&self) -> &VerifyingKey {
        match &self.capability_origin {
            CapabilityOrigin::Issuer => &self.issuer,
            CapabilityOrigin::Delegation(root) => root,
        }
    }

    pub fn expires(&self) -> &Expires {
        &self.valid_until
    }

    /// The raw capability bytes. In every version these are the postcard
    /// encoding of the issuer's capability type.
    pub fn capability(&self) -> &[u8] {
        &self.capability
    }
}

/// A payload with its signature. What the signature covers depends on
/// the version of the containing [`DelegationWire`] variant.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub(crate) struct Signed {
    pub(crate) payload: Payload,
    #[serde(with = "signature_serde")]
    pub(crate) signature: Signature,
}

impl Signed {
    /// The v2 signed bytes: `DST ++ postcard(payload)`.
    fn signed_bytes_v2(&self) -> Vec<u8> {
        postcard::to_extend(&self.payload, DST.to_vec()).expect("vec")
    }

    /// Verify as a v2 token.
    fn verify_v2(&self) -> Result<()> {
        self.payload
            .issuer
            .verify_strict(&self.signed_bytes_v2(), &self.signature)?;
        Ok(())
    }
}

/// An uninhabited type: variants holding it can never be constructed or
/// deserialized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum Never {}

/// The versioned form of a delegation: the in-memory repr of
/// [`Delegation`] and its serde form.
///
/// The postcard enum discriminator doubles as the version byte: variant
/// indices equal version numbers.
///
/// Note that the `V1` variant's serde form is the top level framing
/// (v2 style field encodings), not a v1 wire form — v1 wire bytes can
/// only be read via [`Delegation::decode_any`], with a capability type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// transient and short-lived; boxing buys nothing
#[allow(clippy::large_enum_variant)]
enum DelegationWire {
    /// A version that never existed; pins the variant indices to the
    /// version numbers. Never constructed.
    V0(Never),
    /// A v1 token. Signed over `v1 DST ++ v1 payload layout`.
    V1(Signed),
    /// A v2 token. Signed over `DST ++ postcard(payload)`.
    V2(Signed),
}

/// A token for attenuated capability delegations.
///
/// Any supported version can be represented.
///
/// All envelope fields are accessible without a capability type, for
/// every version, so verification ([`Authorizer`]) and transport code
/// can be version agnostic. The capability type is needed in exactly two
/// places: decoding v1 wire bytes ([`Self::decode_any`]) and evaluating
/// capabilities during invocation checks.
///
/// There are two byte representations:
///
/// - [`Self::encode`] / [`Self::decode`] / [`Self::decode_any`]: the
///   versioned wire form; for v1 tokens the `Rcan::encode` form of rcan
///   0.4.x, reconstructed. The naked v1 serde form is produced by
///   [`V1Compat`] instead.
/// - serde: the top level framing, versioned via the enum discriminator
///   and deserializable without a capability type, but **not** readable
///   by v1-only code. Signatures are verified on deserialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation(DelegationWire);

pub struct DelegationBuilder<'s> {
    issuer: &'s SigningKey,
    audience: VerifyingKey,
    capability_origin: CapabilityOrigin,
    capability: Vec<u8>,
}

impl Delegation {
    pub fn issuing_builder<'s, C: Serialize>(
        issuer: &'s SigningKey,
        audience: VerifyingKey,
        capability: &C,
    ) -> DelegationBuilder<'s> {
        DelegationBuilder {
            issuer,
            audience,
            capability_origin: CapabilityOrigin::Issuer,
            capability: postcard::to_stdvec(capability).expect("vec"),
        }
    }

    pub fn delegating_builder<'s, C: Serialize>(
        issuer: &'s SigningKey,
        audience: VerifyingKey,
        owner: VerifyingKey,
        capability: &C,
    ) -> DelegationBuilder<'s> {
        DelegationBuilder {
            issuer,
            audience,
            capability_origin: CapabilityOrigin::Delegation(owner),
            capability: postcard::to_stdvec(capability).expect("vec"),
        }
    }

    /// Decode a token of version >= 2. A successful decode is signature
    /// checked, and the input must be consumed exactly.
    ///
    /// v1 tokens are rejected: deserializing them requires the
    /// capability type, use [`Self::decode_any`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        match bytes.first() {
            None => bail!("cannot decode, token is empty"),
            Some(0x01) | Some(0x20) => {
                bail!("cannot decode a v1 token without its capability type, use decode_any")
            }
            _ => {
                let (wire, leftover) =
                    postcard::take_from_bytes::<DelegationWire>(bytes).context("decoding")?;
                ensure!(
                    leftover.is_empty(),
                    "cannot decode, {} trailing bytes",
                    leftover.len()
                );
                match wire {
                    DelegationWire::V2(signed) => {
                        signed.verify_v2()?;
                        Ok(Self(DelegationWire::V2(signed)))
                    }
                    // unreachable: 0x01 leading bytes were rejected
                    // above, so the V1 variant cannot have been parsed
                    DelegationWire::V1(_) => bail!("expected a v2 token, found v1"),
                    // this can never happen, but rustc requires us to
                    // handle the uninhabited variant
                    DelegationWire::V0(never) => match never {},
                }
            }
        }
    }

    /// Decode a token of any supported version, using the capability
    /// type `C` where needed (v1 only).
    ///
    /// Version detection: v1 versioned tokens start with `0x01`, naked
    /// v1 serde bytes always start with `0x20` (the length prefix of
    /// the issuer key), and v2 wire tokens start with `0x02`. Version
    /// 32 must never be assigned, it would collide with naked v1.
    pub fn decode_any<C: Serialize + DeserializeOwned>(bytes: &[u8]) -> Result<Self> {
        let signed = match bytes.first() {
            None => bail!("cannot decode, token is empty"),
            Some(0x01) => v1::v1_parse::<C>(&bytes[1..])?,
            Some(0x20) => v1::v1_parse::<C>(bytes)?,
            _ => return Self::decode(bytes),
        };
        Ok(Self(DelegationWire::V1(signed)))
    }

    /// Encode in the versioned wire form. For v1 tokens this is the
    /// `Rcan::encode` form of rcan 0.4.x, reconstructed; the naked v1
    /// serde form is produced by [`V1Compat`] instead.
    pub fn encode(&self) -> Vec<u8> {
        match &self.0 {
            DelegationWire::V0(never) => match *never {},
            DelegationWire::V1(signed) => v1::v1_encode_versioned(signed),
            DelegationWire::V2(_) => postcard::to_stdvec(&self.0).expect("vec"),
        }
    }

    pub(crate) fn signed(&self) -> &Signed {
        match &self.0 {
            DelegationWire::V0(never) => match *never {},
            DelegationWire::V1(signed) | DelegationWire::V2(signed) => signed,
        }
    }

    /// Whether this is a v1 token.
    pub fn is_v1(&self) -> bool {
        matches!(self.0, DelegationWire::V1(_))
    }

    pub(crate) fn from_v1(signed: Signed) -> Self {
        Self(DelegationWire::V1(signed))
    }

    pub fn payload(&self) -> &Payload {
        &self.signed().payload
    }

    pub fn signature(&self) -> &Signature {
        &self.signed().signature
    }

    pub fn issuer(&self) -> &VerifyingKey {
        self.payload().issuer()
    }

    pub fn audience(&self) -> &VerifyingKey {
        self.payload().audience()
    }

    pub fn capability_origin(&self) -> &CapabilityOrigin {
        self.payload().capability_origin()
    }

    pub fn capability_issuer(&self) -> &VerifyingKey {
        self.payload().capability_issuer()
    }

    pub fn expires(&self) -> &Expires {
        self.payload().expires()
    }

    /// The raw capability bytes. In every version these are the postcard
    /// encoding of the issuer's capability type.
    pub fn capability(&self) -> &[u8] {
        self.payload().capability()
    }
}

impl DelegationBuilder<'_> {
    pub fn sign(self, valid_until: Expires) -> Delegation {
        let payload = Payload {
            issuer: self.issuer.verifying_key(),
            audience: self.audience,
            capability_origin: self.capability_origin,
            valid_until,
            capability: self.capability,
        };
        let to_sign = postcard::to_extend(&payload, DST.to_vec()).expect("vec");
        let signature = self.issuer.sign(&to_sign);
        Delegation(DelegationWire::V2(Signed { payload, signature }))
    }
}

impl Serialize for Delegation {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Delegation {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        use serde::de::Error;
        let wire = DelegationWire::deserialize(deserializer)?;
        // Verify before yielding, so a deserialized `Delegation` is
        // always signature checked, whichever version it is.
        match &wire {
            DelegationWire::V0(never) => match *never {},
            DelegationWire::V1(signed) => v1::v1_verify(signed).map_err(D::Error::custom)?,
            DelegationWire::V2(signed) => signed.verify_v2().map_err(D::Error::custom)?,
        }
        Ok(Self(wire))
    }
}

/// An authorizer for invocations.
///
/// This represents an identity in the form of a public key.
/// This public key will always be the same as the original issuer of
/// the capabilities that are invoked against the authorizer.
///
/// Proof chains of any supported version are accepted, including mixed
/// chains.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Authorizer {
    identity: VerifyingKey,
}

impl Authorizer {
    /// Constructs a new authorizer for given identity.
    pub fn new(identity: VerifyingKey) -> Self {
        Self { identity }
    }

    /// Verifies an invocation of a capability owned by this authorizer,
    /// that may have been passed through delegations in a proof chain
    /// and was finally signed back to us from given `invoker`.
    ///
    /// Each delegation's capability bytes must parse as a canonical `C`
    /// encoding, consumed exactly, and permit the invoked `capability`;
    /// anything else is a deny.
    ///
    /// Make sure to verify that the `invoker` signed and authenticated
    /// the message containing the `capability`.
    pub fn check_invocation_from<C: Capability>(
        &self,
        invoker: VerifyingKey,
        capability: C,
        proof_chain: &[&Delegation],
    ) -> Result<()> {
        self.check_invocation_from_at(SystemTime::now(), invoker, capability, proof_chain)
    }

    /// [`Self::check_invocation_from`] with an explicit clock.
    pub fn check_invocation_from_at<C: Capability>(
        &self,
        now: SystemTime,
        invoker: VerifyingKey,
        capability: C,
        proof_chain: &[&Delegation],
    ) -> Result<()> {
        // We require that proof chains are provided "back-to-front".
        // So they start with the owner of the capability, then
        // proceed with the next item in the chain.
        let mut current_issuer_target = &self.identity;
        for proof in proof_chain {
            // Verify proof chain issuer/audience integrity:
            let issuer = proof.issuer();
            ensure!(
                issuer == current_issuer_target,
                "invocation failed: expected proof to be issued by {}, but was issued by {}",
                hex::encode(current_issuer_target),
                hex::encode(issuer),
            );

            // Verify each proof's time validity:
            let expiry = proof.expires();
            ensure!(
                expiry.is_valid_at(now),
                "invocation failed: proof expired at {expiry}"
            );

            // Verify that the capability is actually reached through:
            ensure!(
                proof.capability_issuer() == &self.identity,
                "invocation failed: proof is missing delegation for capability of {}",
                hex::encode(self.identity)
            );

            // Verify that the capability doesn't break out of capabilities:
            let permitted = match postcard::take_from_bytes::<C>(proof.capability()) {
                Ok((granted, [])) => granted.permits(&capability),
                _ => false,
            };
            ensure!(permitted, "invocation failed");

            // Continue checking the proof chain's integrity with this
            // delegation's audience as the next issuer target:
            current_issuer_target = proof.audience();
        }

        ensure!(
            &invoker == current_issuer_target,
            "invocation failed: expected delegation chain to end in the connection's owner {}, but the connection is authenticated by {} instead",
            hex::encode(invoker),
            hex::encode(current_issuer_target),
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub(crate) enum Rpc {
        Read,
        ReadWrite,
        All,
    }

    impl Capability for Rpc {
        fn permits(&self, other: &Self) -> bool {
            match (self, other) {
                (Rpc::All, _) => true,
                (Rpc::ReadWrite, Rpc::Read | Rpc::ReadWrite) => true,
                (Rpc::ReadWrite, _) => false,
                (Rpc::Read, Rpc::Read) => true,
                (Rpc::Read, _) => false,
            }
        }
    }

    pub(crate) fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    /// Pinned v1 wire vectors, generated with the real rcan 0.4.x
    /// implementation (keys [0; 32], [1; 32], [2; 32]):
    ///
    /// - root: issuing_builder(service, alice, Rpc::All)
    ///   .sign(Expires::At(4_102_444_800))
    /// - link: delegating_builder(alice, bob, service, Rpc::Read)
    ///   .sign(Expires::Never)
    pub(crate) const V1_ROOT_VERSIONED: &str = "01203b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c00020180ae99a40f7e0b2024caf7fd65d38fa6007664ba45ac3714dbd0055ae7970d6601cbbec0440d3293fbffe56d9eaa7deddf61e92f8fb7d1272fdbac902a1db5fe9cf6998b04";
    pub(crate) const V1_ROOT_NAKED: &str = "203b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c00020180ae99a40f7e0b2024caf7fd65d38fa6007664ba45ac3714dbd0055ae7970d6601cbbec0440d3293fbffe56d9eaa7deddf61e92f8fb7d1272fdbac902a1db5fe9cf6998b04";
    pub(crate) const V1_LINK_VERSIONED: &str = "01208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39401203b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da2900001e623cd399360cb4fdb00e829430d53b5db30ed3d3149d1c59305f22f89d41fe3d866c5d48943d85ed2c7cb1b289d7d2edbef8b2b8f81c61eb74759600909a0a";
    pub(crate) const V1_LINK_NAKED: &str = "208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39401203b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da2900001e623cd399360cb4fdb00e829430d53b5db30ed3d3149d1c59305f22f89d41fe3d866c5d48943d85ed2c7cb1b289d7d2edbef8b2b8f81c61eb74759600909a0a";

    #[test]
    fn v2_roundtrip() {
        let issuer = key(0);
        let audience = key(1).verifying_key();
        let delegation =
            Delegation::issuing_builder(&issuer, audience, &Rpc::ReadWrite).sign(Expires::Never);

        let bytes = delegation.encode();
        assert_eq!(bytes[0], 2);
        let decoded = Delegation::decode(&bytes).unwrap();
        assert_eq!(decoded, delegation);
        // decode_any handles v2 too, C unused.
        let decoded = Delegation::decode_any::<Rpc>(&bytes).unwrap();
        assert_eq!(decoded, delegation);

        assert_eq!(delegation.issuer(), &issuer.verifying_key());
        assert_eq!(delegation.audience(), &audience);
        assert_eq!(delegation.expires(), &Expires::Never);
        assert_eq!(delegation.capability_issuer(), &issuer.verifying_key());
        assert_eq!(delegation.capability(), &[1]);
        assert!(!delegation.is_v1());

        // For v2, the serde form equals the wire form.
        let wire = postcard::to_stdvec(&delegation).unwrap();
        assert_eq!(wire, bytes);
        let deserialized: Delegation = postcard::from_bytes(&wire).unwrap();
        assert_eq!(deserialized, delegation);
    }

    #[test]
    fn v2_decode_rejects_tampering() {
        let issuer = key(0);
        let audience = key(1).verifying_key();
        let delegation =
            Delegation::issuing_builder(&issuer, audience, &Rpc::Read).sign(Expires::Never);
        let good = delegation.encode();

        // Zeroed signature.
        let mut forged = good.clone();
        let n = forged.len();
        forged[n - SIGNATURE_LENGTH..].fill(0);
        assert!(Delegation::decode(&forged).is_err());

        // Capability widened Read -> All, signature kept. Offset:
        // version, issuer, audience, origin tag, expires tag,
        // capability length prefix - then the capability byte.
        let mut widened = good.clone();
        let capability_offset = 1 + 32 + 32 + 1 + 1 + 1;
        assert_eq!(widened[capability_offset - 1], 1); // length prefix
        assert_eq!(widened[capability_offset], 0); // Rpc::Read
        widened[capability_offset] = 2; // Rpc::All
        assert!(Delegation::decode(&widened).is_err());

        // Trailing garbage between payload and signature.
        let mut padded = good.clone();
        let signature_start = padded.len() - SIGNATURE_LENGTH;
        padded.insert(signature_start, 0);
        assert!(Delegation::decode(&padded).is_err());

        // Unknown version.
        let mut versioned = good.clone();
        versioned[0] = 3;
        assert!(Delegation::decode(&versioned).is_err());

        assert!(Delegation::decode(&[]).is_err());
    }

    #[test]
    fn v1_decode_any_matches_pinned_vectors() {
        let service = key(0);
        let alice = key(1);
        let bob = key(2);

        for (versioned_hex, naked_hex) in [
            (V1_ROOT_VERSIONED, V1_ROOT_NAKED),
            (V1_LINK_VERSIONED, V1_LINK_NAKED),
        ] {
            let versioned = hex::decode(versioned_hex).unwrap();
            let naked = hex::decode(naked_hex).unwrap();

            // Both wire forms decode, to equal values.
            let delegation = Delegation::decode_any::<Rpc>(&versioned).unwrap();
            let from_naked = Delegation::decode_any::<Rpc>(&naked).unwrap();
            assert_eq!(delegation, from_naked);
            assert!(delegation.is_v1());

            // encode always emits the versioned form, byte exact.
            assert_eq!(delegation.encode(), versioned);

            // decode without C rejects v1.
            assert!(Delegation::decode(&versioned).is_err());
            assert!(Delegation::decode(&naked).is_err());
        }

        // Envelope accessors, C free.
        let root =
            Delegation::decode_any::<Rpc>(&hex::decode(V1_ROOT_VERSIONED).unwrap()).unwrap();
        assert_eq!(root.issuer(), &service.verifying_key());
        assert_eq!(root.audience(), &alice.verifying_key());
        assert_eq!(root.capability_issuer(), &service.verifying_key());
        assert_eq!(root.expires(), &Expires::At(4_102_444_800));
        assert_eq!(root.capability(), &[2]); // Rpc::All

        let link =
            Delegation::decode_any::<Rpc>(&hex::decode(V1_LINK_VERSIONED).unwrap()).unwrap();
        assert_eq!(link.issuer(), &alice.verifying_key());
        assert_eq!(link.audience(), &bob.verifying_key());
        assert_eq!(link.capability_issuer(), &service.verifying_key());
        assert_eq!(link.expires(), &Expires::Never);
        assert_eq!(link.capability(), &[0]); // Rpc::Read

        // A tampered v1 token fails signature verification: flip the
        // capability byte (Rpc::All -> Rpc::Read keeps the length).
        let mut tampered = hex::decode(V1_ROOT_VERSIONED).unwrap();
        let capability_offset = 1 + 33 + 33 + 1;
        assert_eq!(tampered[capability_offset], 2);
        tampered[capability_offset] = 0;
        assert!(Delegation::decode_any::<Rpc>(&tampered).is_err());
    }

    #[test]
    fn v1_serde_roundtrip_in_top_level_framing() {
        let naked = hex::decode(V1_ROOT_NAKED).unwrap();
        let delegation = Delegation::decode_any::<Rpc>(&naked).unwrap();

        // The serde form is the top level framing: version discriminator
        // 1, then the v2 style struct. Not readable as v1 wire bytes,
        // but needs no capability type to deserialize.
        let wire = postcard::to_stdvec(&delegation).unwrap();
        assert_eq!(wire[0], 1);
        assert_ne!(wire, naked);
        let deserialized: Delegation = postcard::from_bytes(&wire).unwrap();
        assert_eq!(deserialized, delegation);

        // After the round trip, the versioned v1 bytes are still exactly
        // reconstructible.
        assert_eq!(
            deserialized.encode(),
            hex::decode(V1_ROOT_VERSIONED).unwrap()
        );

        // Tampering with the serde form fails signature verification on
        // deserialize: flip a byte in the capability, which sits right
        // before the 64 byte signature.
        let mut tampered = wire.clone();
        let n = tampered.len();
        tampered[n - 65] ^= 1;
        assert!(postcard::from_bytes::<Delegation>(&tampered).is_err());
    }

    #[test]
    fn mixed_chain_invocation() {
        let service = key(0);
        let alice = key(1);
        let bob = key(2);

        // The root grant is a legacy v1 token (pinned vector: service
        // grants alice everything)...
        let root =
            Delegation::decode_any::<Rpc>(&hex::decode(V1_ROOT_VERSIONED).unwrap()).unwrap();

        // ...and alice delegates onward with v2.
        let link = Delegation::delegating_builder(
            &alice,
            bob.verifying_key(),
            service.verifying_key(),
            &Rpc::Read,
        )
        .sign(Expires::Never);

        let authorizer = Authorizer::new(service.verifying_key());
        let chain = [&root, &link];
        // Within the root grant's validity.
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

        authorizer
            .check_invocation_from_at(now, bob.verifying_key(), Rpc::Read, &chain)
            .unwrap();
        assert!(
            authorizer
                .check_invocation_from_at(now, bob.verifying_key(), Rpc::ReadWrite, &chain)
                .is_err()
        );
        assert!(
            authorizer
                .check_invocation_from_at(now, key(3).verifying_key(), Rpc::Read, &chain)
                .is_err()
        );
        // After the root grant's expiry, the chain is dead.
        let late = SystemTime::UNIX_EPOCH + Duration::from_secs(4_102_444_801);
        assert!(
            authorizer
                .check_invocation_from_at(late, bob.verifying_key(), Rpc::Read, &chain)
                .is_err()
        );
    }

    #[test]
    fn chain_must_start_at_the_authorizer() {
        let service = key(0);
        let alice = key(1);
        let bob = key(2);

        let alice_grant = Delegation::issuing_builder(&alice, bob.verifying_key(), &Rpc::All)
            .sign(Expires::Never);
        let authorizer = Authorizer::new(service.verifying_key());
        assert!(
            authorizer
                .check_invocation_from(bob.verifying_key(), Rpc::Read, &[&alice_grant])
                .is_err()
        );
    }

    #[test]
    fn subject_must_be_the_authorizer() {
        let service = key(0);
        let other = key(1);
        let alice = key(2);

        // The service passes on authority rooted at some *other* key; a
        // chain of it proves nothing about the service's own resources.
        let delegation = Delegation::delegating_builder(
            &service,
            alice.verifying_key(),
            other.verifying_key(),
            &Rpc::All,
        )
        .sign(Expires::Never);
        let authorizer = Authorizer::new(service.verifying_key());
        assert!(
            authorizer
                .check_invocation_from(alice.verifying_key(), Rpc::Read, &[&delegation])
                .is_err()
        );
    }

    #[test]
    fn owner_needs_no_chain() {
        let service = key(0);
        let authorizer = Authorizer::new(service.verifying_key());
        authorizer
            .check_invocation_from(service.verifying_key(), Rpc::All, &[])
            .unwrap();
        assert!(
            authorizer
                .check_invocation_from(key(1).verifying_key(), Rpc::Read, &[])
                .is_err()
        );
    }
}
