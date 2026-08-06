pub mod v1;
pub mod v2;

pub use v2::*;

// TODO: better error management (n0-error?)
use anyhow::{bail, ensure, Context, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use n0_future::time::SystemTime;
use serde::{Deserialize, Serialize};

/// An uninhabited type: variants holding it can never be constructed or
/// deserialized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum Never {}

/// Serde for an ed25519 [`Signature`] via the v2 wire format: 64 raw
/// bytes in binary formats, lowercase hex in human-readable ones.
mod signature_serde {
    use ed25519_dalek::Signature;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::v2::SignatureWire;

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

/// A v1 token, parsed into its envelope fields with the capability kept
/// as opaque bytes.
///
/// This is [`v1::Rcan`] with `Vec<u8>` in place of `C`. Constructing it
/// from v1 wire bytes requires the capability type once (see
/// [`Delegation::decode_any`]): v1 stores the capability mid-payload
/// without a length prefix, so only typed deserialization can find its
/// end. Afterwards everything is capability type free: v1's byte layout
/// is fixed and known, so the exact original wire bytes are
/// *reconstructed* from these fields on [`Delegation::encode`] — the
/// opaque capability bytes are spliced back verbatim — and the signature
/// can be verified against the reconstruction.
///
/// The serde form of this struct is the top level framing, **not** a v1
/// wire form (the capability is length prefixed here, the keys are not),
/// which is what makes it deserializable without the capability type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct V1Parsed {
    #[serde(with = "v2::verifying_key_serde")]
    issuer: VerifyingKey,
    #[serde(with = "v2::verifying_key_serde")]
    audience: VerifyingKey,
    capability_origin: CapabilityOrigin,
    valid_until: Expires,
    capability: Vec<u8>,
    #[serde(with = "signature_serde")]
    signature: Signature,
}

impl V1Parsed {
    /// Convert from a typed v1 token, re-encoding the capability to
    /// opaque bytes.
    fn from_rcan<C: v1::Capability>(rcan: &v1::Rcan<C>) -> Self {
        Self {
            issuer: *rcan.issuer(),
            audience: *rcan.audience(),
            capability_origin: match rcan.capability_origin() {
                v1::CapabilityOrigin::Issuer => CapabilityOrigin::Issuer,
                v1::CapabilityOrigin::Delegation(key) => CapabilityOrigin::Delegation(*key),
            },
            valid_until: match rcan.expires() {
                v1::Expires::Never => Expires::Never,
                v1::Expires::At(at) => Expires::At(*at),
            },
            capability: postcard::to_stdvec(rcan.capability()).expect("vec"),
            signature: rcan.signature,
        }
    }

    /// Reconstruct the exact v1 payload bytes: serdect length-prefixed
    /// keys, capability spliced raw (v1 has no length prefix there),
    /// expiry via postcard (identical encoding in v1 and v2).
    fn payload_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(32);
        buf.extend_from_slice(self.issuer.as_bytes());
        buf.push(32);
        buf.extend_from_slice(self.audience.as_bytes());
        match &self.capability_origin {
            CapabilityOrigin::Issuer => buf.push(0),
            CapabilityOrigin::Delegation(key) => {
                buf.push(1);
                buf.push(32);
                buf.extend_from_slice(key.as_bytes());
            }
        }
        buf.extend_from_slice(&self.capability);
        postcard::to_extend(&self.valid_until, buf).expect("vec")
    }

    /// Reconstruct the versioned v1 wire bytes, like [`v1::Rcan::encode`]:
    /// `0x01 ++ postcard(payload) ++ signature`. The naked serde form is
    /// produced by [`V1Compat`] instead, mirroring v1's own split between
    /// encode and serde.
    fn encode(&self) -> Vec<u8> {
        let mut out = vec![1u8];
        out.extend_from_slice(&self.payload_bytes());
        out.extend_from_slice(&self.signature.to_bytes());
        out
    }

    /// Verify the v1 signature against the reconstructed signed bytes.
    fn verify_signature(&self) -> Result<()> {
        let mut signed = v1::DST.to_vec();
        signed.extend_from_slice(&self.payload_bytes());
        self.issuer.verify_strict(&signed, &self.signature)?;
        Ok(())
    }
}

/// The versioned form of a delegation: the in-memory repr of
/// [`Delegation`] and its serde form.
///
/// The postcard enum discriminator doubles as the version byte:
/// variant indices equal version numbers.
///
/// Note that the `V1` variant's serde form is the top level framing of
/// [`V1Parsed`], not a v1 wire form — v1 wire bytes can only be read via
/// [`Delegation::decode_any`], with a capability type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// transient and short-lived; boxing buys nothing
#[allow(clippy::large_enum_variant)]
enum DelegationWire {
    /// A version that never existed; pins the variant indices to the
    /// version numbers. Never constructed.
    V0(Never),
    /// A v1 token, parsed, capability opaque.
    V1(V1Parsed),
    /// A version 2 delegation.
    V2(v2::Delegation),
}

/// A delegation of any supported version.
///
/// This is the public currency of the crate: all envelope fields are
/// accessible without a capability type, for every version, so
/// verification ([`Authorizer`]) and transport code can be version
/// agnostic. The capability type is needed in exactly two places:
/// decoding v1 wire bytes ([`Self::decode_any`]) and evaluating
/// capabilities during invocation checks.
///
/// There are two byte representations:
///
/// - [`Self::encode`] / [`Self::decode`] / [`Self::decode_any`]: the
///   versioned wire form; for v1 tokens the exact original v1 bytes.
/// - serde: the top level framing, versioned via the enum discriminator
///   and deserializable without a capability type, but **not** readable
///   by v1-only code. Signatures are verified on deserialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation(DelegationWire);

impl Delegation {
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
            _ => Ok(Self(DelegationWire::V2(v2::Delegation::decode(bytes)?))),
        }
    }

    /// Decode a token of any supported version, using the capability
    /// type `C` where needed (v1 only).
    ///
    /// Version detection: v1 versioned tokens start with `0x01`, naked
    /// v1 serde bytes always start with `0x20` (the length prefix of
    /// the issuer key), and v2 wire tokens start with `0x02`. Version
    /// 32 must never be assigned, it would collide with naked v1.
    pub fn decode_any<C>(bytes: &[u8]) -> Result<Self>
    where
        C: v1::Capability + serde::de::DeserializeOwned,
    {
        let rcan: v1::Rcan<C> = match bytes.first() {
            None => bail!("cannot decode, token is empty"),
            Some(0x01) => v1::Rcan::decode(bytes)?,
            Some(0x20) => postcard::from_bytes(bytes).context("decoding naked v1")?,
            _ => return Self::decode(bytes),
        };
        Ok(Self(DelegationWire::V1(V1Parsed::from_rcan(&rcan))))
    }

    /// Encode in the versioned wire form. For v1 tokens this is the
    /// exact [`v1::Rcan::encode`] form, reconstructed; the naked v1
    /// serde form is produced by [`V1Compat`] instead.
    pub fn encode(&self) -> Vec<u8> {
        match &self.0 {
            DelegationWire::V0(never) => match *never {},
            DelegationWire::V1(parsed) => parsed.encode(),
            DelegationWire::V2(delegation) => delegation.encode(),
        }
    }

    pub fn issuer(&self) -> &VerifyingKey {
        match &self.0 {
            DelegationWire::V0(never) => match *never {},
            DelegationWire::V1(parsed) => &parsed.issuer,
            DelegationWire::V2(delegation) => delegation.issuer(),
        }
    }

    pub fn audience(&self) -> &VerifyingKey {
        match &self.0 {
            DelegationWire::V0(never) => match *never {},
            DelegationWire::V1(parsed) => &parsed.audience,
            DelegationWire::V2(delegation) => delegation.audience(),
        }
    }

    pub fn capability_origin(&self) -> &CapabilityOrigin {
        match &self.0 {
            DelegationWire::V0(never) => match *never {},
            DelegationWire::V1(parsed) => &parsed.capability_origin,
            DelegationWire::V2(delegation) => delegation.capability_origin(),
        }
    }

    pub fn capability_issuer(&self) -> &VerifyingKey {
        match self.capability_origin() {
            CapabilityOrigin::Issuer => self.issuer(),
            CapabilityOrigin::Delegation(root) => root,
        }
    }

    pub fn expires(&self) -> &Expires {
        match &self.0 {
            DelegationWire::V0(never) => match *never {},
            DelegationWire::V1(parsed) => &parsed.valid_until,
            DelegationWire::V2(delegation) => delegation.expires(),
        }
    }

    /// The raw capability bytes. In both versions these are the postcard
    /// encoding of the issuer's capability type.
    pub fn capability(&self) -> &[u8] {
        match &self.0 {
            DelegationWire::V0(never) => match *never {},
            DelegationWire::V1(parsed) => &parsed.capability,
            DelegationWire::V2(delegation) => delegation.capability(),
        }
    }

    /// The v2 delegation, if this is a v2 token.
    pub fn v2(&self) -> Option<&v2::Delegation> {
        match &self.0 {
            DelegationWire::V2(delegation) => Some(delegation),
            _ => None,
        }
    }
}

impl From<v2::Delegation> for Delegation {
    fn from(delegation: v2::Delegation) -> Self {
        Self(DelegationWire::V2(delegation))
    }
}

/// A wrapper around [`Delegation`] whose postcard serialization is byte
/// identical to a naked v1 [`v1::Rcan`], for use in message schemas that
/// must stay wire compatible with v1 peers.
///
/// The invariant, enforced at construction: the wrapped token is a v1
/// token whose capability bytes parse in the vocabulary `C`. This is
/// what makes serialization infallible in practice — a v2 token has no
/// v1 signature, and foreign vocabulary bytes would produce a well
/// formed v1 token the receiving `C` typed peer rejects.
pub struct V1Compat<C>(Delegation, std::marker::PhantomData<C>);

/// Fails if the token is not v1, or if its capability bytes are not a
/// canonical `C` encoding.
impl<C: serde::de::DeserializeOwned> TryFrom<Delegation> for V1Compat<C> {
    type Error = anyhow::Error;

    fn try_from(delegation: Delegation) -> Result<Self> {
        match &delegation.0 {
            DelegationWire::V1(parsed) => match postcard::take_from_bytes::<C>(&parsed.capability)
            {
                Ok((_, [])) => Ok(Self(delegation, std::marker::PhantomData)),
                _ => bail!("capability does not parse in the wrapper's vocabulary"),
            },
            DelegationWire::V2(_) => {
                bail!("only a v1 token can be serialized in v1 compatible form")
            }
            DelegationWire::V0(never) => match *never {},
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

impl<C> Serialize for V1Compat<C> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;

        /// Length-prefixed key bytes, like serdect in v1.
        struct PrefixedKey<'a>(&'a VerifyingKey);
        impl Serialize for PrefixedKey<'_> {
            fn serialize<S: serde::Serializer>(
                &self,
                s: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                s.serialize_bytes(self.0.as_bytes())
            }
        }

        /// Raw bytes with no framing: in postcard, a tuple of u8
        /// elements is emitted with no length prefix. This is the splice
        /// that reproduces v1's unprefixed capability field.
        struct RawSplice<'a>(&'a [u8]);
        impl Serialize for RawSplice<'_> {
            fn serialize<S: serde::Serializer>(
                &self,
                s: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                let mut tup = s.serialize_tuple(self.0.len())?;
                for byte in self.0 {
                    tup.serialize_element(byte)?;
                }
                tup.end()
            }
        }

        /// The v1 payload layout, emitted field by field.
        struct V1PayloadMimic<'a>(&'a V1Parsed);
        impl Serialize for V1PayloadMimic<'_> {
            fn serialize<S: serde::Serializer>(
                &self,
                s: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                let parsed = self.0;
                let mut tup = s.serialize_tuple(5)?;
                tup.serialize_element(&PrefixedKey(&parsed.issuer))?;
                tup.serialize_element(&PrefixedKey(&parsed.audience))?;
                match &parsed.capability_origin {
                    CapabilityOrigin::Issuer => tup.serialize_element(&V1OriginIssuer)?,
                    CapabilityOrigin::Delegation(key) => {
                        tup.serialize_element(&V1OriginDelegation(key))?
                    }
                }
                tup.serialize_element(&RawSplice(&parsed.capability))?;
                tup.serialize_element(&parsed.valid_until)?;
                tup.end()
            }
        }

        struct V1OriginIssuer;
        impl Serialize for V1OriginIssuer {
            fn serialize<S: serde::Serializer>(
                &self,
                s: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                s.serialize_unit_variant("CapabilityOrigin", 0, "Issuer")
            }
        }

        struct V1OriginDelegation<'a>(&'a VerifyingKey);
        impl Serialize for V1OriginDelegation<'_> {
            fn serialize<S: serde::Serializer>(
                &self,
                s: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                s.serialize_newtype_variant(
                    "CapabilityOrigin",
                    1,
                    "Delegation",
                    &PrefixedKey(self.0),
                )
            }
        }

        // The v1 mimicry is only byte-correct for postcard; the one
        // format property serde lets us check is human-readability.
        if serializer.is_human_readable() {
            return Err(serde::ser::Error::custom(
                "V1Compat is a postcard wire format, refusing human readable serialization",
            ));
        }
        let DelegationWire::V1(parsed) = &self.0 .0 else {
            return Err(serde::ser::Error::custom(
                "only a v1 token can be serialized in v1 compatible form",
            ));
        };
        let mut tup = serializer.serialize_tuple(2)?;
        tup.serialize_element(&V1PayloadMimic(parsed))?;
        tup.serialize_element(&v2::SignatureWire(parsed.signature.to_bytes()))?;
        tup.end()
    }
}

impl<'de, C> Deserialize<'de> for V1Compat<C>
where
    C: v1::Capability + serde::de::DeserializeOwned,
{
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            return Err(serde::de::Error::custom(
                "V1Compat is a postcard wire format, refusing human readable deserialization",
            ));
        }
        // Invariant holds by construction: the token was just parsed as
        // a v1 token in vocabulary C, no need to re-check via `new`.
        let rcan = v1::Rcan::<C>::deserialize(deserializer)?;
        Ok(Self(
            Delegation(DelegationWire::V1(V1Parsed::from_rcan(&rcan))),
            std::marker::PhantomData,
        ))
    }
}

impl Serialize for Delegation {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Delegation {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let wire = DelegationWire::deserialize(deserializer)?;
        // v2 verifies in its own Deserialize; v1 fields must be checked
        // against the signature over the reconstructed v1 bytes, so that
        // a deserialized `Delegation` is always signature checked.
        if let DelegationWire::V1(parsed) = &wire {
            parsed
                .verify_signature()
                .map_err(serde::de::Error::custom)?;
        }
        Ok(Self(wire))
    }
}

impl v2::Delegation {
    /// Encode this delegation in its versioned wire form.
    ///
    /// Defined here rather than in the version module: the leading
    /// version byte is a top level concern.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(&DelegationWire::V2(self.clone())).expect("vec")
    }

    /// Decode and verify a delegation from its versioned wire form. A
    /// successful decode is signature checked, and the input must be
    /// consumed exactly.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (wire, leftover) =
            postcard::take_from_bytes::<DelegationWire>(bytes).context("decoding")?;
        ensure!(
            leftover.is_empty(),
            "cannot decode, {} trailing bytes",
            leftover.len()
        );
        match wire {
            DelegationWire::V2(delegation) => Ok(delegation),
            DelegationWire::V1(_) => bail!("expected a v2 token, found v1"),
            // this can never happen, but rustc requires us to handle the uninhabited variant
            DelegationWire::V0(never) => match never {},
        }
    }
}

/// An authorizer for invocations, checking proof chains of any version
/// (including mixed chains) against its own identity.
///
/// The uniform accessors on [`Delegation`] are what make this version
/// agnostic; the capability bytes are the postcard encoding of `C` in
/// every version.
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
        let now = SystemTime::now();
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
    use ed25519_dalek::SigningKey;

    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    enum Rpc {
        Read,
        ReadWrite,
        All,
    }

    fn rpc_permits(a: &Rpc, b: &Rpc) -> bool {
        match (a, b) {
            (Rpc::All, _) => true,
            (Rpc::ReadWrite, Rpc::Read | Rpc::ReadWrite) => true,
            (Rpc::ReadWrite, _) => false,
            (Rpc::Read, Rpc::Read) => true,
            (Rpc::Read, _) => false,
        }
    }

    impl Capability for Rpc {
        fn permits(&self, other: &Self) -> bool {
            rpc_permits(self, other)
        }
    }

    impl v1::Capability for Rpc {
        fn permits(&self, other: &Self) -> bool {
            rpc_permits(self, other)
        }
    }

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    #[test]
    fn v2_roundtrip() {
        let issuer = key(0);
        let audience = key(1).verifying_key();
        let inner = v2::Delegation::issuing_builder(&issuer, audience, &Rpc::ReadWrite)
            .sign(Expires::Never);
        let delegation: Delegation = inner.into();

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

        // For v2, the serde form equals the wire form.
        let wire = postcard::to_stdvec(&delegation).unwrap();
        assert_eq!(wire, bytes);
        let deserialized: Delegation = postcard::from_bytes(&wire).unwrap();
        assert_eq!(deserialized, delegation);
    }

    #[test]
    fn v1_decode_any_reconstructs_exact_bytes() {
        let service = key(0);
        let alice = key(1);
        let bob = key(2);

        // A root grant and a delegated link, to exercise both
        // capability_origin encodings.
        let root = v1::Rcan::issuing_builder(&service, alice.verifying_key(), Rpc::All)
            .sign(v1::Expires::At(4_102_444_800));
        let link = v1::Rcan::delegating_builder(
            &alice,
            bob.verifying_key(),
            service.verifying_key(),
            Rpc::Read,
        )
        .sign(v1::Expires::Never);

        for rcan in [&root, &link] {
            // Versioned form.
            let versioned = rcan.encode();
            let delegation = Delegation::decode_any::<Rpc>(&versioned).unwrap();
            assert_eq!(delegation.encode(), versioned);

            // Naked serde form decodes too; encode always emits the
            // versioned form, and provenance does not affect equality.
            let naked = postcard::to_stdvec(rcan).unwrap();
            let delegation = Delegation::decode_any::<Rpc>(&naked).unwrap();
            assert_eq!(delegation.encode(), versioned);
            assert_eq!(
                delegation,
                Delegation::decode_any::<Rpc>(&versioned).unwrap()
            );

            // Envelope accessors work without C.
            assert_eq!(delegation.issuer(), rcan.issuer());
            assert_eq!(delegation.audience(), rcan.audience());
            assert_eq!(delegation.capability_issuer(), rcan.capability_issuer());
            assert_eq!(
                delegation.capability(),
                postcard::to_stdvec(rcan.capability()).unwrap()
            );

            // decode without C rejects v1.
            assert!(Delegation::decode(&versioned).is_err());
            assert!(Delegation::decode(&naked).is_err());
        }

        // Expiry is accessible, converted across versions.
        let delegation = Delegation::decode_any::<Rpc>(&root.encode()).unwrap();
        assert_eq!(delegation.expires(), &Expires::At(4_102_444_800));
    }

    #[test]
    fn v1_serde_roundtrip_in_top_level_framing() {
        let service = key(0);
        let alice = key(1);
        let rcan = v1::Rcan::issuing_builder(&service, alice.verifying_key(), Rpc::All)
            .sign(v1::Expires::At(4_102_444_800));
        let naked = postcard::to_stdvec(&rcan).unwrap();
        let delegation = Delegation::decode_any::<Rpc>(&naked).unwrap();

        // The serde form is the top level framing: version discriminator
        // 1, then the parsed struct. Not readable as v1 wire bytes, but
        // needs no capability type to deserialize.
        let wire = postcard::to_stdvec(&delegation).unwrap();
        assert_eq!(wire[0], 1);
        assert_ne!(wire, naked);
        let deserialized: Delegation = postcard::from_bytes(&wire).unwrap();
        assert_eq!(deserialized, delegation);

        // After the round trip, the versioned v1 bytes are still exactly
        // reconstructible.
        assert_eq!(deserialized.encode(), rcan.encode());

        // Tampering with the serde form fails signature verification on
        // deserialize: flip a byte in the capability.
        let mut tampered = wire.clone();
        let n = tampered.len();
        // capability is right before the 64 byte signature; flip its
        // last byte
        tampered[n - 65] ^= 1;
        assert!(postcard::from_bytes::<Delegation>(&tampered).is_err());
    }

    #[test]
    fn v1_compat_is_byte_identical_to_naked_v1() {
        let service = key(0);
        let alice = key(1);
        let bob = key(2);

        let root = v1::Rcan::issuing_builder(&service, alice.verifying_key(), Rpc::All)
            .sign(v1::Expires::At(4_102_444_800));
        let link = v1::Rcan::delegating_builder(
            &alice,
            bob.verifying_key(),
            service.verifying_key(),
            Rpc::Read,
        )
        .sign(v1::Expires::Never);

        for rcan in [&root, &link] {
            let naked = postcard::to_stdvec(rcan).unwrap();
            let delegation = Delegation::decode_any::<Rpc>(&naked).unwrap();

            // Serializing through the wrapper is byte identical to what
            // an old codebase produces with naked v1 serde.
            let compat = V1Compat::<Rpc>::try_from(delegation.clone()).unwrap();
            assert_eq!(postcard::to_stdvec(&compat).unwrap(), naked);

            // And the wrapper reads what an old codebase sends.
            let read: V1Compat<Rpc> = postcard::from_bytes(&naked).unwrap();
            assert_eq!(read.delegation(), &delegation);
        }

        // Old-style and new-style message schemas are wire compatible in
        // both directions.
        #[derive(Serialize, Deserialize)]
        struct OldMessage {
            rcan: v1::Rcan<Rpc>,
            note: String,
        }
        #[derive(Serialize, Deserialize)]
        struct NewMessage {
            delegation: V1Compat<Rpc>,
            note: String,
        }

        let old_wire = postcard::to_stdvec(&OldMessage {
            rcan: root.clone(),
            note: "hello".into(),
        })
        .unwrap();
        let new: NewMessage = postcard::from_bytes(&old_wire).unwrap();
        assert_eq!(new.note, "hello");
        assert_eq!(postcard::to_stdvec(&new).unwrap(), old_wire);

        // A v2 token cannot be represented in v1 compatible form.
        let v2_token: Delegation = v2::Delegation::issuing_builder(
            &service,
            alice.verifying_key(),
            &Rpc::All,
        )
        .sign(Expires::Never)
        .into();
        assert!(V1Compat::<Rpc>::try_from(v2_token).is_err());

        // Nor can a v1 token whose capability bytes are a different
        // vocabulary.
        #[derive(Debug, Serialize, Deserialize)]
        struct OtherVocabulary {
            topic: String,
            write: bool,
        }
        let naked_root = postcard::to_stdvec(&root).unwrap();
        let foreign = Delegation::decode_any::<Rpc>(&naked_root).unwrap();
        assert!(V1Compat::<OtherVocabulary>::try_from(foreign).is_err());
    }

    #[test]
    fn mixed_chain_invocation() {
        let service = key(0);
        let alice = key(1);
        let bob = key(2);

        // The root grant is a legacy v1 token...
        let root = v1::Rcan::issuing_builder(&service, alice.verifying_key(), Rpc::All)
            .sign(v1::Expires::Never);
        let root = Delegation::decode_any::<Rpc>(&root.encode()).unwrap();

        // ...and alice delegates onward with v2.
        let link = v2::Delegation::delegating_builder(
            &alice,
            bob.verifying_key(),
            service.verifying_key(),
            &Rpc::Read,
        )
        .sign(Expires::Never);
        let link: Delegation = link.into();

        let authorizer = Authorizer::new(service.verifying_key());
        let chain = [&root, &link];

        authorizer
            .check_invocation_from(bob.verifying_key(), Rpc::Read, &chain)
            .unwrap();
        assert!(
            authorizer
                .check_invocation_from(bob.verifying_key(), Rpc::ReadWrite, &chain)
                .is_err()
        );
        assert!(
            authorizer
                .check_invocation_from(key(3).verifying_key(), Rpc::Read, &chain)
                .is_err()
        );
    }
}
