use std::ops::Add;

// TODO: better error management (n0-error?)
use anyhow::{ensure, Result};
use ed25519_dalek::{
    ed25519::signature::Signer, Signature, SigningKey, VerifyingKey, SIGNATURE_LENGTH,
};
use n0_future::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};

/// Domain separation tag
pub const DST: &[u8] = b"rcan-2-delegation";

#[derive(Clone, Serialize, Deserialize, derive_more::Debug, PartialEq, Eq)]
pub struct Payload {
    /// The issuer
    #[debug("{}", hex::encode(issuer))]
    #[serde(with = "verifying_key_serde")]
    issuer: VerifyingKey,
    /// The intended audience
    #[debug("{}", hex::encode(audience))]
    #[serde(with = "verifying_key_serde")]
    audience: VerifyingKey,
    /// The origin of the capability
    capability_origin: CapabilityOrigin,
    /// Valid until unix timestamp in seconds.
    valid_until: Expires,
    /// The capability
    capability: Vec<u8>,
}

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

/// The potential origins of a capability.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum CapabilityOrigin {
    /// The origin is the issuer itself
    Issuer,
    /// This is a delegation, with this key being the root of the delegation chain.
    Delegation(#[serde(with = "verifying_key_serde")] VerifyingKey),
}

/// When an rcan expires
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
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("now is after UNIX_EPOCH")
                .add(duration)
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

/// A trait for types that define a capability.
///
/// Capabilities can be compared using [`Capability::permits`], which determines
/// whether one capability grants permission to perform another.
///
/// A common implementation of this trait might be an enum representing different
/// RPC request types.
///
/// The `Capability` type must be serializable so it can be included in the
/// payload of a [`Delegation`], and deserializable so it can be read back
/// out during [`Authorizer::check_invocation_from`].
pub trait Capability: Serialize + serde::de::DeserializeOwned {
    /// Determines if `self` permits `other`.
    ///
    /// Returns `true` if `self` grants permission to perform the `other` capability,
    /// otherwise returns `false`.
    fn permits(&self, other: &Self) -> bool;
}

/// An authorizer for invocations.
///
/// This represents an identity in the form of a public key.
/// This public key will always be the same as the original issuer of
/// the capabilities that are invoked against the authorizer.
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
    /// Each delegation stores its capability as opaque bytes; reading a
    /// concrete `C` out of them is deferred to this check, per link. The
    /// bytes must be a canonical `C` encoding, consumed exactly — a link
    /// whose capability does not parse in the invoked vocabulary is a
    /// deny.
    ///
    /// Make sure to verify that the `invoker` signed and authenticated
    /// the message containing the `capability`.
    pub fn check_invocation_from<C: Capability>(
        &self,
        invoker: VerifyingKey,
        capability: C,
        proof_chain: &[&Delegation],
    ) -> Result<()> {
        self.check_invocation_from_raw(
            invoker,
            |bytes| match postcard::take_from_bytes::<C>(bytes) {
                Ok((granted, [])) => granted.permits(&capability),
                _ => false,
            },
            proof_chain,
        )
    }

    /// The capability-agnostic chain walk: `permits` receives each
    /// delegation's raw capability bytes and decides whether they permit
    /// the invocation. A parse failure inside the predicate should be a
    /// deny (`false`), not an error.
    fn check_invocation_from_raw(
        &self,
        invoker: VerifyingKey,
        permits: impl Fn(&[u8]) -> bool,
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
            let audience = proof.audience();
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
            ensure!(permits(proof.capability()), "invocation failed");

            // Continue checking the proof chain's integrity with this
            // delegation's audience as the next issuer target:
            current_issuer_target = audience;
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

/// A token for attenuated capability delegations
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delegation {
    /// The actual content.
    pub payload: Payload,
    /// Signature over the serialized payload.
    pub signature: Signature,
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
            // An ed25519 signature is (R, s), two 32 byte halves. Two
            // 32 byte arrays encode as 64 raw bytes in postcard, and
            // arrays up to 32 have built-in serde impls.
            let r: &[u8; 32] = self.0[..32].try_into().expect("32 bytes");
            let s: &[u8; 32] = self.0[32..].try_into().expect("32 bytes");
            (r, s).serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for SignatureWire {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        use serde::de::Error;
        let mut bytes = [0u8; SIGNATURE_LENGTH];
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            hex::decode_to_slice(&s, &mut bytes).map_err(D::Error::custom)?;
        } else {
            let (r, s) = <([u8; 32], [u8; 32])>::deserialize(deserializer)?;
            bytes[..32].copy_from_slice(&r);
            bytes[32..].copy_from_slice(&s);
        }
        Ok(SignatureWire(bytes))
    }
}

impl Serialize for Delegation {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        (&self.payload, SignatureWire(self.signature.to_bytes())).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Delegation {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (payload, SignatureWire(sig_bytes)) = Deserialize::deserialize(deserializer)?;
        let delegation = Delegation {
            payload,
            signature: Signature::from_bytes(&sig_bytes),
        };

        // Verify before yielding, so a deserialized `Delegation` is
        // always signature checked.
        delegation
            .verify_signature()
            .map_err(serde::de::Error::custom)?;

        Ok(delegation)
    }
}

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

    /// Verify the signature over the payload. The signed bytes are
    /// `DST ++ postcard(payload)`, matching [`DelegationBuilder::sign`].
    fn verify_signature(&self) -> Result<()> {
        let signed = postcard::to_extend(&self.payload, DST.to_vec())?;
        self.payload
            .issuer
            .verify_strict(&signed, &self.signature)?;
        Ok(())
    }

    pub fn audience(&self) -> &VerifyingKey {
        &self.payload.audience
    }

    pub fn issuer(&self) -> &VerifyingKey {
        &self.payload.issuer
    }

    pub fn capability(&self) -> &[u8] {
        &self.payload.capability
    }

    pub fn capability_origin(&self) -> &CapabilityOrigin {
        &self.payload.capability_origin
    }

    pub fn capability_issuer(&self) -> &VerifyingKey {
        match self.payload.capability_origin {
            CapabilityOrigin::Issuer => &self.payload.issuer,
            CapabilityOrigin::Delegation(ref root) => root,
        }
    }

    pub fn expires(&self) -> &Expires {
        &self.payload.valid_until
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

        Delegation { signature, payload }
    }
}