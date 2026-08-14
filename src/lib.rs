//! Capability-based authorization through signed delegations.
//!
//! An issuer grants a [`Capability`] to an audience by signing a
//! [`Delegation`]. Delegations can be chained, so a grant can be re-delegated
//! along a path. An [`Authorizer`] verifies that an invocation of a capability
//! is backed by a valid, unexpired chain of delegations.
//!
//! Take a look at [`Delegation`] and [`Authorizer::check_invocation_from`] to
//! get started.

use ed25519_dalek::{
    ed25519::signature::Signer, Signature, SigningKey, VerifyingKey, SIGNATURE_LENGTH,
};
use n0_error::{e, stack_error};
use n0_future::time::{Duration, SystemTime};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[cfg(test)]
mod tests;

/// The domain-separation tag distinguishing rcan delegations from other
/// ed25519-signed data. Exposed for applications that re-verify signatures.
pub const DST: &[u8] = b"rcan-2-delegation";

/// A capability that can be converted to and from its byte representation.
///
/// The bytes are what a [`Delegation`] stores and signs. You usually won't
/// implement this yourself: any [`Serialize`] + [`Deserialize`] type is
/// supported automatically.
pub trait CapabilityEncoding {
    /// Returns the bytes this capability is represented as inside a delegation.
    fn encode(&self) -> Vec<u8>;

    /// Decodes a capability from its bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::WrongCapability`] if `bytes` is not a valid
    /// encoding of this capability.
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError>
    where
        Self: Sized;
}

impl<T: Serialize + DeserializeOwned> CapabilityEncoding for T {
    fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("capability serializes")
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        match postcard::take_from_bytes::<Self>(bytes) {
            Ok((value, [])) => Ok(value),
            _ => Err(e!(DecodeError::WrongCapability)),
        }
    }
}

/// A grantable capability.
///
/// Implement this for your own capability type, typically an enum of the
/// operations or resources you want to authorize. [`permits`] defines how
/// broader capabilities imply narrower ones.
///
/// [`permits`]: Capability::permits
pub trait Capability: CapabilityEncoding {
    /// Returns `true` if `self` grants the permissions described by `other`.
    fn permits(&self, other: &Self) -> bool;
}

/// The authority that verifies an invocation.
///
/// An [`Authorizer`] holds the public key of the identity that first issued a
/// capability. `check_invocation_from` verifies that an invocation is backed by
/// an unexpired, unbroken chain of delegations originating from that identity.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Authorizer {
    identity: VerifyingKey,
}

#[allow(clippy::result_large_err)]
impl Authorizer {
    /// Returns an authorizer for the given verifying key.
    pub fn new(identity: VerifyingKey) -> Self {
        Self { identity }
    }

    /// Verifies an invocation of `capability` by `invoker`, backed by
    /// `proof_chain`.
    ///
    /// The chain must start with the delegation issued by this authorizer's
    /// identity and end at `invoker`. Make sure the invoker signed and
    /// authenticated the message carrying `capability`; this method only
    /// checks the capability chain itself.
    ///
    /// # Examples
    ///
    /// ```
    /// use ed25519_dalek::SigningKey;
    /// use rcan::{Authorizer, Capability, Delegation, Expires};
    /// use serde::{Deserialize, Serialize};
    ///
    /// #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    /// enum Cap {
    ///     Read,
    ///     All,
    /// }
    /// impl Capability for Cap {
    ///     fn permits(&self, other: &Self) -> bool {
    ///         *self == Cap::All || self == other
    ///     }
    /// }
    ///
    /// let service = SigningKey::from_bytes(&[0u8; 32]);
    /// let alice = SigningKey::from_bytes(&[1u8; 32]);
    ///
    /// let grant = Delegation::issuing_builder(&service, alice.verifying_key(), &Cap::All)
    ///     .sign(Expires::Never);
    ///
    /// let authorizer = Authorizer::new(service.verifying_key());
    /// authorizer
    ///     .check_invocation_from(alice.verifying_key(), Cap::Read, &[&grant])
    ///     .unwrap();
    /// ```
    pub fn check_invocation_from<C: Capability>(
        &self,
        invoker: VerifyingKey,
        capability: C,
        proof_chain: &[&Delegation<C>],
    ) -> Result<(), InvocationError> {
        self.check_invocation_from_at(SystemTime::now(), invoker, capability, proof_chain)
    }

    /// Like [`check_invocation_from`](Self::check_invocation_from), but evaluates
    /// expiry against an explicit time instead of "now".
    ///
    /// Opaque delegations are not checked directly; parse them into a typed
    /// delegation with [`OpaqueDelegation::parse`] first, then check them here.
    pub fn check_invocation_from_at<C: Capability>(
        &self,
        now: SystemTime,
        invoker: VerifyingKey,
        capability: C,
        proof_chain: &[&Delegation<C>],
    ) -> Result<(), InvocationError> {
        // The chain is checked back-to-front: it starts at the owner of the
        // capability and each delegation names the next issuer.
        let mut current_issuer = &self.identity;
        for proof in proof_chain {
            if proof.issuer() != current_issuer {
                return Err(e!(InvocationError::ChainBroken {
                    expected: *current_issuer,
                    found: *proof.issuer(),
                }));
            }
            if !proof.expires().is_valid_at(now) {
                return Err(e!(InvocationError::Expired {
                    expiry: proof.expires().clone(),
                }));
            }
            if proof.capability_owner() != &self.identity {
                return Err(e!(InvocationError::WrongCapabilityOwner {
                    authorizer: self.identity,
                }));
            }
            if !proof.capability_ref().permits(&capability) {
                return Err(e!(InvocationError::NotPermitted));
            }
            current_issuer = proof.audience();
        }
        if &invoker != current_issuer {
            return Err(e!(InvocationError::WrongInvoker {
                invoker,
                chain_end: *current_issuer,
            }));
        }
        Ok(())
    }
}

/// A capability as raw, uninterpreted bytes.
///
/// Used by [`OpaqueDelegation`] to carry a delegation whose capability type is
/// not (yet) known. Any byte string is a valid `OpaqueCapability`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpaqueCapability(Vec<u8>);

impl OpaqueCapability {
    /// Returns the underlying capability bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl CapabilityEncoding for OpaqueCapability {
    fn encode(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(bytes.to_vec()))
    }
}

impl Capability for OpaqueCapability {
    fn permits(&self, other: &Self) -> bool {
        self == other
    }
}

/// A delegation whose capability is held as raw bytes rather than a typed
/// value. See [`Delegation`].
pub type OpaqueDelegation = Delegation<OpaqueCapability>;

impl Delegation<OpaqueCapability> {
    /// Parses this delegation's capability bytes as a `C`, yielding a typed
    /// [`Delegation<C>`].
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::WrongCapability`] if the bytes are not a valid
    /// encoding of `C` (unless `C` is [`OpaqueCapability`], which accepts any
    /// bytes).
    ///
    /// # Examples
    ///
    /// ```
    /// use ed25519_dalek::SigningKey;
    /// use rcan::{Delegation, Expires, OpaqueDelegation};
    /// use serde::{Deserialize, Serialize};
    ///
    /// #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    /// enum Cap {
    ///     Read,
    /// }
    ///
    /// let key = SigningKey::from_bytes(&[0u8; 32]);
    /// let typed =
    ///     Delegation::issuing_builder(&key, key.verifying_key(), &Cap::Read).sign(Expires::Never);
    /// let opaque = typed.into_opaque();
    /// let back: Delegation<Cap> = opaque.parse().unwrap();
    /// ```
    pub fn parse<C: CapabilityEncoding>(self) -> Result<Delegation<C>, DecodeError> {
        let capability = C::decode(self.capability.as_bytes())?;
        Ok(Delegation::new(
            self.issuer,
            self.audience,
            self.capability_origin,
            self.valid_until,
            capability,
            self.signature,
        ))
    }
}

/// A signed delegation granting a capability.
///
/// A `Delegation<C>` is a signed capability grant: it records who issued it,
/// who it was granted to (`audience`), what capability it carries, and when it
/// expires. Delegations can be chained (see [`CapabilityOrigin`]) so a receiver
/// can re-delegate an attenuated capability it was given.
///
/// The [`OpaqueDelegation`] form carries the capability as raw bytes and is
/// turned into a typed `Delegation<C>` with [`parse`](OpaqueDelegation::parse).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delegation<C> {
    issuer: VerifyingKey,
    audience: VerifyingKey,
    capability_origin: CapabilityOrigin,
    valid_until: Expires,
    capability: C,
    signature: Signature,
}

impl<C> Delegation<C> {
    /// Constructs a new delegation from its parts.
    fn new(
        issuer: VerifyingKey,
        audience: VerifyingKey,
        capability_origin: CapabilityOrigin,
        valid_until: Expires,
        capability: C,
        signature: Signature,
    ) -> Self {
        Self {
            issuer,
            audience,
            capability_origin,
            valid_until,
            capability,
            signature,
        }
    }

    /// Returns the delegation's signature.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Returns the issuing identity.
    pub fn issuer(&self) -> &VerifyingKey {
        &self.issuer
    }

    /// Returns the identity this delegation was granted to.
    pub fn audience(&self) -> &VerifyingKey {
        &self.audience
    }

    /// Returns the origin of the delegated capability.
    pub fn capability_origin(&self) -> &CapabilityOrigin {
        &self.capability_origin
    }

    /// Returns the identity that owns the capability.
    pub fn capability_owner(&self) -> &VerifyingKey {
        match &self.capability_origin {
            CapabilityOrigin::Issuer => &self.issuer,
            CapabilityOrigin::Delegation(root) => root,
        }
    }

    /// Returns when this delegation expires.
    pub fn expires(&self) -> &Expires {
        &self.valid_until
    }

    /// Returns the stored capability, without cloning. Crate-internal; the
    /// public [`capability`](Self::capability) returns an owned copy.
    pub(crate) fn capability_ref(&self) -> &C {
        &self.capability
    }
}

impl<C: Clone> Delegation<C> {
    /// Returns a copy of the stored capability.
    pub fn capability(&self) -> C {
        self.capability.clone()
    }
}

impl<C: CapabilityEncoding> Delegation<C> {
    /// Turns this delegation into an [`OpaqueDelegation`], encoding the
    /// capability to bytes.
    pub fn into_opaque(self) -> OpaqueDelegation {
        OpaqueDelegation::new(
            self.issuer,
            self.audience,
            self.capability_origin,
            self.valid_until,
            OpaqueCapability(C::encode(&self.capability)),
            self.signature,
        )
    }

    /// Returns the delegation's byte encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut res = vec![2u8];
        encode_body(self, &mut res);
        res.extend_from_slice(&self.signature.to_bytes());
        res
    }

    /// Returns a lowercase base32 string of the delegation's byte encoding,
    /// useful for compact, printable representations.
    pub fn encode_string(&self) -> String {
        let mut out = data_encoding::BASE32_NOPAD.encode(&self.encode());
        out.make_ascii_lowercase();
        out
    }

    /// Decodes a delegation from its byte encoding, verifying the signature and
    /// decoding the capability as `C`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnsupportedV1`] for legacy format tokens,
    /// [`DecodeError::WrongCapability`] if the capability is not a valid `C`,
    /// and other [`DecodeError`]s if the token is malformed or its signature is
    /// invalid.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        match bytes.split_first() {
            None => Err(DecodeError::malformed("token is empty")),
            Some((0x01, _)) | Some((0x20, _)) => Err(e!(DecodeError::UnsupportedV1)),
            Some((0x02, bytes)) => decode_v2_checked::<C>(bytes),
            Some((v, _)) => Err(DecodeError::malformed(format!(
                "unknown version byte {:#x}",
                v
            ))),
        }
    }

    /// Decodes a delegation from a base32 string, verifying the signature and
    /// decoding the capability as `C`. See [`decode`](Delegation::decode).
    pub fn decode_string(s: &str) -> Result<Self, DecodeError> {
        Self::decode(&base32_bytes(s)?)
    }
}

/// Decodes a v2 delegation, verifying the signature and canonical encoding and
/// that the capability decodes as `C`.
fn decode_v2_checked<C: CapabilityEncoding>(bytes: &[u8]) -> Result<Delegation<C>, DecodeError> {
    if bytes.len() < SIGNATURE_LENGTH {
        return Err(DecodeError::malformed("invalid signature length"));
    }
    let (body_bytes, sig_bytes) = bytes.split_at(bytes.len() - SIGNATURE_LENGTH);
    let (delegation, used) = decode_body::<C>(body_bytes)?;
    if used != body_bytes.len() {
        return Err(DecodeError::malformed("non canonical encoding of payload"));
    }
    let signature = Signature::from_bytes(
        sig_bytes
            .try_into()
            .map_err(|_| DecodeError::malformed("invalid signature length"))?,
    );
    let mut to_verify = DST.to_vec();
    encode_body::<C>(&delegation, &mut to_verify);
    if to_verify[DST.len()..] != *body_bytes {
        return Err(DecodeError::malformed("non canonical encoding of payload"));
    }
    delegation
        .issuer
        .verify_strict(&to_verify, &signature)
        .map_err(|_| e!(DecodeError::InvalidSignature))?;
    Ok(Delegation::new(
        delegation.issuer,
        delegation.audience,
        delegation.capability_origin,
        delegation.valid_until,
        delegation.capability,
        signature,
    ))
}

/// Where a delegated capability comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapabilityOrigin {
    /// The capability originates with the delegating identity itself.
    Issuer,
    /// The capability was previously granted by this root identity.
    Delegation(VerifyingKey),
}

/// When a delegation expires.
#[derive(Clone, Debug, PartialEq, Eq, derive_more::Display)]
pub enum Expires {
    /// The delegation never expires.
    #[display("never")]
    Never,
    /// The delegation is valid until the given Unix timestamp (in seconds).
    #[display("{_0}")]
    At(u64),
}

impl Expires {
    /// Returns an expiry `duration` from now.
    pub fn valid_for(duration: Duration) -> Self {
        Self::At(
            (SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("now is after UNIX_EPOCH")
                + duration)
                .as_secs(),
        )
    }

    /// Returns `true` if the delegation is still valid at `time`.
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

impl<C: Clone> Delegation<C> {
    /// Returns a builder for a delegation that `issuer` issues to `audience`
    /// for `capability`, where `issuer` is the origin of the capability.
    pub fn issuing_builder<'s>(
        issuer: &'s SigningKey,
        audience: VerifyingKey,
        capability: &C,
    ) -> DelegationBuilder<'s, C> {
        DelegationBuilder {
            issuer,
            audience,
            capability_origin: CapabilityOrigin::Issuer,
            capability: capability.clone(),
        }
    }

    /// Returns a builder for a delegation that `issuer` issues to `audience`
    /// for `capability`, where the capability was originally held by `owner`.
    pub fn delegating_builder<'s>(
        issuer: &'s SigningKey,
        audience: VerifyingKey,
        owner: VerifyingKey,
        capability: &C,
    ) -> DelegationBuilder<'s, C> {
        DelegationBuilder {
            issuer,
            audience,
            capability_origin: CapabilityOrigin::Delegation(owner),
            capability: capability.clone(),
        }
    }
}

/// Builds and signs a [`Delegation`].
pub struct DelegationBuilder<'s, C> {
    issuer: &'s SigningKey,
    audience: VerifyingKey,
    capability_origin: CapabilityOrigin,
    capability: C,
}

impl<C: CapabilityEncoding + Clone> DelegationBuilder<'_, C> {
    /// Signs the delegation, returning a [`Delegation<C>`] valid until
    /// `valid_until`.
    pub fn sign(self, valid_until: Expires) -> Delegation<C> {
        let delegation = Delegation::new(
            self.issuer.verifying_key(),
            self.audience,
            self.capability_origin,
            valid_until,
            self.capability,
            Signature::from_bytes(&[0u8; 64]),
        );
        let mut to_sign = DST.to_vec();
        encode_body(&delegation, &mut to_sign);
        let signature = self.issuer.sign(&to_sign);
        Delegation {
            signature,
            ..delegation
        }
    }
}

/// Errors produced when decoding a delegation.
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum DecodeError {
    /// The input is malformed, with a reason.
    #[error("malformed token: {reason}")]
    Malformed { reason: String },
    /// The input is a version-1 (legacy) token; use rcan 0.4.x to read those.
    #[error("v1 tokens are not supported, use rcan 0.4.x to read them")]
    UnsupportedV1,
    /// The token's signature is invalid.
    #[error("signature verification failed")]
    InvalidSignature,
    /// The token's capability is not a valid encoding of the expected type.
    #[error("capability does not parse as the expected capability type")]
    WrongCapability,
}

impl DecodeError {
    /// Returns a `Malformed` error for the given `reason`.
    fn malformed(reason: impl std::fmt::Display) -> Self {
        e!(DecodeError::Malformed {
            reason: reason.to_string()
        })
    }
}

/// Errors produced while verifying an invocation.
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum InvocationError {
    /// The proof chain is broken: a delegation was issued by a different
    /// identity than the previous delegation was granted to.
    #[error(
        "expected proof to be issued by {}, but was issued by {}",
        hex::encode(expected),
        hex::encode(found)
    )]
    ChainBroken {
        expected: VerifyingKey,
        found: VerifyingKey,
    },
    /// A delegation in the chain has expired.
    #[error("proof expired at {expiry}")]
    Expired { expiry: Expires },
    #[error(
        "proof is missing delegation for capability of {}",
        hex::encode(authorizer)
    )]
    /// A delegation in the chain does not convey the authorizer's capability.
    WrongCapabilityOwner { authorizer: VerifyingKey },
    /// No delegation in the chain permits the requested capability.
    #[error("capability not permitted")]
    NotPermitted,
    #[error(
        "expected delegation chain to end in the connection's owner {}, but the connection is authenticated by {} instead",
        hex::encode(invoker),
        hex::encode(chain_end)
    )]
    /// The final audience in the chain does not match the invoker.
    WrongInvoker {
        invoker: VerifyingKey,
        chain_end: VerifyingKey,
    },
}

/// Serializes the delegation as its byte encoding, or as a base32 string when
/// the format is human-readable. See [`Delegation::encode`].
impl<C: CapabilityEncoding> Serialize for Delegation<C> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.encode_string())
        } else {
            self.encode().serialize(serializer)
        }
    }
}

/// See [`Delegation::decode`], which this forwards to.
impl<'de, C: CapabilityEncoding> Deserialize<'de> for Delegation<C> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let delegation = if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Self::decode_string(&s)
        } else {
            let v = Vec::<u8>::deserialize(deserializer)?;
            Self::decode(&v)
        };
        delegation.map_err(D::Error::custom)
    }
}

/// Encodes a delegation's payload (everything except its signature) into the
/// canonical byte representation that gets signed.
fn encode_body<C: CapabilityEncoding>(delegation: &Delegation<C>, out: &mut Vec<u8>) {
    out.extend_from_slice(delegation.issuer.as_bytes());
    out.extend_from_slice(delegation.audience.as_bytes());
    match &delegation.capability_origin {
        CapabilityOrigin::Issuer => bijoux::u64::encode(0, out),
        CapabilityOrigin::Delegation(root) => {
            bijoux::u64::encode(1, out);
            out.extend_from_slice(root.as_bytes());
        }
    }
    match &delegation.valid_until {
        Expires::Never => bijoux::u64::encode(0, out),
        Expires::At(t) => {
            bijoux::u64::encode(1, out);
            bijoux::u64::encode(*t, out);
        }
    }
    let capability = C::encode(&delegation.capability);
    bijoux::u64::encode(capability.len() as u64, out);
    out.extend_from_slice(&capability);
}

/// Decodes a delegation's payload from its canonical byte representation,
/// returning it along with the number of bytes consumed. The capability is
/// decoded as `C`, and the signature field is left empty.
fn decode_body<C: CapabilityEncoding>(bytes: &[u8]) -> Result<(Delegation<C>, usize), DecodeError> {
    let mut cursor = 0usize;
    macro_rules! take {
        ($n:expr) => {{
            let end = cursor
                .checked_add($n)
                .ok_or_else(|| DecodeError::malformed("payload length overflow"))?;
            let slice = bytes
                .get(cursor..end)
                .ok_or_else(|| DecodeError::malformed("payload is truncated"))?;
            cursor = end;
            slice
        }};
    }
    macro_rules! take_u64 {
        () => {{
            let (value, consumed) = bijoux::u64::decode(&bytes[cursor..])
                .map_err(|e| DecodeError::malformed(format!("invalid varint: {e}")))?;
            cursor += consumed;
            value
        }};
    }

    let issuer = VerifyingKey::from_bytes(take!(32).try_into().expect("32 bytes"))
        .map_err(|_| DecodeError::malformed("invalid issuer"))?;
    let audience = VerifyingKey::from_bytes(take!(32).try_into().expect("32 bytes"))
        .map_err(|_| DecodeError::malformed("invalid audience"))?;
    let capability_origin = match take_u64!() {
        0 => CapabilityOrigin::Issuer,
        1 => {
            let root = VerifyingKey::from_bytes(take!(32).try_into().expect("32 bytes"))
                .map_err(|_| DecodeError::malformed("invalid capability origin"))?;
            CapabilityOrigin::Delegation(root)
        }
        tag => {
            return Err(DecodeError::malformed(format!(
                "unknown capability origin tag {tag}"
            )))
        }
    };
    let valid_until = match take_u64!() {
        0 => Expires::Never,
        1 => Expires::At(take_u64!()),
        tag => return Err(DecodeError::malformed(format!("unknown expires tag {tag}"))),
    };
    let cap_len = usize::try_from(take_u64!())
        .map_err(|_| DecodeError::malformed("capability length overflow"))?;
    let cap_bytes = take!(cap_len);
    let capability = C::decode(cap_bytes)?;

    Ok((
        Delegation::new(
            issuer,
            audience,
            capability_origin,
            valid_until,
            capability,
            Signature::from_bytes(&[0u8; 64]),
        ),
        cursor,
    ))
}

/// Decodes a string as case insensitive base32, returning the bytes.
///
/// If the string is not valid base32, returns a [`DecodeError::Malformed`] error.
fn base32_bytes(s: &str) -> Result<Vec<u8>, DecodeError> {
    data_encoding::BASE32_NOPAD
        .decode(s.to_ascii_uppercase().as_bytes())
        .map_err(DecodeError::malformed)
}
