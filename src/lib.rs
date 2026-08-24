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

/// A signed delegation granting a capability.
///
/// A `Delegation<C>` is a signed capability grant: it records who issued it,
/// who it was granted to (`audience`), what capability it carries, and when it
/// expires. Delegations can be chained (see [`CapabilityOrigin`]) so a receiver
/// can re-delegate an attenuated capability it was given.
///
/// Bare `Delegation` (the default `C = OpaqueCapability`) holds the capability
/// as raw bytes; turn it into a typed `Delegation<C>` with
/// [`try_into_typed`](Delegation::try_into_typed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delegation<C = OpaqueCapability> {
    issuer: VerifyingKey,
    audience: VerifyingKey,
    capability_origin: CapabilityOrigin,
    valid_until: Expires,
    /// The exact capability representation used by the signed payload.
    capability_bytes: Vec<u8>,
    signature: Signature,
    capability_type: std::marker::PhantomData<C>,
}

impl<C> Delegation<C> {
    fn new(
        issuer: VerifyingKey,
        audience: VerifyingKey,
        capability_origin: CapabilityOrigin,
        valid_until: Expires,
        capability_bytes: Vec<u8>,
        signature: Signature,
    ) -> Self {
        Self {
            issuer,
            audience,
            capability_origin,
            valid_until,
            capability_bytes,
            signature,
            capability_type: std::marker::PhantomData,
        }
    }

    /// Returns the delegation's signature.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Returns the public key of the issuing principal.
    pub fn issuer(&self) -> &VerifyingKey {
        &self.issuer
    }

    /// Returns the public key of the principal this delegation was granted to.
    pub fn audience(&self) -> &VerifyingKey {
        &self.audience
    }

    /// Returns the origin of the delegated capability.
    pub fn capability_origin(&self) -> &CapabilityOrigin {
        &self.capability_origin
    }

    /// Returns the public key of the principal that owns the capability.
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

    /// Returns the encoded capability bytes from the signed payload.
    pub fn capability_bytes(&self) -> &[u8] {
        &self.capability_bytes
    }

    fn with_capability_type<D>(self) -> Delegation<D> {
        Delegation::new(
            self.issuer,
            self.audience,
            self.capability_origin,
            self.valid_until,
            self.capability_bytes,
            self.signature,
        )
    }
}

impl<C> Delegation<C> {
    /// Turns this delegation into a `Delegation` with an opaque capability,
    /// preserving the capability bytes from the signed payload.
    pub fn into_opaque(self) -> Delegation {
        self.with_capability_type()
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
        BASE32_LOWER_NOPAD.encode(&self.encode())
    }
}

impl<C: CapabilityEncoding> Delegation<C> {
    /// Decodes and returns the capability from the signed payload.
    pub fn capability(&self) -> C {
        C::decode(&self.capability_bytes)
            .expect("capability was validated when the delegation was constructed")
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
        let bytes = BASE32_LOWER_NOPAD
            .decode(s.as_bytes())
            .map_err(DecodeError::malformed)?;
        Self::decode(&bytes)
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

/// Serializes the delegation as its byte encoding, or as a base32 string when
/// the format is human-readable. See [`Delegation::encode`].
impl<C> Serialize for Delegation<C> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.encode_string())
        } else {
            serializer.serialize_bytes(&self.encode())
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

/// A capability as raw, uninterpreted bytes.
///
/// This is the default capability type of a [`Delegation`]: a delegation whose
/// capability is not (yet) known. Any byte string is a valid `OpaqueCapability`.
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

impl Delegation {
    /// Consumes this delegation and returns it with the capability interpreted
    /// as `C`, yielding a typed [`Delegation<C>`].
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
    /// use rcan::{Delegation, Expires};
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
    /// let back: Delegation<Cap> = opaque.try_into_typed().unwrap();
    /// ```
    pub fn try_into_typed<C: CapabilityEncoding>(self) -> Result<Delegation<C>, DecodeError> {
        C::decode(&self.capability_bytes)?;
        Ok(self.with_capability_type())
    }
}

/// Where a delegated capability comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapabilityOrigin {
    /// The capability originates with the delegating principal itself.
    Issuer,
    /// The capability was previously granted by this root principal.
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

/// Builds and signs a [`Delegation`].
pub struct DelegationBuilder<'s, C> {
    issuer: &'s SigningKey,
    audience: VerifyingKey,
    capability_origin: CapabilityOrigin,
    capability: C,
}

impl<C: CapabilityEncoding> DelegationBuilder<'_, C> {
    /// Signs the delegation, returning a [`Delegation<C>`] valid until
    /// `valid_until`.
    pub fn sign(self, valid_until: Expires) -> Delegation<C> {
        let capability_bytes = C::encode(&self.capability);
        let delegation = Delegation::new(
            self.issuer.verifying_key(),
            self.audience,
            self.capability_origin,
            valid_until,
            capability_bytes,
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

/// The authority that verifies an invocation.
///
/// An [`Authorizer`] holds the public key of the principal that first issued a
/// capability. `check_invocation_from` verifies that an invocation is backed by
/// an unexpired, unbroken chain of delegations originating from that principal.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Authorizer {
    principal: VerifyingKey,
}

#[allow(clippy::result_large_err)]
impl Authorizer {
    /// Returns an authorizer for the given principal.
    pub fn new(principal: VerifyingKey) -> Self {
        Self { principal }
    }

    /// Verifies an invocation of `capability` by `invoker`, backed by
    /// `proof_chain`.
    ///
    /// The chain must start with the delegation issued by this authorizer's
    /// principal and end at `invoker`. Make sure the invoker signed and
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
    /// delegation with [`try_into_typed`](Delegation::try_into_typed) first,
    /// then check them here.
    pub fn check_invocation_from_at<C: Capability>(
        &self,
        now: SystemTime,
        invoker: VerifyingKey,
        capability: C,
        proof_chain: &[&Delegation<C>],
    ) -> Result<(), InvocationError> {
        // The chain is checked back-to-front: it starts at the owner of the
        // capability and each delegation names the next issuer.
        let mut current_issuer = &self.principal;
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
            if proof.capability_owner() != &self.principal {
                return Err(e!(InvocationError::CapabilityOwnerMismatch {
                    authorizer: self.principal,
                }));
            }
            if !proof.capability().permits(&capability) {
                return Err(e!(InvocationError::NotPermitted));
            }
            current_issuer = proof.audience();
        }
        if &invoker != current_issuer {
            return Err(e!(InvocationError::InvokerMismatch {
                invoker,
                chain_end: *current_issuer,
            }));
        }
        Ok(())
    }
}

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

/// Errors produced when decoding a delegation.
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum DecodeError {
    /// The input is malformed, with a reason.
    #[error("malformed token: {reason}")]
    Malformed { reason: String },
    /// The input is a legacy version-1 token, which this crate does not read.
    /// Re-encode it with an older rcan client first.
    #[error("rcan delegation version 1 not supported")]
    UnsupportedV1,
    /// The token's signature is invalid.
    #[error("signature verification failed")]
    InvalidSignature,
    /// The token's capability is not a valid encoding of the expected type.
    #[error("capability does not parse as the expected capability type")]
    WrongCapability,
}

impl DecodeError {
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
    /// principal than the previous delegation was granted to.
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
    /// A delegation in the chain delegates a capability from a different owner.
    CapabilityOwnerMismatch { authorizer: VerifyingKey },
    /// No delegation in the chain permits the requested capability.
    #[error("capability not permitted")]
    NotPermitted,
    #[error(
        "expected delegation chain to end in the connection's owner {}, but the connection is authenticated by {} instead",
        hex::encode(invoker),
        hex::encode(chain_end)
    )]
    /// The final audience in the chain does not match the invoker.
    InvokerMismatch {
        invoker: VerifyingKey,
        chain_end: VerifyingKey,
    },
}

/// The domain-separation tag distinguishing rcan delegations from other
/// ed25519-signed data. Exposed for applications that re-verify signatures.
pub const DST: &[u8] = b"rcan-2-delegation";

pub(crate) const BASE32_LOWER_NOPAD: data_encoding::Encoding = data_encoding_macro::new_encoding!(
    symbols: "abcdefghijklmnopqrstuvwxyz234567",
);

fn encode_body<C>(delegation: &Delegation<C>, out: &mut Vec<u8>) {
    out.extend_from_slice(delegation.issuer.as_bytes());
    out.extend_from_slice(delegation.audience.as_bytes());
    match &delegation.capability_origin {
        CapabilityOrigin::Issuer => write_varint(0, out),
        CapabilityOrigin::Delegation(root) => {
            write_varint(1, out);
            out.extend_from_slice(root.as_bytes());
        }
    }
    match &delegation.valid_until {
        Expires::Never => write_varint(0, out),
        Expires::At(t) => {
            write_varint(1, out);
            write_varint(*t, out);
        }
    }
    write_varint(delegation.capability_bytes.len() as u64, out);
    out.extend_from_slice(&delegation.capability_bytes);
}

fn decode_v2_checked<C: CapabilityEncoding>(bytes: &[u8]) -> Result<Delegation<C>, DecodeError> {
    if bytes.len() < SIGNATURE_LENGTH {
        return Err(DecodeError::malformed("invalid signature length"));
    }
    let (body_bytes, sig_bytes) = bytes.split_at(bytes.len() - SIGNATURE_LENGTH);
    let mut body = body_bytes;
    let delegation = decode_body::<C>(&mut body)?;
    if !body.is_empty() {
        return Err(DecodeError::malformed("non canonical encoding of payload"));
    }
    let signature = Signature::from_bytes(
        sig_bytes
            .try_into()
            .map_err(|_| DecodeError::malformed("invalid signature length"))?,
    );
    let mut to_verify = DST.to_vec();
    to_verify.extend_from_slice(body_bytes);
    delegation
        .issuer
        .verify_strict(&to_verify, &signature)
        .map_err(|_| e!(DecodeError::InvalidSignature))?;
    Ok(Delegation::new(
        delegation.issuer,
        delegation.audience,
        delegation.capability_origin,
        delegation.valid_until,
        delegation.capability_bytes,
        signature,
    ))
}

fn decode_body<C: CapabilityEncoding>(buf: &mut &[u8]) -> Result<Delegation<C>, DecodeError> {
    let issuer = take_key(buf)?;
    let audience = take_key(buf)?;
    let capability_origin = match take_varint(buf)? {
        0 => CapabilityOrigin::Issuer,
        1 => CapabilityOrigin::Delegation(take_key(buf)?),
        tag => {
            return Err(DecodeError::malformed(format!(
                "unknown capability origin tag {tag}"
            )))
        }
    };
    let valid_until = match take_varint(buf)? {
        0 => Expires::Never,
        1 => Expires::At(take_varint(buf)?),
        tag => return Err(DecodeError::malformed(format!("unknown expires tag {tag}"))),
    };
    let cap_len = usize::try_from(take_varint(buf)?)
        .map_err(|_| DecodeError::malformed("capability length overflow"))?;
    let cap_bytes = take_bytes(buf, cap_len)?;
    C::decode(cap_bytes)?;
    let capability_bytes = cap_bytes.to_vec();

    Ok(Delegation::new(
        issuer,
        audience,
        capability_origin,
        valid_until,
        capability_bytes,
        Signature::from_bytes(&[0u8; 64]),
    ))
}

fn take_bytes<'a>(buf: &mut &'a [u8], n: usize) -> Result<&'a [u8], DecodeError> {
    let (head, rest) = buf
        .split_at_checked(n)
        .ok_or_else(|| DecodeError::malformed("payload is truncated"))?;
    *buf = rest;
    Ok(head)
}

fn take_chunk<'a, const N: usize>(buf: &mut &'a [u8]) -> Result<&'a [u8; N], DecodeError> {
    let Some((head, rest)) = buf.split_first_chunk() else {
        return Err(DecodeError::malformed("payload is truncated"));
    };
    *buf = rest;
    Ok(head)
}

fn take_key(buf: &mut &[u8]) -> Result<VerifyingKey, DecodeError> {
    let bytes = take_chunk::<32>(buf)?;
    VerifyingKey::from_bytes(bytes).map_err(|_| DecodeError::malformed("invalid key"))
}

/// Appends postcard's canonical varint encoding of `value` to `out`.
fn write_varint(value: u64, out: &mut Vec<u8>) {
    let mut buf = [0u8; 10];
    let encoded = postcard::to_slice(&value, &mut buf).expect("u64 fits in ten bytes");
    out.extend_from_slice(encoded);
}

/// Takes one canonically postcard-encoded `u64` from the front of `buf`.
///
/// The input slice is advanced only on success. This rejects truncated,
/// overflowing, and non-minimal encodings without heap allocation.
fn take_varint(buf: &mut &[u8]) -> Result<u64, DecodeError> {
    let before = *buf;
    let (value, rest) = postcard::take_from_bytes::<u64>(before)
        .map_err(|error| DecodeError::malformed(format!("invalid varint: {error}")))?;
    let consumed = &before[..before.len() - rest.len()];

    let mut canonical_buf = [0u8; 10];
    let canonical = postcard::to_slice(&value, &mut canonical_buf).expect("u64 fits in ten bytes");
    if consumed != canonical {
        return Err(DecodeError::malformed("non-canonical varint"));
    }

    *buf = rest;
    Ok(value)
}
