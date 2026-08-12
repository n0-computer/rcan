//! RCANs: really simple user Controlled Authorization Networks.
//!
//! A [`Delegation`] is a [`Payload`] plus the issuer's signature over it.
//! The payload has five fields: issuer, audience, capability origin,
//! expiry, and the capability as opaque, length delimited bytes. The
//! envelope never interprets the capability: typing happens at the
//! edges, via the [`Capability`] trait.
//!
//! The wire format is versioned coarsely by a leading version byte.
//! The current, and only supported, version is 2. Version 1 tokens (the
//! `Rcan<C>` of rcan 0.4.x) are not read by this crate; use rcan 0.4.x
//! to read them.

use ed25519_dalek::{
    ed25519::signature::Signer, Signature, SigningKey, VerifyingKey, SIGNATURE_LENGTH,
};
use n0_error::{e, stack_error};
use n0_future::time::{Duration, SystemTime};
use postcard::take_from_bytes;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Domain separation tag for v2 signatures.
pub const DST: &[u8] = b"rcan-2-delegation";

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
/// A capability owner must not sign delegations in more than one capability
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

/// Decoding a delegation failed.
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum DecodeError {
    /// The bytes are not a well formed token.
    #[error("malformed token: {reason}")]
    Malformed {
        /// What went wrong.
        reason: String,
    },
    /// The token is a v1 token (rcan 0.4.x), which this crate does not
    /// support. Read it with the rcan 0.4.x crate instead.
    #[error("v1 tokens are not supported, use rcan 0.4.x to read them")]
    UnsupportedV1,
    /// Signature verification failed.
    #[error("signature verification failed")]
    InvalidSignature,
    /// The capability bytes are not a canonical encoding in the
    /// vocabulary.
    #[error("capability does not parse in the vocabulary")]
    ForeignVocabulary,
}

impl DecodeError {
    /// The catch-all for decode failures that carry no structure worth
    /// matching on.
    fn malformed(reason: impl std::fmt::Display) -> Self {
        e!(DecodeError::Malformed {
            reason: reason.to_string()
        })
    }
}

/// Verifying an invocation against a proof chain failed.
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum InvocationError {
    /// A proof was not issued by the expected key.
    ///
    /// Chains run back-to-front: the first proof must be issued by the
    /// authorizer, each further one by the previous proof's audience.
    #[error(
        "expected proof to be issued by {}, but was issued by {}",
        hex::encode(expected),
        hex::encode(found)
    )]
    ChainBroken {
        /// The key that should have issued this proof.
        expected: VerifyingKey,
        /// The key that issued it.
        found: VerifyingKey,
    },
    /// A proof's validity window has passed.
    #[error("proof expired at {expiry}")]
    Expired {
        /// When the proof expired.
        expiry: Expires,
    },
    /// A proof passes on authority that is not rooted at the authorizer.
    #[error(
        "proof is missing delegation for capability of {}",
        hex::encode(authorizer)
    )]
    WrongCapabilityIssuer {
        /// The authorizer's key.
        authorizer: VerifyingKey,
    },
    /// A proof's capability does not parse in the vocabulary or does not
    /// permit the invoked capability.
    #[error("capability not permitted")]
    NotPermitted,
    /// The chain does not end at the invoker.
    #[error(
        "expected delegation chain to end in the connection's owner {}, but the connection is authenticated by {} instead",
        hex::encode(invoker),
        hex::encode(chain_end)
    )]
    WrongInvoker {
        /// The key that invoked the capability.
        invoker: VerifyingKey,
        /// The key the chain actually ends at.
        chain_end: VerifyingKey,
    },
}

/// The signed content of a delegation.
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
    /// The capability, as opaque length delimited bytes.
    #[debug("{}", hex::encode(capability))]
    capability: Vec<u8>,
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

/// A payload with its signature over `DST ++ postcard(payload)`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Signed {
    payload: Payload,
    signature: Signature,
}

/// A token for attenuated capability delegations.
///
/// All envelope fields are accessible without a capability type, so
/// verification ([`Authorizer`]) and transport code can be capability
/// agnostic. The capability type is needed only to evaluate capabilities
/// during invocation checks.
///
/// There are two byte representations:
///
/// - [`Self::encode`] / [`Self::decode`]: the versioned wire form.
/// - serde: for binary formats, that same wire form behind a length
///   prefix; for human-readable formats (JSON, RON, TOML, ...) one opaque
///   string — lowercase base32 of the wire form
///   ([`Self::encode_string`]) — instead of a per-field structure.
///   Signatures are verified on deserialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaqueDelegation(Signed);

pub struct DelegationBuilder<'s, C> {
    issuer: &'s SigningKey,
    audience: VerifyingKey,
    capability_origin: CapabilityOrigin,
    capability: Vec<u8>,
    capability_type: std::marker::PhantomData<C>,
}

impl<C: Serialize> Delegation<C> {
    pub fn issuing_builder<'s>(
        issuer: &'s SigningKey,
        audience: VerifyingKey,
        capability: &C,
    ) -> DelegationBuilder<'s, C> {
        DelegationBuilder {
            issuer,
            audience,
            capability_origin: CapabilityOrigin::Issuer,
            capability: postcard::to_stdvec(capability).expect("vec"),
            capability_type: std::marker::PhantomData,
        }
    }

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
            capability: postcard::to_stdvec(capability).expect("vec"),
            capability_type: std::marker::PhantomData,
        }
    }
}

fn read_signed<T: DeserializeOwned>(bytes: &[u8]) -> Result<(T, Signature), DecodeError> {
    let (payload, signature) = take_from_bytes::<T>(bytes).map_err(DecodeError::malformed)?;
    let signature = Signature::from_bytes(
        signature
            .try_into()
            .map_err(|_| DecodeError::malformed("invalid signature length"))?,
    );
    Ok((payload, signature))
}

fn append_postcard<T: Serialize>(payload: &T, dst: &mut Vec<u8>) {
    postcard::to_io(payload, dst).expect("postcard ser failed");
}

impl OpaqueDelegation {
    fn decode_v2(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (payload, signature) = read_signed::<Payload>(bytes)?;
        let mut to_verify = DST.to_vec();
        append_postcard(&payload, &mut to_verify);
        if to_verify[DST.len()..] != bytes[..bytes.len() - SIGNATURE_LENGTH] {
            return Err(DecodeError::malformed("non canonical encoding of payload"));
        }
        payload
            .issuer
            .verify_strict(&to_verify, &signature)
            .map_err(|_| e!(DecodeError::InvalidSignature))?;
        Ok(Self(Signed { payload, signature }))
    }

    /// Decode a v2 token. A successful decode is signature checked, and
    /// the input must be consumed exactly.
    ///
    /// v1 tokens ([`DecodeError::UnsupportedV1`]) are rejected; read them
    /// with rcan 0.4.x.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        match bytes.split_first() {
            None => Err(DecodeError::malformed("token is empty")),
            Some((0x01, _)) | Some((0x20, _)) => Err(e!(DecodeError::UnsupportedV1)),
            Some((0x02, bytes)) => Self::decode_v2(bytes),
            Some((v, _)) => Err(DecodeError::malformed(format!(
                "unknown version byte {:#x}",
                v
            ))),
        }
    }

    /// Encode in the versioned wire form.
    pub fn encode(&self) -> Vec<u8> {
        let mut res = Vec::new();
        res.push(2u8);
        append_postcard(&self.0.payload, &mut res);
        res.extend_from_slice(&self.0.signature.to_bytes());
        res
    }

    pub(crate) fn signed(&self) -> &Signed {
        &self.0
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

impl<C> DelegationBuilder<'_, C> {
    /// Sign, producing a [`Delegation`]: the builder was given the
    /// capability as a `C`, so the vocabulary invariant holds by
    /// construction. Use [`Delegation::into_opaque`] (or
    /// `.into()`) where the untyped form is wanted.
    pub fn sign(self, valid_until: Expires) -> Delegation<C> {
        let payload = Payload {
            issuer: self.issuer.verifying_key(),
            audience: self.audience,
            capability_origin: self.capability_origin,
            valid_until,
            capability: self.capability,
        };
        let to_sign = postcard::to_extend(&payload, DST.to_vec()).expect("vec");
        let signature = self.issuer.sign(&to_sign);
        Delegation::new(OpaqueDelegation(Signed { payload, signature }))
    }
}

/// A delegation in the vocabulary `C`: the capability bytes are
/// guaranteed to parse as a canonical `C` encoding.
///
/// This adds type safety at the edges — most usefully in message
/// schemas: a field of this type states the protocol's vocabulary, and
/// deserialization validates it, so a foreign vocabulary token is a
/// malformed message at the protocol boundary instead of a deny inside
/// the authorizer. The serde and wire forms are identical to
/// [`OpaqueDelegation`]'s.
///
/// Produced by the builders (where the invariant holds by construction)
/// or by fallible conversion from an [`OpaqueDelegation`]; convert back with
/// [`Self::into_opaque`] or `From`. Deliberately no `Deref`: this
/// is a refinement, not a smart pointer.
pub struct Delegation<C> {
    opaque: OpaqueDelegation,
    _marker: std::marker::PhantomData<C>,
}

impl<C> AsRef<OpaqueDelegation> for Delegation<C> {
    fn as_ref(&self) -> &OpaqueDelegation {
        self.opaque()
    }
}

impl<C> Delegation<C> {
    /// The vocabulary invariant is the caller's responsibility.
    fn new(opaque: OpaqueDelegation) -> Self {
        Self {
            opaque,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn opaque(&self) -> &OpaqueDelegation {
        &self.opaque
    }

    pub fn into_opaque(self) -> OpaqueDelegation {
        self.opaque
    }

    // The envelope accessors of [`OpaqueDelegation`], duplicated so typical
    // code never has to go through `opaque()`. Deliberately no
    // `Deref` -- this is a refinement, not a smart pointer.

    pub fn payload(&self) -> &Payload {
        self.opaque.payload()
    }

    pub fn signature(&self) -> &Signature {
        self.opaque.signature()
    }

    pub fn issuer(&self) -> &VerifyingKey {
        self.opaque.issuer()
    }

    pub fn audience(&self) -> &VerifyingKey {
        self.opaque.audience()
    }

    pub fn capability_origin(&self) -> &CapabilityOrigin {
        self.opaque.capability_origin()
    }

    pub fn capability_issuer(&self) -> &VerifyingKey {
        self.opaque.capability_issuer()
    }

    pub fn expires(&self) -> &Expires {
        self.opaque.expires()
    }

    /// Encode in the versioned wire form. See [`OpaqueDelegation::encode`].
    pub fn encode(&self) -> Vec<u8> {
        self.opaque.encode()
    }
}

impl<C: Serialize + DeserializeOwned> Delegation<C> {
    /// The capability. Infallible: the type's invariant guarantees the
    /// bytes parse.
    pub fn capability(&self) -> C {
        postcard::from_bytes(self.opaque.capability()).expect("invariant: capability parses as C")
    }

    /// Decode a v2 token in the vocabulary `C`.
    ///
    /// The capability bytes must parse as `C`, consumed exactly, and the
    /// framing must be canonical. Use
    /// [`into_opaque`](Self::into_opaque) where the untyped form is
    /// wanted; [`OpaqueDelegation::decode`] decodes without a vocabulary.
    /// v1 tokens are rejected ([`DecodeError::UnsupportedV1`]); read them
    /// with rcan 0.4.x.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let delegation = OpaqueDelegation::decode(bytes)?;
        Delegation::<C>::try_from(delegation)
    }

    /// Decode the canonical string form, in the vocabulary `C`.
    pub fn decode_string(s: &str) -> Result<Self, DecodeError> {
        Self::decode(&base32_bytes(s)?)
    }
}

/// Fails if the capability bytes are not a canonical `C` encoding.
impl<C: Serialize + DeserializeOwned> TryFrom<OpaqueDelegation> for Delegation<C> {
    type Error = DecodeError;

    fn try_from(delegation: OpaqueDelegation) -> Result<Self, DecodeError> {
        match postcard::take_from_bytes::<C>(delegation.capability()) {
            Ok((_, [])) => Ok(Self::new(delegation)),
            _ => Err(e!(DecodeError::ForeignVocabulary)),
        }
    }
}

/// Reflexive, so that `&OpaqueDelegation` satisfies `AsRef<OpaqueDelegation>`
/// bounds alongside [`Delegation`] (std has no blanket reflexive
/// `AsRef`).
impl AsRef<OpaqueDelegation> for OpaqueDelegation {
    fn as_ref(&self) -> &OpaqueDelegation {
        self
    }
}

impl<C> From<Delegation<C>> for OpaqueDelegation {
    fn from(typed: Delegation<C>) -> Self {
        typed.opaque
    }
}

impl<C> std::fmt::Debug for Delegation<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.opaque.fmt(f)
    }
}

impl<C> Clone for Delegation<C> {
    fn clone(&self) -> Self {
        Self::new(self.opaque.clone())
    }
}

impl<C> PartialEq for Delegation<C> {
    fn eq(&self, other: &Self) -> bool {
        self.opaque == other.opaque
    }
}

impl<C> Eq for Delegation<C> {}

impl<C> Serialize for Delegation<C> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.opaque.serialize(serializer)
    }
}

impl<'de, C: Serialize + DeserializeOwned> Deserialize<'de> for Delegation<C> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let opaque = OpaqueDelegation::deserialize(deserializer)?;
        Self::try_from(opaque).map_err(D::Error::custom)
    }
}

impl OpaqueDelegation {
    /// Encode into the canonical string form: lowercase base32 (no
    /// padding) of the wire form ([`Self::encode`]) — the iroh-ticket
    /// style, one opaque string instead of a per-field structure. This
    /// is what serde emits for human-readable formats (JSON, RON, TOML,
    /// ...).
    pub fn encode_string(&self) -> String {
        let mut out = data_encoding::BASE32_NOPAD.encode(&self.encode());
        out.make_ascii_lowercase();
        out
    }

    /// Decode the canonical string form of [`Self::encode_string`]. A
    /// successful decode is signature checked. Like [`Self::decode`], v1
    /// tokens are rejected; read them with rcan 0.4.x.
    pub fn decode_string(s: &str) -> Result<Self, DecodeError> {
        Self::decode(&base32_bytes(s)?)
    }
}

impl Serialize for OpaqueDelegation {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.encode_string())
        } else {
            self.encode().serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for OpaqueDelegation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Self::decode_string(&s).map_err(D::Error::custom)
        } else {
            let v = Vec::<u8>::deserialize(deserializer)?;
            Self::decode(&v).map_err(D::Error::custom)
        }
    }
}

/// The standard capability judgement: the link's capability bytes must
/// parse as a canonical `C` encoding, consumed exactly, and permit the
/// invoked capability; anything else is a deny.
fn capability_predicate<C: Capability, T: AsRef<OpaqueDelegation>>(
    capability: C,
) -> impl Fn(&T) -> bool {
    move |proof| match postcard::take_from_bytes::<C>(proof.as_ref().capability()) {
        Ok((granted, [])) => granted.permits(&capability),
        _ => false,
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

// The Err path of an auth check is cold; the keys in the error are
// worth more than a small Result.
#[allow(clippy::result_large_err)]
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
    pub fn check_opaque_invocation_from<C: Capability>(
        &self,
        invoker: VerifyingKey,
        capability: C,
        proof_chain: &[&OpaqueDelegation],
    ) -> Result<(), InvocationError> {
        self.check_opaque_invocation_from_at(SystemTime::now(), invoker, capability, proof_chain)
    }

    /// [`Self::check_opaque_invocation_from`] with an explicit clock.
    pub fn check_opaque_invocation_from_at<C: Capability>(
        &self,
        now: SystemTime,
        invoker: VerifyingKey,
        capability: C,
        proof_chain: &[&OpaqueDelegation],
    ) -> Result<(), InvocationError> {
        self.check_invocation_impl(now, invoker, capability_predicate(capability), proof_chain)
    }

    /// [`Self::check_opaque_invocation_from`] for a typed proof chain: the
    /// chain's vocabulary and the invoked capability are locked to the
    /// same `C`, so a vocabulary mismatch is unrepresentable. To check a
    /// typed chain against a different vocabulary, go via the untyped
    /// form with [`Delegation::opaque`].
    pub fn check_invocation_from<C: Capability>(
        &self,
        invoker: VerifyingKey,
        capability: C,
        proof_chain: &[&Delegation<C>],
    ) -> Result<(), InvocationError> {
        self.check_invocation_from_at(SystemTime::now(), invoker, capability, proof_chain)
    }

    /// [`Self::check_invocation_from`] with an explicit clock.
    pub fn check_invocation_from_at<C: Capability>(
        &self,
        now: SystemTime,
        invoker: VerifyingKey,
        capability: C,
        proof_chain: &[&Delegation<C>],
    ) -> Result<(), InvocationError> {
        self.check_invocation_impl(now, invoker, capability_predicate(capability), proof_chain)
    }

    /// The shared chain walk, generic over anything that views as a
    /// [`OpaqueDelegation`] and over how a link's capability is judged. The
    /// capability semantics live entirely in the `permitted` predicate,
    /// so the walk itself needs no capability type — a caller may pass
    /// `|_| true` to check only the envelope structure of a chain.
    fn check_invocation_impl<T: AsRef<OpaqueDelegation>>(
        &self,
        now: SystemTime,
        invoker: VerifyingKey,
        permitted: impl Fn(&T) -> bool,
        proof_chain: &[T],
    ) -> Result<(), InvocationError> {
        // We require that proof chains are provided "back-to-front".
        // So they start with the owner of the capability, then
        // proceed with the next item in the chain.
        let mut current_issuer_target = &self.identity;
        for original in proof_chain {
            let proof = original.as_ref();
            // Verify proof chain issuer/audience integrity:
            let issuer = proof.issuer();
            if issuer != current_issuer_target {
                return Err(e!(InvocationError::ChainBroken {
                    expected: *current_issuer_target,
                    found: *issuer,
                }));
            }

            // Verify each proof's time validity:
            let expiry = proof.expires();
            if !expiry.is_valid_at(now) {
                return Err(e!(InvocationError::Expired {
                    expiry: expiry.clone(),
                }));
            }

            // Verify that the capability is actually reached through:
            if proof.capability_issuer() != &self.identity {
                return Err(e!(InvocationError::WrongCapabilityIssuer {
                    authorizer: self.identity,
                }));
            }

            // Verify that the capability doesn't break out of capabilities:
            if !permitted(original) {
                return Err(e!(InvocationError::NotPermitted));
            }

            // Continue checking the proof chain's integrity with this
            // delegation's audience as the next issuer target:
            current_issuer_target = proof.audience();
        }

        if &invoker != current_issuer_target {
            return Err(e!(InvocationError::WrongInvoker {
                invoker,
                chain_end: *current_issuer_target,
            }));
        }

        Ok(())
    }
}

/// Stable serde for [`VerifyingKey`]: 32 raw bytes, no length prefix —
/// the length is fixed. Pins the wire format independent of
/// [`ed25519_dalek`]'s own serde impl. Binary only: human-readable
/// formats never see the fields, they get the one canonical string of
/// [`OpaqueDelegation::encode_string`] instead.
pub(crate) mod verifying_key_serde {
    use ed25519_dalek::VerifyingKey;
    use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(key: &VerifyingKey, serializer: S) -> Result<S::Ok, S::Error> {
        key.as_bytes().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<VerifyingKey, D::Error> {
        let buf = <[u8; 32]>::deserialize(deserializer)?;
        VerifyingKey::from_bytes(&buf).map_err(D::Error::custom)
    }
}

/// Decode the lowercase-base32 (no padding) body of a string form.
fn base32_bytes(s: &str) -> Result<Vec<u8>, DecodeError> {
    data_encoding::BASE32_NOPAD
        .decode(s.to_ascii_uppercase().as_bytes())
        .map_err(DecodeError::malformed)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SIGNATURE_LENGTH;

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

    #[test]
    fn v2_roundtrip() {
        let issuer = key(0);
        let audience = key(1).verifying_key();
        let delegation: OpaqueDelegation =
            Delegation::issuing_builder(&issuer, audience, &Rpc::ReadWrite)
                .sign(Expires::Never)
                .into();

        let bytes = delegation.encode();
        assert_eq!(bytes[0], 2);
        let decoded = OpaqueDelegation::decode(&bytes).unwrap();
        assert_eq!(decoded, delegation);
        // The typed decode handles v2 too, additionally validating the vocabulary.
        let decoded = Delegation::<Rpc>::decode(&bytes).unwrap();
        assert_eq!(decoded.into_opaque(), delegation);

        assert_eq!(delegation.issuer(), &issuer.verifying_key());
        assert_eq!(delegation.audience(), &audience);
        assert_eq!(delegation.expires(), &Expires::Never);
        assert_eq!(delegation.capability_issuer(), &issuer.verifying_key());
        assert_eq!(delegation.capability(), &[1]);

        // The binary serde form wraps the wire form (encode()) as a
        // byte string: the wire bytes behind a postcard length prefix.
        let wire = postcard::to_stdvec(&delegation).unwrap();
        assert!(wire.ends_with(&bytes));
        let deserialized: OpaqueDelegation = postcard::from_bytes(&wire).unwrap();
        assert_eq!(deserialized, delegation);
    }

    #[test]
    fn v2_decode_rejects_tampering() {
        let issuer = key(0);
        let audience = key(1).verifying_key();
        let delegation: OpaqueDelegation =
            Delegation::issuing_builder(&issuer, audience, &Rpc::Read)
                .sign(Expires::Never)
                .into();
        let good = delegation.encode();

        // Zeroed signature.
        let mut forged = good.clone();
        let n = forged.len();
        forged[n - SIGNATURE_LENGTH..].fill(0);
        assert!(OpaqueDelegation::decode(&forged).is_err());

        // Capability widened Read -> All, signature kept. Offset:
        // version, issuer, audience, origin tag, expires tag,
        // capability length prefix - then the capability byte.
        let mut widened = good.clone();
        let capability_offset = 1 + 32 + 32 + 1 + 1 + 1;
        assert_eq!(widened[capability_offset - 1], 1); // length prefix
        assert_eq!(widened[capability_offset], 0); // Rpc::Read
        widened[capability_offset] = 2; // Rpc::All
        assert!(OpaqueDelegation::decode(&widened).is_err());

        // Trailing garbage between payload and signature.
        let mut padded = good.clone();
        let signature_start = padded.len() - SIGNATURE_LENGTH;
        padded.insert(signature_start, 0);
        assert!(OpaqueDelegation::decode(&padded).is_err());

        // Unknown version.
        let mut versioned = good.clone();
        versioned[0] = 3;
        assert!(OpaqueDelegation::decode(&versioned).is_err());

        assert!(OpaqueDelegation::decode(&[]).is_err());
    }

    #[test]
    fn two_link_chain_invocation() {
        let service = key(0);
        let alice = key(1);
        let bob = key(2);

        // The service grants alice everything, expiring at a fixed time...
        let root: OpaqueDelegation =
            Delegation::issuing_builder(&service, alice.verifying_key(), &Rpc::All)
                .sign(Expires::At(4_102_444_800))
                .into();

        // ...and alice delegates Read onward to bob.
        let link: OpaqueDelegation = Delegation::delegating_builder(
            &alice,
            bob.verifying_key(),
            service.verifying_key(),
            &Rpc::Read,
        )
        .sign(Expires::Never)
        .into();

        let authorizer = Authorizer::new(service.verifying_key());
        let chain = [&root, &link];
        // Within the root grant's validity.
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

        authorizer
            .check_opaque_invocation_from_at(now, bob.verifying_key(), Rpc::Read, &chain)
            .unwrap();
        assert!(authorizer
            .check_opaque_invocation_from_at(now, bob.verifying_key(), Rpc::ReadWrite, &chain)
            .is_err());
        assert!(authorizer
            .check_opaque_invocation_from_at(now, key(3).verifying_key(), Rpc::Read, &chain)
            .is_err());
        // After the root grant's expiry, the chain is dead.
        let late = SystemTime::UNIX_EPOCH + Duration::from_secs(4_102_444_801);
        assert!(authorizer
            .check_opaque_invocation_from_at(late, bob.verifying_key(), Rpc::Read, &chain)
            .is_err());
    }

    #[test]
    fn chain_must_start_at_the_authorizer() {
        let service = key(0);
        let alice = key(1);
        let bob = key(2);

        let alice_grant: OpaqueDelegation =
            Delegation::issuing_builder(&alice, bob.verifying_key(), &Rpc::All)
                .sign(Expires::Never)
                .into();
        let authorizer = Authorizer::new(service.verifying_key());
        assert!(authorizer
            .check_opaque_invocation_from(bob.verifying_key(), Rpc::Read, &[&alice_grant])
            .is_err());
    }

    #[test]
    fn subject_must_be_the_authorizer() {
        let service = key(0);
        let other = key(1);
        let alice = key(2);

        // The service passes on authority rooted at some *other* key; a
        // chain of it proves nothing about the service's own resources.
        let delegation: OpaqueDelegation = Delegation::delegating_builder(
            &service,
            alice.verifying_key(),
            other.verifying_key(),
            &Rpc::All,
        )
        .sign(Expires::Never)
        .into();
        let authorizer = Authorizer::new(service.verifying_key());
        assert!(authorizer
            .check_opaque_invocation_from(alice.verifying_key(), Rpc::Read, &[&delegation])
            .is_err());
    }

    #[test]
    fn typed_delegation() {
        let issuer = key(0);
        let audience = key(1).verifying_key();

        // The builder produces a typed delegation; the capability is
        // recoverable without a Result.
        let typed =
            Delegation::issuing_builder(&issuer, audience, &Rpc::ReadWrite).sign(Expires::Never);
        assert_eq!(typed.capability(), Rpc::ReadWrite);

        // Downcast and checked upcast round trip.
        let untyped: OpaqueDelegation = typed.clone().into();
        let again = Delegation::<Rpc>::try_from(untyped.clone()).unwrap();
        assert_eq!(again, typed);

        // The upcast is checked: a foreign vocabulary is rejected.
        #[derive(Debug, Serialize, Deserialize)]
        struct OtherVocabulary {
            topic: String,
            write: bool,
        }
        assert!(Delegation::<OtherVocabulary>::try_from(untyped.clone()).is_err());

        // The serde form is identical to the untyped one...
        let wire = postcard::to_stdvec(&typed).unwrap();
        assert_eq!(wire, postcard::to_stdvec(&untyped).unwrap());

        // ...but deserialization validates the vocabulary: a schema
        // field of the right type accepts, of a foreign type rejects at
        // message decode time.
        let ok: Delegation<Rpc> = postcard::from_bytes(&wire).unwrap();
        assert_eq!(ok, typed);
        assert!(postcard::from_bytes::<Delegation<OtherVocabulary>>(&wire).is_err());

        // A typed chain checks against the same vocabulary, with the
        // chain and invoked capability locked together.
        let bob = key(2);
        let typed_link = Delegation::delegating_builder(
            &key(1),
            bob.verifying_key(),
            issuer.verifying_key(),
            &Rpc::Read,
        )
        .sign(Expires::Never);
        let root = Delegation::issuing_builder(&issuer, audience, &Rpc::All).sign(Expires::Never);
        let authorizer = Authorizer::new(issuer.verifying_key());
        authorizer
            .check_invocation_from(bob.verifying_key(), Rpc::Read, &[&root, &typed_link])
            .unwrap();
        assert!(authorizer
            .check_invocation_from(bob.verifying_key(), Rpc::ReadWrite, &[&root, &typed_link])
            .is_err());
    }

    #[test]
    fn owner_needs_no_chain() {
        let service = key(0);
        let authorizer = Authorizer::new(service.verifying_key());
        authorizer
            .check_opaque_invocation_from(service.verifying_key(), Rpc::All, &[])
            .unwrap();
        assert!(authorizer
            .check_opaque_invocation_from(key(1).verifying_key(), Rpc::Read, &[])
            .is_err());
    }
}
