use ed25519_dalek::{
    ed25519::signature::Signer, Signature, SigningKey, VerifyingKey, SIGNATURE_LENGTH,
};
use n0_error::{e, stack_error};
use n0_future::time::{Duration, SystemTime};
use postcard::take_from_bytes;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[cfg(test)]
mod tests;

/// Domain separation tag for rcan v2 signatures.
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
pub trait Capability: Serialize + DeserializeOwned {
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
    /// Make sure to verify that the `invoker` signed and authenticated the
    /// message containing the `capability`.
    pub fn check_invocation_from<C: Capability>(
        &self,
        invoker: VerifyingKey,
        capability: C,
        proof_chain: &[&Delegation<C>],
    ) -> Result<(), InvocationError> {
        self.check_invocation_from_at(SystemTime::now(), invoker, capability, proof_chain)
    }

    pub fn check_invocation_from_at<C: Capability>(
        &self,
        now: SystemTime,
        invoker: VerifyingKey,
        capability: C,
        proof_chain: &[&Delegation<C>],
    ) -> Result<(), InvocationError> {
        self.check_invocation_impl(now, invoker, capability_predicate(capability), proof_chain)
    }

    /// Verifies an opaque invocation of a capability owned by this authorizer,
    /// that may have been passed through delegations in a proof chain
    /// and was finally signed back to us from given `invoker`.
    ///
    /// Make sure to verify that the `invoker` signed and authenticated the
    /// message containing the `capability`.
    pub fn check_opaque_invocation_from<C: Capability>(
        &self,
        invoker: VerifyingKey,
        capability: C,
        proof_chain: &[&OpaqueDelegation],
    ) -> Result<(), InvocationError> {
        self.check_opaque_invocation_from_at(SystemTime::now(), invoker, capability, proof_chain)
    }

    pub fn check_opaque_invocation_from_at<C: Capability>(
        &self,
        now: SystemTime,
        invoker: VerifyingKey,
        capability: C,
        proof_chain: &[&OpaqueDelegation],
    ) -> Result<(), InvocationError> {
        self.check_invocation_impl(now, invoker, capability_predicate(capability), proof_chain)
    }

    /// Implementation of the invocation check, used by both typed and opaque variants.
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

/// Create a predicate to check a capability `C` against a delegation type `T`.
///
/// The predicate will return true if the capability bytes can be deserialized as `C`
/// with no trailing bytes, and the deserialized capability permits the given `capability`.
fn capability_predicate<C: Capability, T: AsRef<OpaqueDelegation>>(
    capability: C,
) -> impl Fn(&T) -> bool {
    move |proof| match postcard::take_from_bytes::<C>(proof.as_ref().capability()) {
        Ok((granted, [])) => granted.permits(&capability),
        _ => false,
    }
}

/// Combines a payload and its signature.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Signed {
    payload: Payload,
    signature: Signature,
}

/// A token for attenuated capability delegations.
///
/// An [`OpaqueDelegation`] is guaranteed to be a valid delegation with a valid
/// signature.
///
/// The opaque variant keeps the capability as a byte array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaqueDelegation(Signed);

impl OpaqueDelegation {
    /// Decodes a v2 delegation from bytes, verifying the signature and canonical encoding.
    ///
    /// Currently this is the only supported version.
    fn decode_v2(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (payload, signature) = read_signed::<Payload>(bytes)?;
        let to_verify = postcard::to_extend(&payload, DST.to_vec()).expect("payload serializes");
        if to_verify[DST.len()..] != bytes[..bytes.len() - SIGNATURE_LENGTH] {
            return Err(DecodeError::malformed("non canonical encoding of payload"));
        }
        payload
            .issuer
            .verify_strict(&to_verify, &signature)
            .map_err(|_| e!(DecodeError::InvalidSignature))?;
        Ok(Self(Signed { payload, signature }))
    }

    /// Decodes a delegation from bytes, verifying the signature and canonical encoding.
    ///
    /// `decode` will not work for v1 delegations. Attempting to decode a v1 delegation
    /// will return a [`DecodeError::UnsupportedV1`] error.
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

    /// Encodes the delegation into bytes, including the version byte.
    pub fn encode(&self) -> Vec<u8> {
        let mut res = postcard::to_extend(&self.0.payload, vec![2u8]).expect("payload serializes");
        res.extend_from_slice(&self.0.signature.to_bytes());
        res
    }

    /// Encodes the delegation into a base32 string of the byte encoding produced
    /// by [`Self::encode`].
    pub fn encode_string(&self) -> String {
        let mut out = data_encoding::BASE32_NOPAD.encode(&self.encode());
        out.make_ascii_lowercase();
        out
    }

    /// Decodes a delegation from a base32 string, verifying the signature and canonical encoding.
    pub fn decode_string(s: &str) -> Result<Self, DecodeError> {
        Self::decode(&base32_bytes(s)?)
    }

    /// The payload of the delegation.
    pub fn payload(&self) -> &Payload {
        &self.0.payload
    }

    /// The signature of the delegation.
    pub fn signature(&self) -> &Signature {
        &self.0.signature
    }

    /// The issuer of the delegation.
    pub fn issuer(&self) -> &VerifyingKey {
        self.payload().issuer()
    }

    /// The audience of the delegation.
    pub fn audience(&self) -> &VerifyingKey {
        self.payload().audience()
    }

    /// The origin of the capability in the delegation.
    pub fn capability_origin(&self) -> &CapabilityOrigin {
        self.payload().capability_origin()
    }

    /// The issuer of the capability in the delegation.
    pub fn capability_issuer(&self) -> &VerifyingKey {
        self.payload().capability_issuer()
    }

    /// The expiration of the delegation.
    pub fn expires(&self) -> &Expires {
        self.payload().expires()
    }

    /// The capability of the delegation, as a byte slice.
    pub fn capability(&self) -> &[u8] {
        self.payload().capability()
    }
}

/// A token for attenuated capability delegations.
///
/// An [`Delegation<C>`] is guaranteed to be a valid delegation with a valid
/// signature. Also it is guaranteed that the capability bytes can be
/// deserialized as `C` with no trailing bytes.
///
/// The capability is currently kept as a byte array, but that is an
/// implementation detail.
pub struct Delegation<C> {
    opaque: OpaqueDelegation,
    _marker: std::marker::PhantomData<C>,
}

impl<C> Delegation<C> {
    /// Constructs a new delegation from an opaque delegation.
    ///
    /// Callers must make sure that the capability bytes in the opaque delegation
    /// can be deserialized as `C` with no trailing bytes.
    fn new(opaque: OpaqueDelegation) -> Self {
        Self {
            opaque,
            _marker: std::marker::PhantomData,
        }
    }

    /// A reference to the underlying opaque delegation.
    pub fn opaque(&self) -> &OpaqueDelegation {
        &self.opaque
    }

    /// Consumes the delegation and returns the underlying opaque delegation.
    pub fn into_opaque(self) -> OpaqueDelegation {
        self.opaque
    }

    /// The payload of the delegation.
    pub fn payload(&self) -> &Payload {
        self.opaque.payload()
    }

    /// The signature of the delegation.
    pub fn signature(&self) -> &Signature {
        self.opaque.signature()
    }

    /// The issuer of the delegation.
    pub fn issuer(&self) -> &VerifyingKey {
        self.opaque.issuer()
    }

    /// The audience of the delegation.
    pub fn audience(&self) -> &VerifyingKey {
        self.opaque.audience()
    }

    /// The origin of the capability.
    pub fn capability_origin(&self) -> &CapabilityOrigin {
        self.opaque.capability_origin()
    }

    /// The issuer of the capability.
    pub fn capability_issuer(&self) -> &VerifyingKey {
        self.opaque.capability_issuer()
    }

    /// The expiration of the delegation.
    pub fn expires(&self) -> &Expires {
        self.opaque.expires()
    }

    /// Encodes the delegation into a blob according to the rcan v2 format, including the version byte.
    pub fn encode(&self) -> Vec<u8> {
        self.opaque.encode()
    }

    /// Encodes the delegation into a base32 string of the byte encoding produced
    /// by [`Self::encode`].
    pub fn encode_string(&self) -> String {
        self.opaque.encode_string()
    }
}

impl<C: Serialize + DeserializeOwned> Delegation<C> {
    /// The capability of the delegation, deserialized as `C`.
    ///
    /// Currently this produces a new capability instance on each call.
    pub fn capability(&self) -> C {
        postcard::from_bytes(self.opaque.capability()).expect("invariant: capability parses as C")
    }

    /// Decodes a delegation from bytes, verifying the signature and canonical encoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let delegation = OpaqueDelegation::decode(bytes)?;
        Delegation::<C>::try_from(delegation)
    }

    /// Decodes a delegation from a base32 string, verifying the signature and canonical encoding.
    pub fn decode_string(s: &str) -> Result<Self, DecodeError> {
        Self::decode(&base32_bytes(s)?)
    }
}

/// Converts an opaque delegation into a typed delegation, verifying that the capability
/// bytes can be deserialized as `C` with no trailing bytes.
impl<C: Serialize + DeserializeOwned> TryFrom<OpaqueDelegation> for Delegation<C> {
    type Error = DecodeError;

    fn try_from(delegation: OpaqueDelegation) -> Result<Self, DecodeError> {
        match postcard::take_from_bytes::<C>(delegation.capability()) {
            Ok((_, [])) => Ok(Self::new(delegation)),
            _ => Err(e!(DecodeError::WrongCapability)),
        }
    }
}

/// Converts a typed delegation into an opaque delegation.
impl<C> From<Delegation<C>> for OpaqueDelegation {
    fn from(typed: Delegation<C>) -> Self {
        typed.opaque
    }
}

/// Allows sharing the invocation check code between typed and opaque delegations.
impl<C> AsRef<OpaqueDelegation> for Delegation<C> {
    fn as_ref(&self) -> &OpaqueDelegation {
        self.opaque()
    }
}

/// Allows sharing the invocation check code between typed and opaque delegations.
impl AsRef<OpaqueDelegation> for OpaqueDelegation {
    fn as_ref(&self) -> &OpaqueDelegation {
        self
    }
}

impl<C> std::fmt::Debug for Delegation<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // this isn't nice, but not doing this would require a `C: Debug` bound.
        self.opaque.fmt(f)
    }
}

/// Manual instance due to the phantom type parameter `C`.
impl<C> Clone for Delegation<C> {
    fn clone(&self) -> Self {
        Self::new(self.opaque.clone())
    }
}

/// Manual instance due to the phantom type parameter `C`.
impl<C> PartialEq for Delegation<C> {
    fn eq(&self, other: &Self) -> bool {
        self.opaque == other.opaque
    }
}

/// Manual instance due to the phantom type parameter `C`.
impl<C> Eq for Delegation<C> {}

/// The payload of a delegation.
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
    #[debug("{}", hex::encode(capability))]
    capability: Vec<u8>,
}

impl Payload {
    /// The issuer of the delegation.
    pub fn issuer(&self) -> &VerifyingKey {
        &self.issuer
    }

    /// The audience of the delegation.
    pub fn audience(&self) -> &VerifyingKey {
        &self.audience
    }

    /// The origin of the capability.
    pub fn capability_origin(&self) -> &CapabilityOrigin {
        &self.capability_origin
    }

    /// The issuer of the capability.
    pub fn capability_issuer(&self) -> &VerifyingKey {
        match &self.capability_origin {
            CapabilityOrigin::Issuer => &self.issuer,
            CapabilityOrigin::Delegation(root) => root,
        }
    }

    /// When the delegation expires.
    pub fn expires(&self) -> &Expires {
        &self.valid_until
    }

    /// The capability of the delegation, as a byte slice.
    pub fn capability(&self) -> &[u8] {
        &self.capability
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
    /// Creates an `Expires` value that is valid for the given duration from now.
    pub fn valid_for(duration: Duration) -> Self {
        Self::At(
            (SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("now is after UNIX_EPOCH")
                + duration)
                .as_secs(),
        )
    }

    /// Checks if the `Expires` value is valid at the given `SystemTime`.
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

impl<C: Serialize> Delegation<C> {
    /// Creates a builder for issuing a new delegation where the issuer is the origin of the capability.
    pub fn issuing_builder<'s>(
        issuer: &'s SigningKey,
        audience: VerifyingKey,
        capability: &C,
    ) -> DelegationBuilder<'s, C> {
        DelegationBuilder {
            issuer,
            audience,
            capability_origin: CapabilityOrigin::Issuer,
            capability: postcard::to_stdvec(capability).expect("capability serializes"),
            capability_type: std::marker::PhantomData,
        }
    }

    /// Creates a builder for issuing a new delegation where the capability originates from another delegation.
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
            capability: postcard::to_stdvec(capability).expect("capability serializes"),
            capability_type: std::marker::PhantomData,
        }
    }
}

/// A builder for creating a delegation.
pub struct DelegationBuilder<'s, C> {
    issuer: &'s SigningKey,
    audience: VerifyingKey,
    capability_origin: CapabilityOrigin,
    capability: Vec<u8>,
    capability_type: std::marker::PhantomData<C>,
}

impl<C> DelegationBuilder<'_, C> {
    /// Signs the delegation with the given expiration time, returning a `Delegation<C>`.
    pub fn sign(self, valid_until: Expires) -> Delegation<C> {
        let payload = Payload {
            issuer: self.issuer.verifying_key(),
            audience: self.audience,
            capability_origin: self.capability_origin,
            valid_until,
            capability: self.capability,
        };
        let to_sign = postcard::to_extend(&payload, DST.to_vec()).expect("payload serializes");
        let signature = self.issuer.sign(&to_sign);
        Delegation::new(OpaqueDelegation(Signed { payload, signature }))
    }
}

/// Error types for decoding.
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum DecodeError {
    /// The input is malformed in some way, with a reason provided.
    #[error("malformed token: {reason}")]
    Malformed { reason: String },
    /// The input is a v1 token, which is not supported by this version of the library.
    #[error("v1 tokens are not supported, use rcan 0.4.x to read them")]
    UnsupportedV1,
    /// The signature on the token is invalid.
    #[error("signature verification failed")]
    InvalidSignature,
    /// The capability in the token does not parse as the expected capability type.
    #[error("capability does not parse as the expected capability type")]
    WrongCapability,
}

impl DecodeError {
    /// Helper to create a `DecodeError::Malformed` with a reason.
    fn malformed(reason: impl std::fmt::Display) -> Self {
        e!(DecodeError::Malformed {
            reason: reason.to_string()
        })
    }
}

/// Error types for invocation checks.
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum InvocationError {
    /// The proof chain is broken. The issuer of a delegation does not match the
    /// audience of the previous delegation in the chain.
    #[error(
        "expected proof to be issued by {}, but was issued by {}",
        hex::encode(expected),
        hex::encode(found)
    )]
    ChainBroken {
        expected: VerifyingKey,
        found: VerifyingKey,
    },
    /// The proof has expired.
    #[error("proof expired at {expiry}")]
    Expired { expiry: Expires },
    #[error(
        "proof is missing delegation for capability of {}",
        hex::encode(authorizer)
    )]
    /// A delegation in the proof chain does not have the correct capability issuer.
    WrongCapabilityIssuer { authorizer: VerifyingKey },
    /// The capability in the proof chain does not permit the requested capability.
    #[error("capability not permitted")]
    NotPermitted,
    #[error(
        "expected delegation chain to end in the connection's owner {}, but the connection is authenticated by {} instead",
        hex::encode(invoker),
        hex::encode(chain_end)
    )]
    /// The final audience in the proof chain does not match the invoker of the capability.
    WrongInvoker {
        invoker: VerifyingKey,
        chain_end: VerifyingKey,
    },
}

/// Forward all serialization of `OpaqueDelegation` to [`OpaqueDelegation::encode`].
impl Serialize for OpaqueDelegation {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.encode_string())
        } else {
            serializer.serialize_bytes(&self.encode())
        }
    }
}

/// Forward all deserialization of `OpaqueDelegation` to [`OpaqueDelegation::decode`].
impl<'de> Deserialize<'de> for OpaqueDelegation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Self::decode_string(&s).map_err(D::Error::custom)
        } else {
            let bytes = deserialize_byte_buf(deserializer)?;
            Self::decode(&bytes).map_err(D::Error::custom)
        }
    }
}

/// Deserialize an owned byte buffer without requiring `serde_bytes`.
fn deserialize_byte_buf<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    struct ByteBufVisitor;

    impl<'de> serde::de::Visitor<'de> for ByteBufVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a byte string")
        }

        fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
            Ok(bytes.to_vec())
        }

        fn visit_borrowed_bytes<E: serde::de::Error>(
            self,
            bytes: &'de [u8],
        ) -> Result<Self::Value, E> {
            Ok(bytes.to_vec())
        }

        fn visit_byte_buf<E: serde::de::Error>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
            Ok(bytes)
        }
    }

    deserializer.deserialize_byte_buf(ByteBufVisitor)
}

/// Forward all serialization of `Delegation<C>` to [`OpaqueDelegation`].
impl<C> Serialize for Delegation<C> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.opaque.serialize(serializer)
    }
}

/// Forward all deserialization of `Delegation<C>` to [`OpaqueDelegation`].
impl<'de, C: Serialize + DeserializeOwned> Deserialize<'de> for Delegation<C> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let opaque = OpaqueDelegation::deserialize(deserializer)?;
        Self::try_from(opaque).map_err(D::Error::custom)
    }
}

/// Custom serialization and deserialization for [`ed25519_dalek::VerifyingKey`]
/// via its byte representation.
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

/// Helper function to read a buffer as a type `T` and a 64 byte signature.
///
/// This does not check that the encoding was canonical and also does not check
/// the signature.
fn read_signed<T: DeserializeOwned>(bytes: &[u8]) -> Result<(T, Signature), DecodeError> {
    let (payload, signature) = take_from_bytes::<T>(bytes).map_err(DecodeError::malformed)?;
    let signature = Signature::from_bytes(
        signature
            .try_into()
            .map_err(|_| DecodeError::malformed("invalid signature length"))?,
    );
    Ok((payload, signature))
}

/// Decodes a string as case insensitive base32, returning the bytes.
///
/// If the string is not valid base32, returns a [`DecodeError::Malformed`] error.
fn base32_bytes(s: &str) -> Result<Vec<u8>, DecodeError> {
    data_encoding::BASE32_NOPAD
        .decode(s.to_ascii_uppercase().as_bytes())
        .map_err(DecodeError::malformed)
}
