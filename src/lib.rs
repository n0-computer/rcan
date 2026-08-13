use ed25519_dalek::{
    ed25519::signature::Signer, Signature, SigningKey, VerifyingKey, SIGNATURE_LENGTH,
};
use n0_error::{e, stack_error};
use n0_future::time::{Duration, SystemTime};
use postcard::take_from_bytes;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Domain separation tag
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

#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum DecodeError {
    #[error("malformed token: {reason}")]
    Malformed { reason: String },
    #[error("v1 tokens are not supported, use rcan 0.4.x to read them")]
    UnsupportedV1,
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("capability does not parse in the vocabulary")]
    ForeignVocabulary,
}

impl DecodeError {
    fn malformed(reason: impl std::fmt::Display) -> Self {
        e!(DecodeError::Malformed {
            reason: reason.to_string()
        })
    }
}

#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum InvocationError {
    #[error(
        "expected proof to be issued by {}, but was issued by {}",
        hex::encode(expected),
        hex::encode(found)
    )]
    ChainBroken {
        expected: VerifyingKey,
        found: VerifyingKey,
    },
    #[error("proof expired at {expiry}")]
    Expired { expiry: Expires },
    #[error(
        "proof is missing delegation for capability of {}",
        hex::encode(authorizer)
    )]
    WrongCapabilityIssuer { authorizer: VerifyingKey },
    #[error("capability not permitted")]
    NotPermitted,
    #[error(
        "expected delegation chain to end in the connection's owner {}, but the connection is authenticated by {} instead",
        hex::encode(invoker),
        hex::encode(chain_end)
    )]
    WrongInvoker {
        invoker: VerifyingKey,
        chain_end: VerifyingKey,
    },
}

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

    pub fn capability(&self) -> &[u8] {
        &self.capability
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Signed {
    payload: Payload,
    signature: Signature,
}

/// A token for attenuated capability delegations
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

    pub fn capability(&self) -> &[u8] {
        self.payload().capability()
    }
}

impl<C> DelegationBuilder<'_, C> {
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

    pub fn encode(&self) -> Vec<u8> {
        self.opaque.encode()
    }
}

impl<C: Serialize + DeserializeOwned> Delegation<C> {
    pub fn capability(&self) -> C {
        postcard::from_bytes(self.opaque.capability()).expect("invariant: capability parses as C")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let delegation = OpaqueDelegation::decode(bytes)?;
        Delegation::<C>::try_from(delegation)
    }

    pub fn decode_string(s: &str) -> Result<Self, DecodeError> {
        Self::decode(&base32_bytes(s)?)
    }
}

impl<C: Serialize + DeserializeOwned> TryFrom<OpaqueDelegation> for Delegation<C> {
    type Error = DecodeError;

    fn try_from(delegation: OpaqueDelegation) -> Result<Self, DecodeError> {
        match postcard::take_from_bytes::<C>(delegation.capability()) {
            Ok((_, [])) => Ok(Self::new(delegation)),
            _ => Err(e!(DecodeError::ForeignVocabulary)),
        }
    }
}

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
    pub fn encode_string(&self) -> String {
        let mut out = data_encoding::BASE32_NOPAD.encode(&self.encode());
        out.make_ascii_lowercase();
        out
    }

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

            // Verify that the capability doesn't break out of capabilitys:
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
        let decoded = Delegation::<Rpc>::decode(&bytes).unwrap();
        assert_eq!(decoded.into_opaque(), delegation);

        assert_eq!(delegation.issuer(), &issuer.verifying_key());
        assert_eq!(delegation.audience(), &audience);
        assert_eq!(delegation.expires(), &Expires::Never);
        assert_eq!(delegation.capability_issuer(), &issuer.verifying_key());
        assert_eq!(delegation.capability(), &[1]);

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

        let mut forged = good.clone();
        let n = forged.len();
        forged[n - SIGNATURE_LENGTH..].fill(0);
        assert!(OpaqueDelegation::decode(&forged).is_err());

        let mut widened = good.clone();
        let capability_offset = 1 + 32 + 32 + 1 + 1 + 1;
        assert_eq!(widened[capability_offset - 1], 1);
        assert_eq!(widened[capability_offset], 0);
        widened[capability_offset] = 2;
        assert!(OpaqueDelegation::decode(&widened).is_err());

        let mut padded = good.clone();
        let signature_start = padded.len() - SIGNATURE_LENGTH;
        padded.insert(signature_start, 0);
        assert!(OpaqueDelegation::decode(&padded).is_err());

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

        let root: OpaqueDelegation =
            Delegation::issuing_builder(&service, alice.verifying_key(), &Rpc::All)
                .sign(Expires::At(4_102_444_800))
                .into();

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

        let typed =
            Delegation::issuing_builder(&issuer, audience, &Rpc::ReadWrite).sign(Expires::Never);
        assert_eq!(typed.capability(), Rpc::ReadWrite);

        let untyped: OpaqueDelegation = typed.clone().into();
        let again = Delegation::<Rpc>::try_from(untyped.clone()).unwrap();
        assert_eq!(again, typed);

        #[derive(Debug, Serialize, Deserialize)]
        struct OtherVocabulary {
            topic: String,
            write: bool,
        }
        assert!(Delegation::<OtherVocabulary>::try_from(untyped.clone()).is_err());

        let wire = postcard::to_stdvec(&typed).unwrap();
        assert_eq!(wire, postcard::to_stdvec(&untyped).unwrap());

        let ok: Delegation<Rpc> = postcard::from_bytes(&wire).unwrap();
        assert_eq!(ok, typed);
        assert!(postcard::from_bytes::<Delegation<OtherVocabulary>>(&wire).is_err());

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
