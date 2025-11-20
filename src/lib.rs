use std::ops::Add;

// TODO: better error management
use anyhow::{bail, ensure, Context, Result};
use ed25519_dalek::{
    ed25519::signature::Signer, Signature, SigningKey, VerifyingKey, SIGNATURE_LENGTH,
};
use n0_future::time::{Duration, SystemTime};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub const VERSION: u8 = 1;

/// Domain separation tag
pub const DST: &[u8] = b"rcan-1-delegation";

/// A trait for types that define a capability.
///
/// Capabilities can be compared using [`Capability::permits`], which determines
/// whether one capability grants permission to perform another.
///
/// A common implementation of this trait might be an enum representing different
/// RPC request types.
///
/// The `Capability` type must be serializable so it can be included in the signature
/// payload in an [`Rcan`].
pub trait Capability: Serialize {
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
    // Might even make that `SigningKey` and allow it to `sign` rcans?
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
    /// Make sure to verify that the `invoker` signed and authenticated the
    /// message containing the `capability`.
    pub fn check_invocation_from<C: Capability>(
        &self,
        invoker: VerifyingKey,
        capability: C,
        proof_chain: &[&Rcan<C>],
    ) -> Result<()> {
        let now = SystemTime::now();
        // We require that proof chains are provided "back-to-front".
        // So they start with the owner of the capability, then
        // proceed with the next item in the chain.
        let mut current_issuer_target = &self.identity;
        for proof in proof_chain {
            // Verify proof chain issuer/audience integrity:
            let issuer = &proof.payload.issuer;
            let audience = &proof.payload.audience;
            ensure!(
                issuer == current_issuer_target,
                "invocation failed: expected proof to be issued by {}, but was issued by {}",
                hex::encode(current_issuer_target),
                hex::encode(issuer),
            );

            // Verify each proof's time validity:
            let expiry = &proof.payload.valid_until;
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

            // Verify that the capability doesn't break out of capabilitys:
            ensure!(
                proof.payload.capability().permits(&capability),
                "invocation failed"
            );

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
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Rcan<C> {
    /// The actual content.
    pub payload: Payload<C>,
    /// Signature over the serialized payload.
    pub signature: Signature,
}

#[derive(Clone, Serialize, Deserialize, derive_more::Debug, PartialEq, Eq)]
pub struct Payload<C> {
    /// The issuer
    #[debug("{}", hex::encode(issuer))]
    issuer: VerifyingKey,
    /// The intended audience
    #[debug("{}", hex::encode(audience))]
    audience: VerifyingKey,
    /// The origin of the capability
    capability_origin: CapabilityOrigin,
    /// The capability
    capability: C,
    /// Valid until unix timestamp in seconds.
    valid_until: Expires,
}

impl<C> Payload<C> {
    pub fn capability(&self) -> &C {
        &self.capability
    }

    pub fn capability_origin(&self) -> &CapabilityOrigin {
        &self.capability_origin
    }
}

/// The potential origins of a capability.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum CapabilityOrigin {
    /// The origin is the issuer itself
    Issuer,
    /// This is a delegation, with this key being the root of the delegation chain.
    Delegation(VerifyingKey),
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

pub struct RcanBuilder<'s, C> {
    issuer: &'s SigningKey,
    audience: VerifyingKey,
    capability_origin: CapabilityOrigin,
    capability: C,
}

impl<C> Rcan<C> {
    pub fn issuing_builder(
        issuer: &SigningKey,
        audience: VerifyingKey,
        capability: C,
    ) -> RcanBuilder<'_, C> {
        RcanBuilder {
            issuer,
            audience,
            capability_origin: CapabilityOrigin::Issuer,
            capability,
        }
    }

    pub fn delegating_builder(
        issuer: &SigningKey,
        audience: VerifyingKey,
        owner: VerifyingKey,
        capability: C,
    ) -> RcanBuilder<'_, C> {
        RcanBuilder {
            issuer,
            audience,
            capability_origin: CapabilityOrigin::Delegation(owner),
            capability,
        }
    }

    pub fn encode(&self) -> Vec<u8>
    where
        C: Serialize,
    {
        postcard::to_extend(self, vec![VERSION]).expect("vec")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self>
    where
        C: DeserializeOwned,
    {
        let Some(version) = bytes.first() else {
            bail!("cannot decode, token is empty");
        };
        ensure!(*version == VERSION, "invalid version: {}", version);
        let rcan: Self = postcard::from_bytes(&bytes[1..]).context("decoding")?;

        // Verify the signature
        let mut signed = DST.to_vec();
        signed.extend_from_slice(&bytes[1..bytes.len() - SIGNATURE_LENGTH]);
        rcan.payload
            .issuer
            .verify_strict(&signed, &rcan.signature)?;

        Ok(rcan)
    }

    pub fn audience(&self) -> &VerifyingKey {
        &self.payload.audience
    }

    pub fn issuer(&self) -> &VerifyingKey {
        &self.payload.issuer
    }

    pub fn capability(&self) -> &C {
        self.payload.capability()
    }

    pub fn capability_origin(&self) -> &CapabilityOrigin {
        self.payload.capability_origin()
    }

    pub fn capability_issuer(&self) -> &VerifyingKey {
        match self.payload.capability_origin() {
            CapabilityOrigin::Issuer => &self.payload.issuer,
            CapabilityOrigin::Delegation(ref root) => root,
        }
    }

    pub fn expires(&self) -> &Expires {
        &self.payload.valid_until
    }
}

impl<C> RcanBuilder<'_, C> {
    pub fn sign(self, valid_until: Expires) -> Rcan<C>
    where
        C: Serialize,
    {
        let payload = Payload {
            issuer: self.issuer.verifying_key(),
            audience: self.audience,
            capability_origin: self.capability_origin,
            capability: self.capability,
            valid_until,
        };

        let to_sign = postcard::to_extend(&payload, DST.to_vec()).expect("vec");
        let signature = self.issuer.sign(&to_sign);

        Rcan { signature, payload }
    }
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

#[cfg(test)]
mod test {
    use testresult::TestResult;

    use super::*;

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    enum Rpc {
        Read,
        ReadWrite,
        /// Read, ReadWrite, and any "future ones" that we might not have thought of yet.
        All,
    }

    impl Capability for Rpc {
        fn permits(&self, other: &Self) -> bool {
            match (self, other) {
                // `All` permits all RPC operations, by definition
                (Rpc::All, _) => true,
                // `ReadWrite` permits `Read` and `ReadWrite`, but not `All` (which may be extended later to include more caps)
                (Rpc::ReadWrite, Rpc::ReadWrite | Rpc::Read) => true,
                (Rpc::ReadWrite, _) => false,
                // `Read` only permits `Read`
                (Rpc::Read, Rpc::Read) => true,
                (Rpc::Read, _) => false,
            }
        }
    }

    #[test]
    fn test_simple_capabilitys() {
        assert!(Rpc::Read.permits(&Rpc::Read));
        assert!(Rpc::ReadWrite.permits(&Rpc::Read));
        assert!(Rpc::ReadWrite.permits(&Rpc::ReadWrite),);
        assert!(!Rpc::Read.permits(&Rpc::ReadWrite));
        assert!(!Rpc::Read.permits(&Rpc::All));
        assert!(Rpc::All.permits(&Rpc::All));
        assert!(Rpc::All.permits(&Rpc::Read));
        assert!(Rpc::All.permits(&Rpc::ReadWrite));
    }

    #[test]
    fn test_rcan_encoding() -> TestResult {
        let issuer = SigningKey::from_bytes(&[0u8; 32]);
        let audience = SigningKey::from_bytes(&[1u8; 32]);
        let rcan = Rcan::issuing_builder(&issuer, audience.verifying_key(), Rpc::ReadWrite)
            .sign(Expires::Never);

        println!("{}", hex::encode(rcan.encode()));

        let expected: String = [
            // Version
            "01",
            // Issuer
            "203b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
            // Audience
            "208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
            // Capability Origin: Issuer
            "00",
            // capability: Rpc::ReadWrite
            "01",
            // Expires::Never
            "00",
            // Signature
            "54675ed0b6ba3a830fe24ec8523f776fa43001edfe4cc9e3bd639009a2058b1805de5e05958b46c03b423ed5d1c72acaab48a9f3bf8db2402c82295f085df404",
        ]
        .join("");

        assert_eq!(hex::encode(rcan.encode()), expected);
        assert_eq!(Rcan::decode(&rcan.encode())?, rcan);
        Ok(())
    }

    #[test]
    fn test_rcan_invocation() -> TestResult {
        let service = SigningKey::from_bytes(&[0u8; 32]);
        let alice = SigningKey::from_bytes(&[1u8; 32]);
        let bob = SigningKey::from_bytes(&[2u8; 32]);

        // The service gives alice access to everything for 60 seconds
        let service_rcan = Rcan::issuing_builder(&service, alice.verifying_key(), Rpc::All)
            .sign(Expires::valid_for(Duration::from_secs(60)));
        // alice gives attenuated (only read access) to bob, but doesn't care for how long still
        let friend_rcan = Rcan::delegating_builder(
            &alice,
            bob.verifying_key(),
            service.verifying_key(),
            Rpc::Read,
        )
        .sign(Expires::Never);
        // bob can now pass the authorization test for the service
        let service_auth = Authorizer::new(service.verifying_key());
        assert!(service_auth
            .check_invocation_from(
                bob.verifying_key(),
                Rpc::Read,
                &[&service_rcan, &friend_rcan],
            )
            .is_ok());

        // but bob doesn't have read-write access
        assert!(service_auth
            .check_invocation_from(
                bob.verifying_key(),
                Rpc::ReadWrite,
                &[&service_rcan, &friend_rcan]
            )
            .is_err());

        Ok(())
    }

    #[test]
    fn test_expiry() {
        let issuer = SigningKey::from_bytes(&[0u8; 32]);
        let audience = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        let rcan = Rcan::issuing_builder(&issuer, audience, Rpc::All)
            .sign(Expires::valid_for(Duration::from_secs(60)));
        assert!(rcan.expires().is_valid_at(SystemTime::UNIX_EPOCH));
        let now = SystemTime::now();
        assert!(rcan.expires().is_valid_at(now));
        let future = now + Duration::from_secs(61);
        assert!(!rcan.expires().is_valid_at(future));
    }
}
