use std::fmt;
use std::ops::Add;

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

/// Extension of [`Capability`] for types that support the full grant verification API.
///
/// Implementors get access to the [`Verifier`] builder on [`Rcan`] for structured,
/// typed verification of grants.
pub trait GrantCapability: Capability + DeserializeOwned + Clone + fmt::Debug {}

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

/// A bundle of capabilities that permits if any member permits.
///
/// Useful for defining composite capability labels like "client" that map to
/// a specific set of individual capabilities.
///
/// **Warning:** A bundle must not contain a variant that delegates back to the
/// bundle itself, or [`CapBundle::permits`] will recurse infinitely.
#[derive(Clone, Debug)]
pub struct CapBundle<C>(Vec<C>);

impl<C: Capability> CapBundle<C> {
    /// Create a new capability bundle from the given members.
    pub fn new(members: Vec<C>) -> Self {
        Self(members)
    }

    /// Returns `true` if any member of this bundle permits `other`.
    pub fn permits(&self, other: &C) -> bool {
        self.0.iter().any(|m| m.permits(other))
    }

    /// Returns the members of this bundle.
    pub fn members(&self) -> &[C] {
        &self.0
    }
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

    /// Encode this token as a base32 (no-pad, lowercase) string.
    pub fn to_base32(&self) -> String
    where
        C: Serialize,
    {
        data_encoding::BASE32_NOPAD
            .encode(&self.encode())
            .to_ascii_lowercase()
    }

    /// Decode a token from a base32 (no-pad, case-insensitive) string.
    pub fn from_base32(s: &str) -> Result<Self>
    where
        C: DeserializeOwned,
    {
        let bytes = data_encoding::BASE32_NOPAD
            .decode(s.to_ascii_uppercase().as_bytes())
            .context("invalid base32")?;
        Self::decode(&bytes)
    }
}

/// A type-erased rcan that deserializes envelope fields but leaves the
/// capability payload as opaque bytes.
///
/// Intended for infrastructure that routes, stores, or relays grants without
/// needing to interpret the capability.
#[derive(Clone, Debug)]
pub struct RawRcan {
    /// The full encoded bytes (including version prefix), suitable for forwarding.
    encoded: Vec<u8>,
    /// The issuer's public key.
    pub issuer: VerifyingKey,
    /// The intended audience's public key.
    pub audience: VerifyingKey,
    /// The origin of the capability.
    pub capability_origin: CapabilityOrigin,
    /// The capability field, still encoded as postcard bytes.
    pub capability_bytes: Vec<u8>,
    /// When the grant expires.
    pub valid_until: Expires,
    /// The signature over the payload.
    pub signature: Signature,
}

impl RawRcan {
    /// Decode envelope fields and verify the signature.
    ///
    /// The capability bytes are retained verbatim for later type-specific
    /// decode via [`RawRcan::capability_as`] or pass-through forwarding.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let Some(version) = bytes.first() else {
            bail!("cannot decode, token is empty");
        };
        ensure!(*version == VERSION, "invalid version: {}", version);

        // The last SIGNATURE_LENGTH bytes are the signature
        let payload_bytes = &bytes[1..bytes.len() - SIGNATURE_LENGTH];
        let sig_bytes = &bytes[bytes.len() - SIGNATURE_LENGTH..];

        // Verify the signature over the payload
        let signature: Signature = postcard::from_bytes(sig_bytes).context("decoding signature")?;
        let mut signed = DST.to_vec();
        signed.extend_from_slice(payload_bytes);
        let (issuer, rest): (VerifyingKey, &[u8]) =
            postcard::take_from_bytes(payload_bytes).context("decoding issuer")?;
        issuer.verify_strict(&signed, &signature)?;

        // Decode fields one by one, tracking remaining bytes to find capability boundaries
        let (audience, rest): (VerifyingKey, &[u8]) =
            postcard::take_from_bytes(rest).context("decoding audience")?;
        let (capability_origin, rest): (CapabilityOrigin, &[u8]) =
            postcard::take_from_bytes(rest).context("decoding capability_origin")?;

        // Everything between here and valid_until is the capability.
        // Decode valid_until from the end of the payload to find the boundary.
        // We know valid_until is the last field before the signature.
        // Try decoding Expires from progressively earlier positions.
        let cap_and_expiry = rest;

        // Decode valid_until by trying from the end. Expires is either:
        //   0x00 (Never, 1 byte) or 0x01 + varint (At, 1 + varint bytes)
        // We can find it by decoding from each possible split point.
        let mut capability_bytes = None;
        let mut valid_until = None;
        for split in (0..cap_and_expiry.len()).rev() {
            if let Ok((expires, remaining)) =
                postcard::take_from_bytes::<Expires>(&cap_and_expiry[split..])
            {
                if remaining.is_empty() {
                    capability_bytes = Some(cap_and_expiry[..split].to_vec());
                    valid_until = Some(expires);
                    break;
                }
            }
        }

        let capability_bytes = capability_bytes.context("could not find capability boundary")?;
        let valid_until = valid_until.context("could not decode valid_until")?;

        Ok(Self {
            encoded: bytes.to_vec(),
            issuer,
            audience,
            capability_origin,
            capability_bytes,
            valid_until,
            signature,
        })
    }

    /// The full encoded bytes (including version prefix), suitable for forwarding.
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Attempt to decode the capability as a specific type.
    pub fn capability_as<C: DeserializeOwned>(&self) -> Result<C> {
        postcard::from_bytes(&self.capability_bytes).context("decoding capability")
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

/// Typed verification errors returned by [`Verifier::check`].
#[derive(Debug)]
#[non_exhaustive]
pub enum VerifyError {
    /// Grant expired before the verification time.
    Expired { expired_at: u64, checked_at: u64 },
    /// Grant's audience doesn't match the expected audience.
    AudienceMismatch {
        expected: VerifyingKey,
        actual: VerifyingKey,
    },
    /// Grant's issuer doesn't match the expected (pinned) issuer.
    IssuerMismatch {
        expected: VerifyingKey,
        actual: VerifyingKey,
    },
    /// The grant's capability does not permit the required capability.
    CapabilityInsufficient,
    /// The grant has been revoked.
    Revoked,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired {
                expired_at,
                checked_at,
            } => write!(f, "grant expired at {expired_at}, checked at {checked_at}"),
            Self::AudienceMismatch { expected, actual } => write!(
                f,
                "audience mismatch: expected {}, got {}",
                hex::encode(expected),
                hex::encode(actual),
            ),
            Self::IssuerMismatch { expected, actual } => write!(
                f,
                "issuer mismatch: expected {}, got {}",
                hex::encode(expected),
                hex::encode(actual),
            ),
            Self::CapabilityInsufficient => write!(f, "capability insufficient"),
            Self::Revoked => write!(f, "grant has been revoked"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// A trait for checking whether a grant has been revoked.
///
/// Implementations must be synchronous and non-blocking.
pub trait RevocationCheck: Send + Sync {
    /// Returns `true` if the grant (provided as its encoded bytes) has been revoked.
    fn is_revoked(&self, encoded: &[u8]) -> bool;
}

/// A default revocation set backed by a bloom filter and a `HashSet`.
///
/// The bloom filter acts as a cheap negative-check prefilter. On a positive
/// bloom hit, the authoritative `HashSet` is consulted.
///
/// Call [`RevocationSet::sweep`] periodically to evict expired entries.
/// Higher-level crates (e.g. `iroh-caps`) can wire this into a tokio interval.
pub struct RevocationSet {
    bloom: std::sync::RwLock<fastbloom::BloomFilter>,
    entries: std::sync::RwLock<std::collections::HashSet<Vec<u8>>>,
}

impl RevocationSet {
    /// Create a new, empty revocation set.
    ///
    /// `expected_items` is a hint for sizing the bloom filter. The false-positive
    /// rate is tuned to ~1% at the expected size.
    pub fn new(expected_items: usize) -> Self {
        let bloom = fastbloom::BloomFilter::with_false_pos(0.01).expected_items(expected_items);
        Self {
            bloom: std::sync::RwLock::new(bloom),
            entries: std::sync::RwLock::new(std::collections::HashSet::new()),
        }
    }

    /// Mark a grant as revoked.
    pub fn revoke(&self, encoded_grant: Vec<u8>) {
        self.bloom
            .write()
            .expect("bloom lock poisoned")
            .insert(&encoded_grant);
        self.entries
            .write()
            .expect("entries lock poisoned")
            .insert(encoded_grant);
    }

    /// Number of revoked entries currently tracked.
    pub fn len(&self) -> usize {
        self.entries.read().expect("entries lock poisoned").len()
    }

    /// Returns `true` if no entries are tracked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remove expired entries and rebuild the bloom filter.
    ///
    /// Decodes each entry to read `valid_until`, dropping any that have expired
    /// relative to the current time. The bloom filter is rebuilt from scratch
    /// after eviction.
    pub fn sweep(&self) {
        let now = SystemTime::now();
        let mut entries = self.entries.write().expect("entries lock poisoned");
        entries.retain(|encoded| {
            // Try to decode as RawRcan to check expiry. If decode fails,
            // keep the entry (don't silently drop undecodable revocations).
            match RawRcan::decode(encoded) {
                Ok(raw) => raw.valid_until.is_valid_at(now),
                Err(_) => true,
            }
        });

        // Rebuild bloom filter from surviving entries
        let mut new_bloom =
            fastbloom::BloomFilter::with_false_pos(0.01).expected_items(entries.len().max(1));
        for entry in entries.iter() {
            new_bloom.insert(entry);
        }
        *self.bloom.write().expect("bloom lock poisoned") = new_bloom;
    }
}

impl RevocationCheck for RevocationSet {
    fn is_revoked(&self, encoded: &[u8]) -> bool {
        if !self
            .bloom
            .read()
            .expect("bloom lock poisoned")
            .contains(encoded)
        {
            return false;
        }
        self.entries
            .read()
            .expect("entries lock poisoned")
            .contains(encoded)
    }
}

/// Builder for verifying an [`Rcan`] grant.
///
/// Constructed via [`Rcan::verifier`]. Configure checks with the builder methods,
/// then call [`Verifier::check`] to run all configured checks.
pub struct Verifier<'a, C> {
    rcan: &'a Rcan<C>,
    expected_audience: Option<&'a VerifyingKey>,
    expected_issuer: Option<&'a VerifyingKey>,
    required_capability: Option<&'a C>,
    now: Option<SystemTime>,
    revocation: Option<&'a dyn RevocationCheck>,
}

impl<'a, C: GrantCapability> Verifier<'a, C> {
    fn new(rcan: &'a Rcan<C>) -> Self {
        Self {
            rcan,
            expected_audience: None,
            expected_issuer: None,
            required_capability: None,
            now: None,
            revocation: None,
        }
    }

    /// Require the grant's audience to match this key.
    pub fn audience(mut self, expected: &'a VerifyingKey) -> Self {
        self.expected_audience = Some(expected);
        self
    }

    /// Require the grant to permit this capability.
    pub fn capability(mut self, required: &'a C) -> Self {
        self.required_capability = Some(required);
        self
    }

    /// Override the current-time check (defaults to [`SystemTime::now`]).
    pub fn now(mut self, time: SystemTime) -> Self {
        self.now = Some(time);
        self
    }

    /// Pin the grant's issuer.
    pub fn issuer(mut self, expected: &'a VerifyingKey) -> Self {
        self.expected_issuer = Some(expected);
        self
    }

    /// Check against a revocation source before accepting.
    pub fn revocation(mut self, check: &'a dyn RevocationCheck) -> Self {
        self.revocation = Some(check);
        self
    }

    /// Run all configured checks.
    pub fn check(&self) -> std::result::Result<(), Box<VerifyError>>
    where
        C: Serialize,
    {
        // Check issuer
        if let Some(expected) = self.expected_issuer {
            let actual = self.rcan.issuer();
            if actual != expected {
                return Err(Box::new(VerifyError::IssuerMismatch {
                    expected: *expected,
                    actual: *actual,
                }));
            }
        }

        // Check audience
        if let Some(expected) = self.expected_audience {
            let actual = self.rcan.audience();
            if actual != expected {
                return Err(Box::new(VerifyError::AudienceMismatch {
                    expected: *expected,
                    actual: *actual,
                }));
            }
        }

        // Check expiry
        let now = self.now.unwrap_or_else(SystemTime::now);
        if !self.rcan.expires().is_valid_at(now) {
            let checked_at = now
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("time must be after UNIX_EPOCH")
                .as_secs();
            let expired_at = match self.rcan.expires() {
                Expires::At(t) => *t,
                Expires::Never => unreachable!(),
            };
            return Err(Box::new(VerifyError::Expired {
                expired_at,
                checked_at,
            }));
        }

        // Check capability
        if let Some(required) = self.required_capability {
            if !self.rcan.capability().permits(required) {
                return Err(Box::new(VerifyError::CapabilityInsufficient));
            }
        }

        // Check revocation
        if let Some(revocation) = self.revocation {
            if revocation.is_revoked(&self.rcan.encode()) {
                return Err(Box::new(VerifyError::Revoked));
            }
        }

        Ok(())
    }
}

impl<C: GrantCapability> Rcan<C> {
    /// Create a [`Verifier`] builder for this grant.
    pub fn verifier(&self) -> Verifier<'_, C> {
        Verifier::new(self)
    }
}

#[cfg(test)]
mod test {
    use testresult::TestResult;

    use super::*;

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
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

    impl GrantCapability for Rpc {}

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

    #[test]
    fn test_verifier_happy_path() {
        let issuer = SigningKey::from_bytes(&[0u8; 32]);
        let audience = SigningKey::from_bytes(&[1u8; 32]);
        let rcan = Rcan::issuing_builder(&issuer, audience.verifying_key(), Rpc::ReadWrite)
            .sign(Expires::valid_for(Duration::from_secs(60)));

        let result = rcan
            .verifier()
            .issuer(&issuer.verifying_key())
            .audience(&audience.verifying_key())
            .capability(&Rpc::Read)
            .check();
        assert!(result.is_ok());
    }

    #[test]
    fn test_verifier_audience_mismatch() {
        let issuer = SigningKey::from_bytes(&[0u8; 32]);
        let audience = SigningKey::from_bytes(&[1u8; 32]);
        let wrong = SigningKey::from_bytes(&[2u8; 32]);
        let rcan = Rcan::issuing_builder(&issuer, audience.verifying_key(), Rpc::Read)
            .sign(Expires::Never);

        let result = rcan.verifier().audience(&wrong.verifying_key()).check();
        assert!(matches!(
            *result.unwrap_err(),
            VerifyError::AudienceMismatch { .. }
        ));
    }

    #[test]
    fn test_verifier_issuer_mismatch() {
        let issuer = SigningKey::from_bytes(&[0u8; 32]);
        let audience = SigningKey::from_bytes(&[1u8; 32]);
        let wrong = SigningKey::from_bytes(&[2u8; 32]);
        let rcan = Rcan::issuing_builder(&issuer, audience.verifying_key(), Rpc::Read)
            .sign(Expires::Never);

        let result = rcan.verifier().issuer(&wrong.verifying_key()).check();
        assert!(matches!(
            *result.unwrap_err(),
            VerifyError::IssuerMismatch { .. }
        ));
    }

    #[test]
    fn test_verifier_expired() {
        let issuer = SigningKey::from_bytes(&[0u8; 32]);
        let audience = SigningKey::from_bytes(&[1u8; 32]);
        let rcan = Rcan::issuing_builder(&issuer, audience.verifying_key(), Rpc::Read)
            .sign(Expires::At(1000));

        // Check at a time after expiry
        let after_expiry = SystemTime::UNIX_EPOCH + Duration::from_secs(2000);
        let result = rcan.verifier().now(after_expiry).check();
        assert!(matches!(
            *result.unwrap_err(),
            VerifyError::Expired {
                expired_at: 1000,
                checked_at: 2000,
            }
        ));
    }

    #[test]
    fn test_verifier_capability_insufficient() {
        let issuer = SigningKey::from_bytes(&[0u8; 32]);
        let audience = SigningKey::from_bytes(&[1u8; 32]);
        let rcan = Rcan::issuing_builder(&issuer, audience.verifying_key(), Rpc::Read)
            .sign(Expires::Never);

        // Read doesn't permit ReadWrite
        let result = rcan.verifier().capability(&Rpc::ReadWrite).check();
        assert!(matches!(
            *result.unwrap_err(),
            VerifyError::CapabilityInsufficient
        ));
    }

    #[test]
    fn test_verifier_revoked() {
        struct AlwaysRevoked;
        impl RevocationCheck for AlwaysRevoked {
            fn is_revoked(&self, _encoded: &[u8]) -> bool {
                true
            }
        }

        let issuer = SigningKey::from_bytes(&[0u8; 32]);
        let audience = SigningKey::from_bytes(&[1u8; 32]);
        let rcan = Rcan::issuing_builder(&issuer, audience.verifying_key(), Rpc::Read)
            .sign(Expires::Never);

        let result = rcan.verifier().revocation(&AlwaysRevoked).check();
        assert!(matches!(*result.unwrap_err(), VerifyError::Revoked));
    }

    #[test]
    fn test_revocation_set() {
        let issuer = SigningKey::from_bytes(&[0u8; 32]);
        let audience = SigningKey::from_bytes(&[1u8; 32]);
        let rcan = Rcan::issuing_builder(&issuer, audience.verifying_key(), Rpc::Read)
            .sign(Expires::Never);

        let revocations = RevocationSet::new(100);
        assert!(!revocations.is_revoked(&rcan.encode()));
        assert!(revocations.is_empty());

        revocations.revoke(rcan.encode());
        assert!(revocations.is_revoked(&rcan.encode()));
        assert_eq!(revocations.len(), 1);

        // A different grant should not be revoked
        let other =
            Rcan::issuing_builder(&issuer, audience.verifying_key(), Rpc::All).sign(Expires::Never);
        assert!(!revocations.is_revoked(&other.encode()));
    }

    #[test]
    fn test_revocation_set_sweep() {
        let issuer = SigningKey::from_bytes(&[0u8; 32]);
        let audience = SigningKey::from_bytes(&[1u8; 32]);

        // Create a grant that expired in the past
        let expired = Rcan::issuing_builder(&issuer, audience.verifying_key(), Rpc::Read)
            .sign(Expires::At(1));
        // Create a grant that never expires
        let forever =
            Rcan::issuing_builder(&issuer, audience.verifying_key(), Rpc::All).sign(Expires::Never);

        let revocations = RevocationSet::new(100);
        revocations.revoke(expired.encode());
        revocations.revoke(forever.encode());
        assert_eq!(revocations.len(), 2);

        // Sweep should remove the expired entry
        revocations.sweep();
        assert_eq!(revocations.len(), 1);
        assert!(!revocations.is_revoked(&expired.encode()));
        assert!(revocations.is_revoked(&forever.encode()));
    }

    #[test]
    fn test_base32_round_trip() -> TestResult {
        let issuer = SigningKey::from_bytes(&[0u8; 32]);
        let audience = SigningKey::from_bytes(&[1u8; 32]);
        let rcan = Rcan::issuing_builder(&issuer, audience.verifying_key(), Rpc::ReadWrite)
            .sign(Expires::Never);

        let s = rcan.to_base32();
        // Should be lowercase
        assert_eq!(s, s.to_ascii_lowercase());
        // Round-trip
        let decoded = Rcan::<Rpc>::from_base32(&s)?;
        assert_eq!(decoded, rcan);
        // Case-insensitive decode
        let decoded_upper = Rcan::<Rpc>::from_base32(&s.to_ascii_uppercase())?;
        assert_eq!(decoded_upper, rcan);

        Ok(())
    }

    #[test]
    fn test_cap_bundle() {
        let bundle = CapBundle::new(vec![Rpc::Read, Rpc::ReadWrite]);
        assert!(bundle.permits(&Rpc::Read));
        assert!(bundle.permits(&Rpc::ReadWrite));
        assert!(!bundle.permits(&Rpc::All));
        assert_eq!(bundle.members().len(), 2);
    }

    #[test]
    fn test_cap_bundle_empty() {
        let bundle: CapBundle<Rpc> = CapBundle::new(vec![]);
        assert!(!bundle.permits(&Rpc::Read));
        assert!(!bundle.permits(&Rpc::All));
        assert_eq!(bundle.members().len(), 0);
    }

    #[test]
    fn test_raw_rcan_decode() -> TestResult {
        let issuer = SigningKey::from_bytes(&[0u8; 32]);
        let audience = SigningKey::from_bytes(&[1u8; 32]);
        let rcan = Rcan::issuing_builder(&issuer, audience.verifying_key(), Rpc::ReadWrite)
            .sign(Expires::Never);

        let encoded = rcan.encode();
        let raw = RawRcan::decode(&encoded)?;

        assert_eq!(raw.issuer, issuer.verifying_key());
        assert_eq!(raw.audience, audience.verifying_key());
        assert_eq!(raw.capability_origin, CapabilityOrigin::Issuer);
        assert_eq!(raw.valid_until, Expires::Never);
        assert_eq!(raw.signature, rcan.signature);
        assert_eq!(raw.encoded(), &encoded);

        // Decode the capability from raw bytes
        let cap: Rpc = raw.capability_as()?;
        assert_eq!(cap, Rpc::ReadWrite);

        Ok(())
    }

    #[test]
    fn test_raw_rcan_with_expiry() -> TestResult {
        let issuer = SigningKey::from_bytes(&[0u8; 32]);
        let audience = SigningKey::from_bytes(&[1u8; 32]);
        let rcan = Rcan::issuing_builder(&issuer, audience.verifying_key(), Rpc::All)
            .sign(Expires::At(1234567890));

        let encoded = rcan.encode();
        let raw = RawRcan::decode(&encoded)?;

        assert_eq!(raw.valid_until, Expires::At(1234567890));
        let cap: Rpc = raw.capability_as()?;
        assert_eq!(cap, Rpc::All);

        Ok(())
    }

    #[test]
    fn test_raw_rcan_delegation() -> TestResult {
        let issuer = SigningKey::from_bytes(&[0u8; 32]);
        let audience = SigningKey::from_bytes(&[1u8; 32]);
        let owner = SigningKey::from_bytes(&[2u8; 32]);
        let rcan = Rcan::delegating_builder(
            &issuer,
            audience.verifying_key(),
            owner.verifying_key(),
            Rpc::Read,
        )
        .sign(Expires::Never);

        let encoded = rcan.encode();
        let raw = RawRcan::decode(&encoded)?;

        assert_eq!(
            raw.capability_origin,
            CapabilityOrigin::Delegation(owner.verifying_key())
        );
        let cap: Rpc = raw.capability_as()?;
        assert_eq!(cap, Rpc::Read);

        Ok(())
    }
}
