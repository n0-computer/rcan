//! RCAN primitives bound to authenticated iroh connections.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use ed25519_dalek::{Signature, SigningKey, VerifyingKey, ed25519::signature::Signer};
use iroh::EndpointId;
use n0_error::{e, stack_error};
use rcan::{CapabilityEncoding, CapabilityOrigin, Delegation};

pub mod fetch;
pub mod push;
pub mod renewal;

/// Maximum number of delegations in one proof chain.
pub const MAX_DELEGATION_CHAIN_DEPTH: usize = 8;

/// Maximum encoded size of one delegation.
pub const MAX_DELEGATION_BYTES: usize = 2 * 1024;

const DELEGATION_CHAIN_VERSION: u8 = 1;

/// Errors produced while checking a delegation chain.
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum ChainError {
    /// The chain contains no delegations.
    #[error("delegation chain is empty")]
    Empty,
    /// The chain contains more delegations than the protocol allows.
    #[error("delegation chain exceeds maximum depth of {max}")]
    TooDeep { max: usize },
    /// A delegation exceeds the protocol's size limit.
    #[error("delegation exceeds maximum size of {max} bytes")]
    DelegationTooLarge { max: usize },
    /// The encoded chain exceeds the protocol's size limit.
    #[error("delegation chain exceeds maximum encoded size of {max} bytes")]
    ChainTooLarge { max: usize },
    /// A postcard field cannot be decoded.
    #[error("invalid {field}")]
    InvalidPostcard {
        /// The field that failed to decode.
        field: &'static str,
        /// The postcard decoding error.
        #[error(std_err)]
        source: postcard::Error,
    },
    /// A delegation cannot be decoded.
    #[error("invalid delegation")]
    InvalidDelegation { source: rcan::DecodeError },
    /// A delegation uses an invalid capability representation.
    #[error("invalid delegation capability")]
    InvalidCapability { source: rcan::DecodeError },
    /// A delegation in the encoded chain cannot be decoded.
    #[error("invalid delegation in chain")]
    InvalidDelegationInChain { source: rcan::DecodeError },
    /// A chain ended before the advertised delegation bytes were available.
    #[error("delegation chain is truncated")]
    Truncated,
    /// The chain contains a non-canonical numeric field encoding.
    #[error("noncanonical {field}")]
    NonCanonical {
        /// The field with the non-canonical encoding.
        field: &'static str,
    },
    /// The encoded chain uses an unsupported version.
    #[error("unsupported delegation chain version {version}")]
    UnsupportedVersion { version: u8 },
    /// The encoded chain contains bytes after its final delegation.
    #[error("trailing bytes after delegation chain")]
    TrailingBytes,
    /// A delegation is issued by a principal other than the previous audience.
    #[error("delegation chain issuer does not match previous audience")]
    IssuerMismatch,
    /// A delegation changes the capability owner within the chain.
    #[error("delegation chain changes capability owner")]
    OwnerMismatch,
}

/// Errors produced while storing delegation evidence.
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum StoreError {
    /// A delegation exceeds the store's size limit.
    #[error("delegation exceeds maximum size of {max} bytes")]
    DelegationTooLarge { max: usize },
    /// A stored delegation cannot be decoded.
    #[error("invalid delegation")]
    InvalidDelegation { source: rcan::DecodeError },
    /// A stored revoked delegation cannot be decoded.
    #[error("invalid revoked delegation")]
    InvalidRevokedDelegation { source: rcan::DecodeError },
    /// A revocation signature is invalid.
    #[error("invalid revocation signature")]
    InvalidRevocationSignature {
        /// The signature verification error.
        #[error(std_err)]
        source: ed25519_dalek::SignatureError,
    },
}

/// Maximum encoded size of one delegation chain.
pub const MAX_DELEGATION_CHAIN_BYTES: usize = 1
    + postcard_u64_len(MAX_DELEGATION_CHAIN_DEPTH as u64)
    + MAX_DELEGATION_CHAIN_DEPTH
        * (postcard_u64_len(MAX_DELEGATION_BYTES as u64) + MAX_DELEGATION_BYTES);

const fn postcard_u64_len(mut value: u64) -> usize {
    let mut len = 1;
    while value >= 128 {
        value >>= 7;
        len += 1;
    }
    len
}

fn append_postcard_u64(output: &mut Vec<u8>, value: u64) {
    let mut buffer = [0; 10];
    let encoded = postcard::to_slice(&value, &mut buffer).expect("a u64 fits in ten bytes");
    output.extend_from_slice(encoded);
}

fn take_canonical_postcard_u64(
    input: &mut &[u8],
    field: &'static str,
) -> std::result::Result<u64, ChainError> {
    let original_len = input.len();
    let (value, remaining) = postcard::take_from_bytes::<u64>(input)
        .map_err(|source| e!(ChainError::InvalidPostcard { field }, source))?;
    let encoded_len = original_len - remaining.len();
    if encoded_len != postcard_u64_len(value) {
        return Err(e!(ChainError::NonCanonical { field }));
    }
    *input = remaining;
    Ok(value)
}

/// Canonical identity of one signed delegation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DelegationId([u8; 32]);

impl DelegationId {
    /// Derives the identity from a delegation's canonical encoding.
    pub fn new<C: CapabilityEncoding>(delegation: &Delegation<C>) -> Self {
        Self::from_encoded(&delegation.encode())
    }

    fn from_encoded(encoded: &[u8]) -> Self {
        Self(*blake3::hash(encoded).as_bytes())
    }
}

/// A signed statement permanently revoking one delegation.
///
/// This type belongs in `rcan` once the format and error vocabulary settle.
#[derive(Clone, Debug)]
pub struct Revocation {
    payload: RevocationPayload,
    signature: Signature,
}

#[derive(Clone, Debug)]
struct RevocationPayload {
    revoker: VerifyingKey,
    delegation: Delegation,
}

impl Revocation {
    /// Revokes `delegation` with `revoker`'s identity.
    ///
    /// Whether that identity has authority to revoke the delegation is chain-dependent and is
    /// checked by [`Store::check_revocations`].
    pub fn new(revoker: &SigningKey, delegation: Delegation) -> Self {
        let payload = RevocationPayload {
            revoker: revoker.verifying_key(),
            delegation,
        };
        let signature = revoker.sign(&payload.signed_bytes());
        Self { payload, signature }
    }

    /// Verifies the revocation signature.
    pub fn verify(&self) -> std::result::Result<(), ed25519_dalek::SignatureError> {
        self.payload
            .revoker
            .verify_strict(&self.payload.signed_bytes(), &self.signature)
    }

    /// The identity claiming revocation authority.
    pub fn revoker(&self) -> &VerifyingKey {
        &self.payload.revoker
    }

    /// The revoked delegation.
    pub fn delegation(&self) -> &Delegation {
        &self.payload.delegation
    }

    /// The revoker's signature.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }
}

impl RevocationPayload {
    fn signed_bytes(&self) -> Vec<u8> {
        let mut signed_bytes = b"rcan-2-revocation".to_vec();
        signed_bytes.extend_from_slice(self.revoker.as_bytes());
        signed_bytes.extend_from_slice(&self.delegation.encode());
        signed_bytes
    }
}

/// A proof chain contains a delegation revoked by one of its upstream issuers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revoked {
    delegation: DelegationId,
    revoker: [u8; 32],
}

impl Revoked {
    /// The revoked delegation's identifier.
    pub fn delegation(&self) -> DelegationId {
        self.delegation
    }

    /// The upstream issuer that revoked it.
    pub fn revoker(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(&self.revoker).expect("stored revoker is a verified key")
    }
}

impl std::fmt::Display for Revoked {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "delegation {:?} was revoked by {:?}",
            self.delegation, self.revoker
        )
    }
}

impl std::error::Error for Revoked {}

/// A checked root-to-leaf RCAN proof chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationChain<C = rcan::OpaqueCapability> {
    delegations: Vec<Delegation<C>>,
}

impl<C> DelegationChain<C>
where
    C: CapabilityEncoding,
{
    /// Checks and constructs a bounded proof chain.
    pub fn new(delegations: Vec<Delegation<C>>) -> std::result::Result<Self, ChainError> {
        if delegations.is_empty() {
            return Err(e!(ChainError::Empty));
        }
        if delegations.len() > MAX_DELEGATION_CHAIN_DEPTH {
            return Err(e!(ChainError::TooDeep {
                max: MAX_DELEGATION_CHAIN_DEPTH
            }));
        }

        let delegations = delegations
            .into_iter()
            .map(|delegation| {
                let encoded = delegation.encode();
                if encoded.len() > MAX_DELEGATION_BYTES {
                    return Err(e!(ChainError::DelegationTooLarge {
                        max: MAX_DELEGATION_BYTES
                    }));
                }
                let delegation: Delegation = Delegation::decode(&encoded)
                    .map_err(|source| e!(ChainError::InvalidDelegation, source))?;
                delegation
                    .try_with_capability_type::<C>()
                    .map_err(|source| e!(ChainError::InvalidCapability, source))
            })
            .collect::<std::result::Result<Vec<_>, ChainError>>()?;
        let first = delegations.first().expect("chain is nonempty");
        let owner = *first.capability_owner();
        let mut expected_issuer = owner;
        for delegation in &delegations {
            if delegation.issuer() != &expected_issuer {
                return Err(e!(ChainError::IssuerMismatch));
            }
            if delegation.capability_owner() != &owner {
                return Err(e!(ChainError::OwnerMismatch));
            }
            expected_issuer = *delegation.audience();
        }

        Ok(Self { delegations })
    }

    /// Encodes this chain in the canonical bounded v1 binary format.
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.push(DELEGATION_CHAIN_VERSION);
        append_postcard_u64(&mut encoded, self.delegations.len() as u64);
        for delegation in &self.delegations {
            let delegation = delegation.encode();
            debug_assert!(delegation.len() <= MAX_DELEGATION_BYTES);
            append_postcard_u64(&mut encoded, delegation.len() as u64);
            encoded.extend_from_slice(&delegation);
        }
        debug_assert!(encoded.len() <= MAX_DELEGATION_CHAIN_BYTES);
        encoded
    }

    /// Decodes and checks a canonical bounded v1 binary delegation chain.
    pub fn decode(encoded: &[u8]) -> std::result::Result<Self, ChainError> {
        if encoded.len() > MAX_DELEGATION_CHAIN_BYTES {
            return Err(e!(ChainError::ChainTooLarge {
                max: MAX_DELEGATION_CHAIN_BYTES
            }));
        }

        let Some((&version, mut remaining)) = encoded.split_first() else {
            return Err(e!(ChainError::Empty));
        };
        if version != DELEGATION_CHAIN_VERSION {
            return Err(e!(ChainError::UnsupportedVersion { version }));
        }

        let count = take_canonical_postcard_u64(&mut remaining, "delegation count")?;
        if count == 0 {
            return Err(e!(ChainError::Empty));
        }
        if count > MAX_DELEGATION_CHAIN_DEPTH as u64 {
            return Err(e!(ChainError::TooDeep {
                max: MAX_DELEGATION_CHAIN_DEPTH
            }));
        }
        let count = count as usize;
        let mut delegations = Vec::with_capacity(count);

        for _ in 0..count {
            let len = take_canonical_postcard_u64(&mut remaining, "delegation length")?;
            if len > MAX_DELEGATION_BYTES as u64 {
                return Err(e!(ChainError::DelegationTooLarge {
                    max: MAX_DELEGATION_BYTES
                }));
            }
            let len = len as usize;
            let (delegation, rest) = remaining
                .split_at_checked(len)
                .ok_or_else(|| e!(ChainError::Truncated))?;
            remaining = rest;
            delegations.push(
                Delegation::<C>::decode(delegation)
                    .map_err(|source| e!(ChainError::InvalidDelegationInChain, source))?,
            );
        }

        if !remaining.is_empty() {
            return Err(e!(ChainError::TrailingBytes));
        }
        Self::new(delegations)
    }
}

impl<C> DelegationChain<C> {
    /// Returns the root-to-leaf delegations.
    pub fn delegations(&self) -> &[Delegation<C>] {
        &self.delegations
    }
}

/// A deduplicated, vocabulary-agnostic set of signature-checked delegations.
#[derive(Clone, Debug, Default)]
pub struct Store {
    delegations: BTreeMap<DelegationId, Delegation>,
    revocations: BTreeMap<(DelegationId, [u8; 32]), Signature>,
}

impl Store {
    /// Signature-checks and inserts one opaque delegation, returning its ID.
    ///
    /// Inserting a delegation that is already present returns the existing ID.
    pub fn insert(
        &mut self,
        delegation: Delegation,
    ) -> std::result::Result<DelegationId, StoreError> {
        let encoded = delegation.encode();
        let id = DelegationId::from_encoded(&encoded);
        self.insert_encoded(encoded)?;
        Ok(id)
    }

    /// Decodes, signature-checks, and inserts one encoded v2 delegation.
    pub fn insert_encoded(&mut self, encoded: Vec<u8>) -> std::result::Result<bool, StoreError> {
        if encoded.len() > MAX_DELEGATION_BYTES {
            return Err(e!(StoreError::DelegationTooLarge {
                max: MAX_DELEGATION_BYTES
            }));
        }
        let id = DelegationId::from_encoded(&encoded);
        if self.delegations.contains_key(&id) {
            return Ok(false);
        }
        let delegation = Delegation::decode(&encoded)
            .map_err(|source| e!(StoreError::InvalidDelegation, source))?;
        self.delegations.insert(id, delegation);
        Ok(true)
    }

    /// Iterates over stored delegations in canonical encoded order.
    pub fn delegations(&self) -> impl Iterator<Item = &Delegation> {
        self.delegations.values()
    }

    /// Verifies and inserts a revocation, returning whether it was new.
    ///
    /// The target delegation need not already be known. Revocation authority remains
    /// chain-dependent and is checked by [`Self::check_revocations`].
    pub fn insert_revocation(
        &mut self,
        revocation: Revocation,
    ) -> std::result::Result<bool, StoreError> {
        let encoded = revocation.delegation().encode();
        if encoded.len() > MAX_DELEGATION_BYTES {
            return Err(e!(StoreError::DelegationTooLarge {
                max: MAX_DELEGATION_BYTES
            }));
        }
        let _: Delegation = Delegation::decode(&encoded)
            .map_err(|source| e!(StoreError::InvalidRevokedDelegation, source))?;
        revocation
            .verify()
            .map_err(|source| e!(StoreError::InvalidRevocationSignature, source))?;
        let Revocation { payload, signature } = revocation;
        let RevocationPayload {
            revoker,
            delegation: _,
        } = payload;
        let delegation_id = DelegationId::from_encoded(&encoded);
        Ok(self
            .revocations
            .insert((delegation_id, revoker.to_bytes()), signature)
            .is_none())
    }

    /// Checks that no delegation in `chain` was revoked by its issuer or an upstream issuer.
    pub fn check_revocations<C: CapabilityEncoding>(
        &self,
        chain: &DelegationChain<C>,
    ) -> std::result::Result<(), Revoked> {
        let mut upstream = Vec::new();
        for delegation in chain.delegations() {
            upstream.push(*delegation.issuer());
            let delegation_id = DelegationId::new(delegation);
            if let Some(revoker) = upstream.iter().find(|revoker| {
                self.revocations
                    .contains_key(&(delegation_id, revoker.to_bytes()))
            }) {
                return Err(Revoked {
                    delegation: delegation_id,
                    revoker: revoker.to_bytes(),
                });
            }
        }
        Ok(())
    }

    /// Whether `revoker` has signed a revocation for this exact delegation.
    pub fn is_revoked_by<C: CapabilityEncoding>(
        &self,
        delegation: &Delegation<C>,
        revoker: &VerifyingKey,
    ) -> bool {
        self.revocations
            .contains_key(&(DelegationId::new(delegation), revoker.to_bytes()))
    }

    /// Returns all reverse-reachable evidence that may contribute to `audience`.
    ///
    /// This includes incomplete chain suffixes. A receiver may already have the missing ancestors.
    pub fn relevant_delegations(&self, audience: VerifyingKey) -> Vec<Delegation> {
        let delegations = self.delegations.values().collect::<Vec<_>>();
        self.relevant_from(&delegations, audience)
    }

    /// Returns the latest reverse-reachable evidence that may contribute to `audience`.
    pub fn latest_relevant_delegations(&self, audience: VerifyingKey) -> Vec<Delegation> {
        self.relevant_from(&self.latest_delegations(), audience)
    }

    fn relevant_from(
        &self,
        delegations: &[&Delegation],
        audience: VerifyingKey,
    ) -> Vec<Delegation> {
        let mut pending = VecDeque::from([(audience.to_bytes(), None)]);
        let mut visited = BTreeSet::new();
        let mut selected = BTreeSet::new();
        while let Some((next_audience, owner)) = pending.pop_front() {
            if !visited.insert((next_audience, owner)) {
                continue;
            }
            for delegation in delegations {
                if delegation.audience().to_bytes() != next_audience
                    || owner.is_some_and(|owner| delegation.capability_owner().to_bytes() != owner)
                {
                    continue;
                }
                selected.insert(DelegationId::new(*delegation));
                if !matches!(delegation.capability_origin(), CapabilityOrigin::Issuer) {
                    pending.push_back((
                        delegation.issuer().to_bytes(),
                        Some(delegation.capability_owner().to_bytes()),
                    ));
                }
            }
        }
        self.delegations
            .iter()
            .filter(|(encoded, _)| selected.contains(*encoded))
            .map(|(_, delegation)| delegation.clone())
            .collect()
    }

    /// Finds structurally valid chains in vocabulary `C` ending at `audience`.
    ///
    /// Paths containing a delegation from another vocabulary are ignored.
    pub fn chains_for<C>(&self, audience: VerifyingKey) -> Vec<DelegationChain<C>>
    where
        C: CapabilityEncoding,
    {
        let delegations = self.delegations.values().collect::<Vec<_>>();
        self.chains_from(&delegations, audience)
    }

    /// Finds structurally valid chains using only the latest version of each logical delegation.
    pub fn latest_chains_for<C>(&self, audience: VerifyingKey) -> Vec<DelegationChain<C>>
    where
        C: CapabilityEncoding,
    {
        let latest = self.latest_delegations();
        self.chains_from(&latest, audience)
    }

    fn chains_from<C>(
        &self,
        delegations: &[&Delegation],
        audience: VerifyingKey,
    ) -> Vec<DelegationChain<C>>
    where
        C: CapabilityEncoding,
    {
        let mut chains = Vec::new();
        for root in delegations
            .iter()
            .copied()
            .filter(|delegation| matches!(delegation.capability_origin(), CapabilityOrigin::Issuer))
        {
            self.walk::<C>(
                delegations,
                *root.capability_owner(),
                audience,
                root,
                &mut vec![root],
                &mut chains,
            );
        }
        chains
    }

    fn walk<'a, C>(
        &'a self,
        delegations: &[&'a Delegation],
        owner: VerifyingKey,
        audience: VerifyingKey,
        current: &'a Delegation,
        path: &mut Vec<&'a Delegation>,
        chains: &mut Vec<DelegationChain<C>>,
    ) where
        C: CapabilityEncoding,
    {
        if current.audience() == &audience {
            let typed = path
                .iter()
                .map(|delegation| (*delegation).clone().try_with_capability_type::<C>())
                .collect::<std::result::Result<Vec<_>, _>>();
            if let Ok(delegations) = typed {
                chains.push(
                    DelegationChain::new(delegations)
                        .expect("Store paths are already bounded and structurally linked"),
                );
            }
            return;
        }
        if path.len() >= MAX_DELEGATION_CHAIN_DEPTH {
            return;
        }
        for next in delegations.iter().copied() {
            if next.issuer() != current.audience()
                || next.capability_owner() != &owner
                || path.iter().any(|known| std::ptr::eq(*known, next))
            {
                continue;
            }
            path.push(next);
            self.walk::<C>(delegations, owner, audience, next, path, chains);
            path.pop();
        }
    }

    pub(crate) fn renewal_targets(&self, audience: EndpointId) -> Vec<(EndpointId, u64)> {
        let mut targets = BTreeMap::<[u8; 32], u64>::new();
        for delegation in self.latest_delegations() {
            if delegation.audience() != &audience.as_verifying_key() {
                continue;
            }
            let rcan::Expires::At(expires_at) = delegation.expires() else {
                continue;
            };
            targets
                .entry(delegation.issuer().to_bytes())
                .and_modify(|current| *current = (*current).min(*expires_at))
                .or_insert(*expires_at);
        }
        targets
            .into_iter()
            .map(|(issuer, expires_at)| {
                (
                    EndpointId::from_bytes(&issuer).expect("delegation issuer is a verified key"),
                    expires_at,
                )
            })
            .collect()
    }

    fn latest_delegations(&self) -> Vec<&Delegation> {
        let mut latest = BTreeMap::<DelegationKey, &Delegation>::new();
        for delegation in self.delegations.values() {
            let key = DelegationKey::new(delegation);
            match latest.entry(key) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(delegation);
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    if expiry_rank(delegation) > expiry_rank(entry.get()) {
                        entry.insert(delegation);
                    }
                }
            }
        }
        latest.into_values().collect()
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct DelegationKey {
    issuer: [u8; 32],
    audience: [u8; 32],
    owner: [u8; 32],
    capability: Vec<u8>,
}

impl DelegationKey {
    fn new(delegation: &Delegation) -> Self {
        Self {
            issuer: delegation.issuer().to_bytes(),
            audience: delegation.audience().to_bytes(),
            owner: delegation.capability_owner().to_bytes(),
            capability: delegation.capability_bytes().to_vec(),
        }
    }
}

fn expiry_rank(delegation: &Delegation) -> u64 {
    match delegation.expires() {
        rcan::Expires::Never => u64::MAX,
        rcan::Expires::At(expires_at) => *expires_at,
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, SigningKey};
    use rcan::{Delegation, Expires};
    use serde::{Deserialize, Serialize};

    use super::{
        DelegationChain, DelegationId, MAX_DELEGATION_BYTES, MAX_DELEGATION_CHAIN_BYTES,
        MAX_DELEGATION_CHAIN_DEPTH, Revocation, Store, append_postcard_u64,
    };

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    enum TestCapability {
        All,
        Service(u8),
    }

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn valid_chain_delegations() -> Vec<Delegation<TestCapability>> {
        let owner = key(100);
        let delegate = key(101);
        let client = key(102);
        vec![
            Delegation::issuing_builder(
                &owner,
                delegate.verifying_key(),
                &TestCapability::Service(1),
            )
            .sign(Expires::Never),
            Delegation::delegating_builder(
                &delegate,
                client.verifying_key(),
                owner.verifying_key(),
                &TestCapability::Service(1),
            )
            .sign(Expires::Never),
        ]
    }

    fn encode_unchecked_chain<C>(delegations: &[Delegation<C>]) -> Vec<u8> {
        let mut encoded = vec![1];
        append_postcard_u64(&mut encoded, delegations.len() as u64);
        for delegation in delegations {
            let delegation = delegation.encode();
            append_postcard_u64(&mut encoded, delegation.len() as u64);
            encoded.extend_from_slice(&delegation);
        }
        encoded
    }

    #[test]
    fn accepts_a_valid_delegation_chain() {
        let owner = key(1);
        let delegate = key(2);
        let client = key(3);
        let root = Delegation::issuing_builder(
            &owner,
            delegate.verifying_key(),
            &TestCapability::Service(1),
        )
        .sign(Expires::Never);
        let leaf = Delegation::delegating_builder(
            &delegate,
            client.verifying_key(),
            owner.verifying_key(),
            &TestCapability::Service(1),
        )
        .sign(Expires::Never);

        let chain = DelegationChain::new(vec![root, leaf]).unwrap();

        assert_eq!(chain.delegations().len(), 2);
        assert_eq!(
            chain.delegations().last().unwrap().audience(),
            &client.verifying_key()
        );
    }

    #[test]
    fn delegation_chain_binary_roundtrip_is_canonical() {
        let chain = DelegationChain::new(valid_chain_delegations()).unwrap();

        let encoded = chain.encode();
        let decoded = DelegationChain::<TestCapability>::decode(&encoded).unwrap();

        assert_eq!(decoded, chain);
        assert_eq!(decoded.encode(), encoded);
        assert!(encoded.len() <= MAX_DELEGATION_CHAIN_BYTES);
    }

    #[test]
    fn chain_decode_rejects_advertised_bounds_before_delegations() {
        let oversized = vec![0; MAX_DELEGATION_CHAIN_BYTES + 1];
        let error = DelegationChain::<TestCapability>::decode(&oversized).unwrap_err();
        assert!(error.to_string().contains("maximum encoded size"));

        let too_many = [1, (MAX_DELEGATION_CHAIN_DEPTH + 1) as u8];
        let error = DelegationChain::<TestCapability>::decode(&too_many).unwrap_err();
        assert!(error.to_string().contains("maximum depth"));

        let mut oversized_length = vec![1, 1];
        append_postcard_u64(&mut oversized_length, (MAX_DELEGATION_BYTES as u64) + 1);
        let error = DelegationChain::<TestCapability>::decode(&oversized_length).unwrap_err();
        assert!(error.to_string().contains("maximum size"));
    }

    #[test]
    fn chain_decode_rejects_noncanonical_varints_and_trailing_bytes() {
        let noncanonical_count = [1, 0x81, 0x00];
        let error = DelegationChain::<TestCapability>::decode(&noncanonical_count).unwrap_err();
        assert!(error.to_string().contains("noncanonical delegation count"));

        let noncanonical_length = [1, 1, 0x80, 0x00];
        let error = DelegationChain::<TestCapability>::decode(&noncanonical_length).unwrap_err();
        assert!(error.to_string().contains("noncanonical delegation length"));

        let chain = DelegationChain::new(valid_chain_delegations()).unwrap();
        let mut trailing = chain.encode();
        trailing.push(0);
        let error = DelegationChain::<TestCapability>::decode(&trailing).unwrap_err();
        assert!(error.to_string().contains("trailing bytes"));
    }

    #[test]
    fn chain_decode_rejects_malformed_framing_and_empty_chains() {
        assert!(DelegationChain::<TestCapability>::decode(&[]).is_err());
        assert!(DelegationChain::<TestCapability>::decode(&[2, 1]).is_err());
        assert!(DelegationChain::<TestCapability>::decode(&[1, 0]).is_err());
        assert!(DelegationChain::<TestCapability>::decode(&[1]).is_err());
        assert!(DelegationChain::<TestCapability>::decode(&[1, 1, 1]).is_err());
    }

    #[test]
    fn chain_decode_rejects_tampered_signatures_and_broken_chains() {
        let chain = DelegationChain::new(valid_chain_delegations()).unwrap();
        let mut tampered = chain.encode();
        *tampered.last_mut().unwrap() ^= 1;
        let error = DelegationChain::<TestCapability>::decode(&tampered).unwrap_err();
        assert!(error.to_string().contains("invalid delegation in chain"));

        let owner = key(103);
        let delegate = key(104);
        let unrelated = key(105);
        let client = key(106);
        let root = Delegation::issuing_builder(
            &owner,
            delegate.verifying_key(),
            &TestCapability::Service(1),
        )
        .sign(Expires::Never);
        let broken = Delegation::delegating_builder(
            &unrelated,
            client.verifying_key(),
            owner.verifying_key(),
            &TestCapability::Service(1),
        )
        .sign(Expires::Never);
        let encoded = encode_unchecked_chain(&[root, broken]);
        let error = DelegationChain::<TestCapability>::decode(&encoded).unwrap_err();
        assert!(error.to_string().contains("issuer does not match"));
    }

    #[test]
    fn chain_does_not_treat_the_leaf_capability_as_an_invocation() {
        let owner = key(10);
        let delegate = key(11);
        let client = key(12);
        let root = Delegation::issuing_builder(
            &owner,
            delegate.verifying_key(),
            &TestCapability::Service(1),
        )
        .sign(Expires::Never);
        let broader_leaf = Delegation::delegating_builder(
            &delegate,
            client.verifying_key(),
            owner.verifying_key(),
            &TestCapability::All,
        )
        .sign(Expires::Never);

        assert!(DelegationChain::new(vec![root, broader_leaf]).is_ok());
    }

    #[test]
    fn rejects_empty_broken_and_overlong_chains() {
        assert!(DelegationChain::<TestCapability>::new(Vec::new()).is_err());

        let owner = key(4);
        let delegate = key(5);
        let unrelated = key(6);
        let client = key(7);
        let root = Delegation::issuing_builder(
            &owner,
            delegate.verifying_key(),
            &TestCapability::Service(1),
        )
        .sign(Expires::Never);
        let broken = Delegation::delegating_builder(
            &unrelated,
            client.verifying_key(),
            owner.verifying_key(),
            &TestCapability::Service(1),
        )
        .sign(Expires::Never);
        assert!(DelegationChain::new(vec![root.clone(), broken]).is_err());
        assert!(DelegationChain::new(vec![root; MAX_DELEGATION_CHAIN_DEPTH + 1]).is_err());
    }

    #[test]
    fn store_checks_signatures_and_deduplicates_without_a_vocabulary() {
        let owner = key(8);
        let client = key(9);
        let delegation = Delegation::issuing_builder(
            &owner,
            client.verifying_key(),
            &TestCapability::Service(1),
        )
        .sign(Expires::Never);
        let mut store = Store::default();

        let delegation_id = DelegationId::new(&delegation);
        assert_eq!(
            store.insert(delegation.clone().into_opaque()).unwrap(),
            delegation_id
        );
        assert_eq!(
            store.insert(delegation.clone().into_opaque()).unwrap(),
            delegation_id
        );
        assert_eq!(store.delegations().count(), 1);

        let mut encoded = delegation.encode();
        let last = encoded.last_mut().unwrap();
        *last ^= 1;
        assert!(store.insert_encoded(encoded).is_err());
        assert_eq!(store.delegations().count(), 1);

        let foreign = Delegation::issuing_builder(
            &owner,
            client.verifying_key(),
            &"foreign vocabulary".to_owned(),
        )
        .sign(Expires::Never);
        let foreign_id = DelegationId::new(&foreign);
        assert_eq!(store.insert(foreign.into_opaque()).unwrap(), foreign_id);
        assert_eq!(store.delegations().count(), 2);
        assert_eq!(
            store
                .chains_for::<TestCapability>(client.verifying_key())
                .len(),
            1
        );
    }

    #[test]
    fn store_finds_chains_ending_at_an_audience() {
        let owner = key(13);
        let delegate = key(14);
        let client = key(15);
        let root = Delegation::issuing_builder(
            &owner,
            delegate.verifying_key(),
            &TestCapability::Service(1),
        )
        .sign(Expires::Never);
        let leaf = Delegation::delegating_builder(
            &delegate,
            client.verifying_key(),
            owner.verifying_key(),
            &TestCapability::Service(1),
        )
        .sign(Expires::Never);
        let mut store = Store::default();
        store.insert(root.into_opaque()).unwrap();
        store.insert(leaf.into_opaque()).unwrap();

        let chains = store.chains_for::<TestCapability>(client.verifying_key());

        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].delegations().len(), 2);
    }

    #[test]
    fn revocations_are_signature_checked_and_deduplicated() {
        let owner = key(21);
        let client = key(22);
        let delegation = Delegation::issuing_builder(
            &owner,
            client.verifying_key(),
            &TestCapability::Service(1),
        )
        .sign(Expires::Never)
        .into_opaque();
        let revocation = Revocation::new(&owner, delegation.clone());
        let mut store = Store::default();

        assert!(revocation.verify().is_ok());
        assert!(store.insert_revocation(revocation.clone()).unwrap());
        assert!(!store.insert_revocation(revocation).unwrap());
        assert_eq!(store.delegations().count(), 0);

        let mut forged = Revocation::new(&owner, delegation);
        forged.signature = Signature::from_bytes(&[0; 64]);
        assert!(forged.verify().is_err());
        assert!(store.insert_revocation(forged).is_err());
    }

    #[test]
    fn revocation_authority_is_path_dependent() {
        let owner = key(23);
        let delegate_a = key(24);
        let delegate_x = key(25);
        let issuer = key(26);
        let client = key(27);
        let unrelated = key(28);
        let capability = TestCapability::Service(1);

        let root_a = Delegation::issuing_builder(&owner, delegate_a.verifying_key(), &capability)
            .sign(Expires::Never);
        let middle_a = Delegation::delegating_builder(
            &delegate_a,
            issuer.verifying_key(),
            owner.verifying_key(),
            &capability,
        )
        .sign(Expires::Never);
        let root_x = Delegation::issuing_builder(&owner, delegate_x.verifying_key(), &capability)
            .sign(Expires::Never);
        let middle_x = Delegation::delegating_builder(
            &delegate_x,
            issuer.verifying_key(),
            owner.verifying_key(),
            &capability,
        )
        .sign(Expires::Never);
        let leaf = Delegation::delegating_builder(
            &issuer,
            client.verifying_key(),
            owner.verifying_key(),
            &capability,
        )
        .sign(Expires::Never);
        let chain_a =
            DelegationChain::new(vec![root_a.clone(), middle_a.clone(), leaf.clone()]).unwrap();
        let chain_x =
            DelegationChain::new(vec![root_x.clone(), middle_x.clone(), leaf.clone()]).unwrap();
        let mut store = Store::default();
        for delegation in [root_a, middle_a, root_x, middle_x, leaf.clone()] {
            store.insert(delegation.into_opaque()).unwrap();
        }

        store
            .insert_revocation(Revocation::new(&unrelated, leaf.clone().into_opaque()))
            .unwrap();
        assert!(store.check_revocations(&chain_a).is_ok());
        assert!(store.check_revocations(&chain_x).is_ok());

        store
            .insert_revocation(Revocation::new(&delegate_a, leaf.clone().into_opaque()))
            .unwrap();
        let error = store.check_revocations(&chain_a).unwrap_err();
        assert_eq!(error.delegation(), DelegationId::new(&leaf));
        assert_eq!(error.revoker(), delegate_a.verifying_key());
        assert!(store.check_revocations(&chain_x).is_ok());

        let mut owner_store = store.clone();
        owner_store
            .insert_revocation(Revocation::new(&owner, leaf.clone().into_opaque()))
            .unwrap();
        assert!(owner_store.check_revocations(&chain_a).is_err());
        assert!(owner_store.check_revocations(&chain_x).is_err());

        let mut issuer_store = store;
        issuer_store
            .insert_revocation(Revocation::new(&issuer, leaf.into_opaque()))
            .unwrap();
        assert!(issuer_store.check_revocations(&chain_a).is_err());
        assert!(issuer_store.check_revocations(&chain_x).is_err());
    }

    #[test]
    fn relevant_delegations_include_incomplete_chain_suffixes() {
        let owner = key(16);
        let first_delegate = key(17);
        let second_delegate = key(18);
        let client = key(19);
        let missing_root = Delegation::issuing_builder(
            &owner,
            first_delegate.verifying_key(),
            &TestCapability::Service(1),
        )
        .sign(Expires::Never);
        let middle = Delegation::delegating_builder(
            &first_delegate,
            second_delegate.verifying_key(),
            owner.verifying_key(),
            &TestCapability::Service(1),
        )
        .sign(Expires::Never);
        let leaf = Delegation::delegating_builder(
            &second_delegate,
            client.verifying_key(),
            owner.verifying_key(),
            &TestCapability::Service(1),
        )
        .sign(Expires::Never);
        let unrelated = Delegation::issuing_builder(
            &owner,
            key(20).verifying_key(),
            &TestCapability::Service(2),
        )
        .sign(Expires::Never);
        let mut store = Store::default();
        store.insert(middle.into_opaque()).unwrap();
        store.insert(leaf.into_opaque()).unwrap();
        store.insert(unrelated.into_opaque()).unwrap();

        let relevant = store.relevant_delegations(client.verifying_key());

        assert_eq!(relevant.len(), 2);
        assert!(
            store
                .chains_for::<TestCapability>(client.verifying_key())
                .is_empty()
        );
        store.insert(missing_root.into_opaque()).unwrap();
        assert_eq!(
            store
                .latest_chains_for::<TestCapability>(client.verifying_key())
                .len(),
            1
        );
    }

    #[test]
    fn renewal_evidence_uses_only_latest_logical_delegations() {
        let owner = key(29);
        let client = key(30);
        let capability = TestCapability::Service(1);
        let older = Delegation::issuing_builder(&owner, client.verifying_key(), &capability)
            .sign(Expires::At(1_000));
        let latest = Delegation::issuing_builder(&owner, client.verifying_key(), &capability)
            .sign(Expires::At(2_000));
        let mut store = Store::default();
        store.insert(older.into_opaque()).unwrap();
        store.insert(latest.clone().into_opaque()).unwrap();

        let relevant = store.relevant_delegations(client.verifying_key());
        assert_eq!(relevant.len(), 2);
        let relevant = store.latest_relevant_delegations(client.verifying_key());
        assert_eq!(relevant.len(), 1);
        assert_eq!(DelegationId::new(&relevant[0]), DelegationId::new(&latest));
        assert_eq!(
            store
                .latest_chains_for::<TestCapability>(client.verifying_key())
                .len(),
            1
        );
    }
}
