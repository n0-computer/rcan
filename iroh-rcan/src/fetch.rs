//! Authenticated one-shot delegation fetch over iroh.

use std::{collections::BTreeSet, fmt};

use iroh::{
    Endpoint, EndpointAddr, EndpointId,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};
use n0_error::{e, stack_error};
use rcan::Delegation;

use crate::{MAX_DELEGATION_BYTES, Store};

/// Errors produced by the delegation-fetch protocol.
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum Error {
    /// The response contains more delegations than the protocol allows.
    #[error("too many delegations")]
    TooManyDelegations,
    /// The encoded response exceeds the protocol's size limit.
    #[error("delegation response is too large")]
    ResponseTooLarge,
    /// The response contains the same delegation more than once.
    #[error("duplicate delegation")]
    DuplicateDelegation,
    /// The response contains evidence unrelated to its authenticated requester.
    #[error("response contains a delegation unrelated to this endpoint")]
    UnrelatedDelegation,
    /// Encoding the response failed.
    #[error("failed to encode delegation response")]
    EncodeResponse {
        #[error(std_err)]
        source: postcard::Error,
    },
    /// Decoding the response failed.
    #[error("failed to decode delegation response")]
    DecodeResponse {
        #[error(std_err)]
        source: postcard::Error,
    },
    /// Connecting to the delegation provider failed.
    #[error("failed to connect to delegation provider")]
    Connect {
        #[error(std_err)]
        source: iroh::endpoint::ConnectError,
    },
    /// Opening a response stream failed.
    #[error("failed to open delegation response stream")]
    OpenStream {
        #[error(std_err)]
        source: iroh::endpoint::ConnectionError,
    },
    /// Reading a response stream failed.
    #[error("failed to read delegation response")]
    ReadResponse {
        #[error(std_err)]
        source: iroh::endpoint::ReadToEndError,
    },
    /// Writing a response stream failed.
    #[error("failed to write delegation response")]
    WriteResponse {
        #[error(std_err)]
        source: iroh::endpoint::WriteError,
    },
    /// Finishing a response stream failed.
    #[error("failed to finish delegation response")]
    FinishResponse {
        #[error(std_err)]
        source: iroh::endpoint::ClosedStream,
    },
    /// The response contained invalid stored evidence.
    #[error("invalid delegation in response")]
    InvalidDelegation { source: crate::StoreError },
}

/// Result returned by the delegation-fetch protocol.
pub type Result<T> = std::result::Result<T, Error>;

/// ALPN used by the delegation-fetch protocol.
pub const ALPN: &[u8] = b"iroh-rcan/fetch/3";

/// Maximum number of delegations returned by one request.
pub const MAX_DELEGATIONS: usize = 128;

/// Maximum encoded response size.
pub const MAX_RESPONSE_BYTES: usize = MAX_DELEGATIONS * MAX_DELEGATION_BYTES + 1024;

/// Serves relevant delegations selected from the authenticated remote endpoint ID.
#[derive(Clone)]
pub struct FetchProtocol<F> {
    delegations_for: F,
}

impl<F> FetchProtocol<F> {
    /// Creates a fetch handler.
    pub fn new(delegations_for: F) -> Self {
        Self { delegations_for }
    }
}

impl<F> fmt::Debug for FetchProtocol<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FetchProtocol")
    }
}

impl<F> ProtocolHandler for FetchProtocol<F>
where
    F: Fn(EndpointId) -> Result<Vec<Delegation>> + Send + Sync + 'static,
{
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        serve(connection, &self.delegations_for)
            .await
            .map_err(|error| AcceptError::from_boxed(Box::new(error)))
    }
}

async fn serve(
    connection: Connection,
    delegations_for: impl FnOnce(EndpointId) -> Result<Vec<Delegation>>,
) -> Result<()> {
    let requester = connection.remote_id();
    let delegations = delegations_for(requester)?;
    if delegations.len() > MAX_DELEGATIONS {
        return Err(e!(Error::TooManyDelegations));
    }
    let response =
        postcard::to_stdvec(&delegations).map_err(|source| e!(Error::EncodeResponse, source))?;
    if response.len() > MAX_RESPONSE_BYTES {
        return Err(e!(Error::ResponseTooLarge));
    }
    let mut send = connection
        .open_uni()
        .await
        .map_err(|source| e!(Error::OpenStream, source))?;
    send.write_all(&response)
        .await
        .map_err(|source| e!(Error::WriteResponse, source))?;
    send.finish()
        .map_err(|source| e!(Error::FinishResponse, source))?;
    connection.closed().await;
    Ok(())
}

/// Fetches delegations relevant to this endpoint from `provider`.
pub async fn fetch(
    endpoint: &Endpoint,
    provider: impl Into<EndpointAddr>,
) -> Result<Vec<Delegation>> {
    let connection = endpoint
        .connect(provider, ALPN)
        .await
        .map_err(|source| e!(Error::Connect, source))?;
    let mut recv = connection
        .accept_uni()
        .await
        .map_err(|source| e!(Error::OpenStream, source))?;
    let response = recv
        .read_to_end(MAX_RESPONSE_BYTES)
        .await
        .map_err(|source| e!(Error::ReadResponse, source))?;
    connection.close(0u32.into(), b"delegations received");

    let delegations: Vec<Delegation> =
        postcard::from_bytes(&response).map_err(|source| e!(Error::DecodeResponse, source))?;
    if delegations.len() > MAX_DELEGATIONS {
        return Err(e!(Error::TooManyDelegations));
    }
    let audience = endpoint.id().as_verifying_key();
    let received = delegations
        .iter()
        .map(Delegation::encode)
        .collect::<BTreeSet<_>>();
    if received.len() != delegations.len() {
        return Err(e!(Error::DuplicateDelegation));
    }
    let mut store = Store::default();
    for delegation in &delegations {
        store
            .insert(delegation.clone())
            .map_err(|source| e!(Error::InvalidDelegation, source))?;
    }
    let relevant = store
        .relevant_delegations(audience)
        .iter()
        .map(Delegation::encode)
        .collect::<BTreeSet<_>>();
    if received != relevant {
        return Err(e!(Error::UnrelatedDelegation));
    }
    Ok(delegations)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use iroh::{Endpoint, SecretKey, endpoint::presets, protocol::Router};
    use rcan::{Delegation, Expires};
    use serde::{Deserialize, Serialize};

    use super::{ALPN, FetchProtocol, fetch};
    use crate::Store;

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct TestCapability(String);

    async fn endpoint(secret_key: SecretKey) -> Endpoint {
        Endpoint::builder(presets::Minimal)
            .secret_key(secret_key)
            .clear_ip_transports()
            .bind_addr((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .bind()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn fetch_uses_the_authenticated_requester() {
        let owner_key = SecretKey::from_bytes(&[1; 32]);
        let provider_key = SecretKey::from_bytes(&[2; 32]);
        let client_key = SecretKey::from_bytes(&[3; 32]);
        let other_key = SecretKey::from_bytes(&[4; 32]);
        let provider = endpoint(provider_key.clone()).await;
        let client = endpoint(client_key.clone()).await;
        let other = endpoint(other_key).await;
        let missing_root = Delegation::issuing_builder(
            owner_key.as_signing_key(),
            provider.id().as_verifying_key(),
            &TestCapability("lmstudio".to_owned()),
        )
        .sign(Expires::Never);
        let leaf = Delegation::delegating_builder(
            provider_key.as_signing_key(),
            client.id().as_verifying_key(),
            owner_key.public().as_verifying_key(),
            &TestCapability("lmstudio".to_owned()),
        )
        .sign(Expires::Never);
        let mut served = Store::default();
        served.insert(leaf.into_opaque()).unwrap();
        let protocol = FetchProtocol::new(move |requester: iroh::EndpointId| {
            Ok(served.relevant_delegations(requester.as_verifying_key()))
        });
        let router = Router::builder(provider).accept(ALPN, protocol).spawn();

        let delegations = fetch(&client, router.endpoint().addr()).await.unwrap();
        assert_eq!(delegations.len(), 1);
        let mut received = Store::default();
        received.insert(missing_root.into_opaque()).unwrap();
        for delegation in delegations {
            received.insert(delegation).unwrap();
        }
        assert_eq!(
            received
                .chains_for::<TestCapability>(client.id().as_verifying_key())
                .len(),
            1
        );
        assert!(
            fetch(&other, router.endpoint().addr())
                .await
                .unwrap()
                .is_empty()
        );

        client.close().await;
        other.close().await;
        router.shutdown().await.unwrap();
    }
}
