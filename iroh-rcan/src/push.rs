//! Authenticated one-shot delegation delivery over iroh.

use std::{collections::BTreeSet, fmt};

use iroh::{
    Endpoint, EndpointAddr, EndpointId,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};
use n0_error::{e, stack_error};
use rcan::Delegation;

use crate::{
    Store,
    fetch::{MAX_DELEGATIONS, MAX_RESPONSE_BYTES},
};

/// Errors produced by the delegation-push protocol.
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum Error {
    /// The request contains more delegations than the protocol allows.
    #[error("too many delegations")]
    TooManyDelegations,
    /// The encoded request exceeds the protocol's size limit.
    #[error("delegation request is too large")]
    RequestTooLarge,
    /// The request contains the same delegation more than once.
    #[error("duplicate delegation")]
    DuplicateDelegation,
    /// The request contains evidence unrelated to its authenticated audience.
    #[error("request contains a delegation unrelated to this endpoint")]
    UnrelatedDelegation,
    /// The acknowledgement did not contain the expected marker.
    #[error("invalid delegation acknowledgement")]
    InvalidAcknowledgement,
    /// Encoding the request failed.
    #[error("failed to encode delegation request")]
    EncodeRequest {
        #[error(std_err)]
        source: postcard::Error,
    },
    /// Decoding the request failed.
    #[error("failed to decode delegation request")]
    DecodeRequest {
        #[error(std_err)]
        source: postcard::Error,
    },
    /// Opening a request or acknowledgement stream failed.
    #[error("failed to open delegation stream")]
    OpenStream {
        #[error(std_err)]
        source: iroh::endpoint::ConnectionError,
    },
    /// Reading a request or acknowledgement stream failed.
    #[error("failed to read delegation stream")]
    ReadStream {
        #[error(std_err)]
        source: iroh::endpoint::ReadToEndError,
    },
    /// Writing a request or acknowledgement stream failed.
    #[error("failed to write delegation stream")]
    WriteStream {
        #[error(std_err)]
        source: iroh::endpoint::WriteError,
    },
    /// Finishing a request or acknowledgement stream failed.
    #[error("failed to finish delegation stream")]
    FinishStream {
        #[error(std_err)]
        source: iroh::endpoint::ClosedStream,
    },
    /// Connecting to the delegation audience failed.
    #[error("failed to connect to delegation audience")]
    Connect {
        #[error(std_err)]
        source: iroh::endpoint::ConnectError,
    },
    /// The request contained invalid stored evidence.
    #[error("invalid delegation in request")]
    InvalidDelegation { source: crate::StoreError },
}

/// Result returned by the delegation-push protocol.
pub type Result<T> = std::result::Result<T, Error>;

/// ALPN used by the delegation-push protocol.
pub const ALPN: &[u8] = b"iroh-rcan/push/2";

/// Receives delegations for this endpoint and passes them to the application.
#[derive(Clone)]
pub struct PushProtocol<F> {
    audience: EndpointId,
    receive: F,
}

impl<F> PushProtocol<F> {
    /// Creates a push handler.
    pub fn new(audience: EndpointId, receive: F) -> Self {
        Self { audience, receive }
    }
}

impl<F> fmt::Debug for PushProtocol<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PushProtocol")
    }
}

impl<F> ProtocolHandler for PushProtocol<F>
where
    F: Fn(EndpointId, Vec<Delegation>) -> Result<()> + Send + Sync + 'static,
{
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        receive(connection, self.audience, &self.receive)
            .await
            .map_err(|error| AcceptError::from_boxed(Box::new(error)))
    }
}

async fn receive(
    connection: Connection,
    audience: EndpointId,
    receive: impl FnOnce(EndpointId, Vec<Delegation>) -> Result<()>,
) -> Result<()> {
    let sender = connection.remote_id();
    let mut recv = connection
        .accept_uni()
        .await
        .map_err(|source| e!(Error::OpenStream, source))?;
    let request = recv
        .read_to_end(MAX_RESPONSE_BYTES)
        .await
        .map_err(|source| e!(Error::ReadStream, source))?;
    let delegations = decode_relevant(&request, audience)?;
    receive(sender, delegations)?;
    let mut send = connection
        .open_uni()
        .await
        .map_err(|source| e!(Error::OpenStream, source))?;
    send.write_all(&[0])
        .await
        .map_err(|source| e!(Error::WriteStream, source))?;
    send.finish()
        .map_err(|source| e!(Error::FinishStream, source))?;
    connection.closed().await;
    Ok(())
}

/// Delivers delegations to `audience` and returns after the receiver acknowledges them.
pub async fn push(
    endpoint: &Endpoint,
    audience: impl Into<EndpointAddr>,
    delegations: Vec<Delegation>,
) -> Result<()> {
    let audience = audience.into();
    validate_relevant(&delegations, audience.id)?;
    let request =
        postcard::to_stdvec(&delegations).map_err(|source| e!(Error::EncodeRequest, source))?;
    if request.len() > MAX_RESPONSE_BYTES {
        return Err(e!(Error::RequestTooLarge));
    }
    let connection = endpoint
        .connect(audience, ALPN)
        .await
        .map_err(|source| e!(Error::Connect, source))?;
    let mut send = connection
        .open_uni()
        .await
        .map_err(|source| e!(Error::OpenStream, source))?;
    send.write_all(&request)
        .await
        .map_err(|source| e!(Error::WriteStream, source))?;
    send.finish()
        .map_err(|source| e!(Error::FinishStream, source))?;
    let mut recv = connection
        .accept_uni()
        .await
        .map_err(|source| e!(Error::OpenStream, source))?;
    let acknowledgement = recv
        .read_to_end(1)
        .await
        .map_err(|source| e!(Error::ReadStream, source))?;
    if acknowledgement != [0] {
        return Err(e!(Error::InvalidAcknowledgement));
    }
    connection.close(0u32.into(), b"delegations acknowledged");
    Ok(())
}

fn decode_relevant(bytes: &[u8], audience: EndpointId) -> Result<Vec<Delegation>> {
    let delegations: Vec<Delegation> =
        postcard::from_bytes(bytes).map_err(|source| e!(Error::DecodeRequest, source))?;
    validate_relevant(&delegations, audience)?;
    Ok(delegations)
}

fn validate_relevant(delegations: &[Delegation], audience: EndpointId) -> Result<()> {
    if delegations.len() > MAX_DELEGATIONS {
        return Err(e!(Error::TooManyDelegations));
    }
    let received = delegations
        .iter()
        .map(Delegation::encode)
        .collect::<BTreeSet<_>>();
    if received.len() != delegations.len() {
        return Err(e!(Error::DuplicateDelegation));
    }
    let mut store = Store::default();
    for delegation in delegations {
        store
            .insert(delegation.clone())
            .map_err(|source| e!(Error::InvalidDelegation, source))?;
    }
    let relevant = store
        .relevant_delegations(audience.as_verifying_key())
        .iter()
        .map(Delegation::encode)
        .collect::<BTreeSet<_>>();
    if received != relevant {
        return Err(e!(Error::UnrelatedDelegation));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        net::Ipv4Addr,
        sync::{Arc, RwLock},
    };

    use iroh::{Endpoint, SecretKey, endpoint::presets, protocol::Router};
    use n0_error::e;
    use rcan::{Delegation, Expires};
    use serde::{Deserialize, Serialize};

    use super::{ALPN, Error, PushProtocol, push};
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
    async fn push_delivers_only_receiver_relevant_evidence() {
        let owner_key = SecretKey::from_bytes(&[5; 32]);
        let sender_key = SecretKey::from_bytes(&[6; 32]);
        let receiver_key = SecretKey::from_bytes(&[7; 32]);
        let other_key = SecretKey::from_bytes(&[8; 32]);
        let sender = endpoint(sender_key.clone()).await;
        let receiver = endpoint(receiver_key.clone()).await;
        let other = endpoint(other_key).await;
        let root = Delegation::issuing_builder(
            owner_key.as_signing_key(),
            sender.id().as_verifying_key(),
            &TestCapability("lmstudio".to_owned()),
        )
        .sign(Expires::Never);
        let leaf = Delegation::delegating_builder(
            sender_key.as_signing_key(),
            receiver.id().as_verifying_key(),
            owner_key.public().as_verifying_key(),
            &TestCapability("lmstudio".to_owned()),
        )
        .sign(Expires::Never);
        let received = Arc::new(RwLock::new(Store::default()));
        let target = received.clone();
        let protocol = PushProtocol::new(receiver.id(), move |_sender, delegations| {
            let mut store = target.write().unwrap();
            for delegation in delegations {
                store
                    .insert(delegation)
                    .map_err(|source| e!(Error::InvalidDelegation, source))?;
            }
            Ok(())
        });
        let router = Router::builder(receiver).accept(ALPN, protocol).spawn();

        push(
            &sender,
            router.endpoint().addr(),
            vec![root.clone().into_opaque(), leaf.into_opaque()],
        )
        .await
        .unwrap();
        assert_eq!(
            received
                .read()
                .unwrap()
                .chains_for::<TestCapability>(router.endpoint().id().as_verifying_key())
                .len(),
            1
        );
        assert!(
            push(&sender, other.addr(), vec![root.into_opaque()],)
                .await
                .is_err()
        );

        sender.close().await;
        other.close().await;
        router.shutdown().await.unwrap();
    }
}
