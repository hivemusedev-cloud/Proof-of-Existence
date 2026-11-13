//! poe-net — the node's network transport (BUILD_FLOW Step 4: libp2p
//! gossip).
//!
//! Three gossipsub topics carry the consensus traffic — `poe/blocks`,
//! `poe/votes`, `poe/acts` — and mDNS plus direct dial handle discovery.
//! Payloads are opaque bytes at this layer: the block, vote and act
//! encodings belong to poe-dag / poe-finality / poe-store, and a node
//! never relays a payload it has not first handed to its own validators
//! (that wiring lives in the node binary, above this crate).
//!
//! Scope honesty: this is the transport the flow names (libp2p gossip).
//! The transport *proposal* document in poe-build-2026-11-11 (hand-rolled
//! PQ sessions etc.) is a separate, unadopted design and is NOT what this
//! crate implements.

use futures::StreamExt;
use libp2p::gossipsub;
use libp2p::mdns;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{Multiaddr, PeerId, Swarm, SwarmBuilder};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

pub const TOPIC_BLOCKS: &str = "poe/blocks";
pub const TOPIC_VOTES: &str = "poe/votes";
pub const TOPIC_ACTS: &str = "poe/acts";
pub const ALL_TOPICS: [&str; 3] = [TOPIC_BLOCKS, TOPIC_VOTES, TOPIC_ACTS];

#[derive(NetworkBehaviour)]
struct Behaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

/// A running gossip node. Drive it with [`NetNode::poll_once`] (or run
/// [`NetNode::run`] as a task) so it keeps discovering, dialing and
/// relaying; publish with [`NetNode::publish`].
pub struct NetNode {
    swarm: Swarm<Behaviour>,
    topic_blocks: gossipsub::IdentTopic,
    topic_votes: gossipsub::IdentTopic,
    topic_acts: gossipsub::IdentTopic,
}

/// One inbound gossip message: the topic it arrived on and its payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inbound {
    pub topic: String,
    pub data: Vec<u8>,
    pub source: Option<PeerId>,
}

impl NetNode {
    /// Create a node and start listening on an OS-assigned localhost port.
    pub async fn new() -> std::io::Result<NetNode> {
        Self::start(None, "/ip4/127.0.0.1/tcp/0").await
    }

    /// Create a node with a persistent transport identity (a libp2p
    /// keypair the caller loaded from its key store) listening on the
    /// given multiaddr — the form a long-running network node takes.
    /// With `None` the identity is fresh, as in [`NetNode::new`].
    pub async fn start(
        keypair: Option<libp2p::identity::Keypair>,
        listen: &str,
    ) -> std::io::Result<NetNode> {
        let mut swarm = match keypair {
            Some(kp) => SwarmBuilder::with_existing_identity(kp),
            None => SwarmBuilder::with_new_identity(),
        }
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )
            .map_err(std::io::Error::other)?
            .with_behaviour(|key| {
                // Message ids are content hashes: the same payload gossiped
                // twice is one message, so relays deduplicate for free.
                let message_id_fn = |msg: &gossipsub::Message| {
                    let mut h = DefaultHasher::new();
                    msg.data.hash(&mut h);
                    msg.topic.hash(&mut h);
                    gossipsub::MessageId::from(h.finish().to_be_bytes())
                };
                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_millis(200))
                    .validation_mode(gossipsub::ValidationMode::Permissive)
                    .message_id_fn(message_id_fn)
                    .build()
                    .map_err(std::io::Error::other)?;
                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )
                .map_err(std::io::Error::other)?;
                let mdns = mdns::tokio::Behaviour::new(
                    mdns::Config::default(),
                    key.public().to_peer_id(),
                )?;
                Ok(Behaviour { gossipsub, mdns })
            })
            .map_err(std::io::Error::other)?
            .build();
        swarm
            .listen_on(listen.parse().map_err(std::io::Error::other)?)
            .map_err(std::io::Error::other)?;
        let topic_blocks = gossipsub::IdentTopic::new(TOPIC_BLOCKS);
        let topic_votes = gossipsub::IdentTopic::new(TOPIC_VOTES);
        let topic_acts = gossipsub::IdentTopic::new(TOPIC_ACTS);
        for t in [&topic_blocks, &topic_votes, &topic_acts] {
            swarm.behaviour_mut().gossipsub.subscribe(t).map_err(std::io::Error::other)?;
        }
        Ok(NetNode { swarm, topic_blocks, topic_votes, topic_acts })
    }

    pub fn peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    pub fn dial(&mut self, addr: Multiaddr) -> Result<(), libp2p::swarm::DialError> {
        self.swarm.dial(addr)
    }

    fn topic(&self, name: &str) -> &gossipsub::IdentTopic {
        match name {
            TOPIC_VOTES => &self.topic_votes,
            TOPIC_ACTS => &self.topic_acts,
            _ => &self.topic_blocks,
        }
    }

    /// Publish a payload on one of the three topics. Fails with
    /// `InsufficientPeers` until the topic mesh has formed — callers that
    /// publish early should retry, as the simnet test does.
    pub fn publish(
        &mut self,
        topic: &str,
        data: Vec<u8>,
    ) -> Result<gossipsub::MessageId, gossipsub::PublishError> {
        let t = self.topic(topic).clone();
        self.swarm.behaviour_mut().gossipsub.publish(t, data)
    }

    /// Drive the swarm until the next notable event: an inbound gossip
    /// message (returned), a new listen address, or a discovery. Returns
    /// `None` for events the caller does not need to see.
    pub async fn poll_once(&mut self) -> Option<Inbound> {
        match self.swarm.select_next_some().await {
            SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(peers))) => {
                for (peer, addr) in peers {
                    self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
                    let _ = self.swarm.dial(addr);
                }
                None
            }
            SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                message,
                ..
            })) => Some(Inbound {
                topic: message.topic.to_string(),
                data: message.data,
                source: message.source,
            }),
            _ => None,
        }
    }

    /// Wait (up to `timeout`) for this node's first listen address —
    /// what a peer needs to dial it directly.
    pub async fn wait_listen_addr(&mut self, timeout: Duration) -> Option<Multiaddr> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return None;
            }
            match tokio::time::timeout(remaining, self.swarm.select_next_some()).await {
                Ok(SwarmEvent::NewListenAddr { address, .. }) => return Some(address),
                Ok(_) => continue,
                Err(_) => return None,
            }
        }
    }
}
