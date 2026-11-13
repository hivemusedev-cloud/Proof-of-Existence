//! Two libp2p nodes on localhost discover each other by direct dial,
//! form a gossipsub mesh, and exchange a block payload and a vote payload.

use poe_net::{NetNode, TOPIC_BLOCKS, TOPIC_VOTES};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_nodes_exchange_gossip() {
    let mut a = NetNode::new().await.unwrap();
    let mut b = NetNode::new().await.unwrap();
    let addr = a
        .wait_listen_addr(Duration::from_secs(10))
        .await
        .expect("node A must listen");
    let full = addr.with(libp2p::multiaddr::Protocol::P2p(a.peer_id()));
    b.dial(full).unwrap();

    // Drive both swarms; republish until the mesh accepts it, and collect
    // whatever B receives.
    let payload: Vec<u8> = b"block:round-7".to_vec();
    let vote_payload: Vec<u8> = b"vote:machine-3".to_vec();
    let mut got_block = false;
    let mut got_vote = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while tokio::time::Instant::now() < deadline && !(got_block && got_vote) {
        let _ = a.publish(TOPIC_BLOCKS, payload.clone());
        let _ = a.publish(TOPIC_VOTES, vote_payload.clone());
        tokio::select! {
            msg = b.poll_once() => {
                if let Some(m) = msg {
                    if m.topic == TOPIC_BLOCKS && m.data == payload {
                        got_block = true;
                    }
                    if m.topic == TOPIC_VOTES && m.data == vote_payload {
                        got_vote = true;
                    }
                }
            }
            _ = a.poll_once() => {}
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
    assert!(got_block, "B must receive the block payload");
    assert!(got_vote, "B must receive the vote payload");
}
