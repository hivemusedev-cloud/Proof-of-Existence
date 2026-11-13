//! poe-msg — the messaging layer (BUILD_FLOW Step 9).
//!
//! * **Detection tags.** A message is announced by a tag only its
//!   recipient can recognize: `tag = H("msgtag", shared, window, i)`.
//!   Tags are *claimed* — the first claim stands; the identical claim
//!   again is a **replay** (refused), and the same tag presented bound
//!   to a different message or a different window is a **restamp**
//!   (refused, and evidence against the claimant). The claims live in a
//!   hash index here at the network edge; the kernel's MessageTag
//!   registry is the settlement record they mirror.
//! * **The window.** Messages live in a 4-week window (`epoch / 4`).
//!   Claims for an expired window or a future one are refused.
//! * **Key exchange + ratchet.** An ML-KEM-1024 exchange seeds a hash
//!   ratchet: `ck₀ = H("ratchet", ss)`, each message keyed by
//!   `H("msgkey", ckᵢ)` and the chain stepped by `H("ratchet-next", ckᵢ)`.
//!   Nothing is signed — the construction is symmetric-only, so a
//!   transcript could have been produced by either party: that is the
//!   deniability the files ask for. (The keystream is H-based, in the
//!   seed's hash-centric style; a production cipher swap does not change
//!   the ratchet or the tag layer.)
//! * **Slot-priced spam.** Sending costs one of the sender's slots:
//!   65,536 per heartbeat-credited machine-epoch, zero otherwise. A slot
//!   is spent once; reuse is refused.

use poe_crypto::hash::{h, h_u64, Part};
use poe_crypto::pq::{kem_encapsulate, KemKeypair};
use std::collections::{HashMap, HashSet};

/// Slots per credited machine-epoch (the kernel's SLOTS constant).
pub const SLOTS_PER_EPOCH: u64 = 65_536;
/// Epochs per message window.
pub const WINDOW_EPOCHS: u64 = 4;

pub fn window_of(epoch: u64) -> u64 {
    epoch / WINDOW_EPOCHS
}

/// The detection tag for the `i`-th message under a shared secret in a
/// window. Only a holder of the shared secret can compute or recognize it.
pub fn detection_tag(shared: &[u8; 64], window: u64, i: u64) -> u64 {
    h_u64("msgtag", &[Part::Bytes(shared), Part::Nat(window), Part::Nat(i)])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimOutcome {
    Accepted,
    /// The identical claim again.
    Replay,
    /// The same tag bound to a different message or window.
    Restamp,
    /// Outside the live window (expired or future).
    WrongWindow,
}

/// The network-edge tag claim index.
#[derive(Default)]
pub struct TagClaims {
    claimed: HashMap<u64, (u64, u64)>, // tag -> (window, message digest prefix)
}

impl TagClaims {
    pub fn claim(&mut self, tag: u64, window: u64, msg_digest: u64, current_window: u64) -> ClaimOutcome {
        if window != current_window {
            return ClaimOutcome::WrongWindow;
        }
        match self.claimed.get(&tag) {
            None => {
                self.claimed.insert(tag, (window, msg_digest));
                ClaimOutcome::Accepted
            }
            Some(&(w, d)) if w == window && d == msg_digest => ClaimOutcome::Replay,
            Some(_) => ClaimOutcome::Restamp,
        }
    }

    pub fn len(&self) -> usize {
        self.claimed.len()
    }
}

// -- the ratchet ----------------------------------------------------------------

/// One side of a conversation: a hash ratchet over the KEM shared secret.
pub struct Ratchet {
    chain: [u8; 64],
    index: u64,
    skipped: HashMap<u64, [u8; 64]>,
}

fn msg_key(chain: &[u8; 64]) -> [u8; 64] {
    h("msgkey", &[Part::Bytes(chain)])
}

fn step(chain: &[u8; 64]) -> [u8; 64] {
    h("ratchet-next", &[Part::Bytes(chain)])
}

/// Run the ML-KEM-1024 exchange: the initiator encapsulates to the
/// responder's key; both sides land on the same shared secret and start
/// identical ratchets.
pub fn initiate(
    rng: &mut rand::rngs::ThreadRng,
    responder: &KemKeypair,
) -> (Vec<u8>, Ratchet, Ratchet) {
    let (ct, ss) = kem_encapsulate(rng, &responder.encaps_key_bytes()).expect("encapsulate");
    let ss2 = responder.decapsulate(&ct).expect("decapsulate");
    assert_eq!(ss, ss2, "KEM sides agree");
    let mut seed = [0u8; 64];
    seed[..ss.len()].copy_from_slice(&ss);
    let start = h("ratchet", &[Part::Bytes(&seed)]);
    (
        ct,
        Ratchet { chain: start, index: 0, skipped: HashMap::new() },
        Ratchet { chain: start, index: 0, skipped: HashMap::new() },
    )
}

/// Start a ratchet from an already-shared secret (e.g. resumed state).
pub fn from_shared(shared: &[u8; 64]) -> Ratchet {
    Ratchet {
        chain: h("ratchet", &[Part::Bytes(shared)]),
        index: 0,
        skipped: HashMap::new(),
    }
}

fn keystream(key: &[u8; 64], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut block = 0u64;
    while out.len() < len {
        let b = h("stream", &[Part::Bytes(key), Part::Nat(block)]);
        out.extend_from_slice(&b);
        block += 1;
    }
    out.truncate(len);
    out
}

impl Ratchet {
    pub fn index(&self) -> u64 {
        self.index
    }

    /// Encrypt the next message; the wire form is (index, ciphertext).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> (u64, Vec<u8>) {
        let key = msg_key(&self.chain);
        let ks = keystream(&key, plaintext.len());
        let ct: Vec<u8> = plaintext.iter().zip(ks).map(|(a, b)| a ^ b).collect();
        self.chain = step(&self.chain);
        let i = self.index;
        self.index += 1;
        (i, ct)
    }

    /// Decrypt a message by index, tolerating out-of-order delivery by
    /// caching skipped message keys (bounded, as any real client must).
    pub fn decrypt(&mut self, index: u64, ct: &[u8]) -> Option<Vec<u8>> {
        let key = if let Some(k) = self.skipped.remove(&index) {
            k
        } else if index >= self.index {
            // Walk forward, caching the keys we pass.
            let mut key = msg_key(&self.chain);
            let mut cur = self.index;
            while cur < index {
                self.skipped.insert(cur, key);
                if self.skipped.len() > 1024 {
                    return None; // too far ahead; refuse rather than balloon
                }
                self.chain = step(&self.chain);
                cur += 1;
                key = msg_key(&self.chain);
            }
            self.chain = step(&self.chain);
            self.index = index + 1;
            key
        } else {
            return None; // already consumed and not cached: gone for good
        };
        let ks = keystream(&key, ct.len());
        Some(ct.iter().zip(ks).map(|(a, b)| a ^ b).collect())
    }
}

// -- slot-priced sending ----------------------------------------------------------

/// A machine's slot account for one epoch.
#[derive(Default)]
pub struct SlotAccount {
    spent: HashSet<(u64, u64, u64)>, // (machine, epoch, slot)
}

impl SlotAccount {
    /// How many slots a machine has in an epoch: the full 65,536 if its
    /// heartbeat was credited, none otherwise.
    pub fn allowance(heartbeat_credited: bool) -> u64 {
        if heartbeat_credited { SLOTS_PER_EPOCH } else { 0 }
    }

    /// Spend one slot for a send. Refused when the slot is out of the
    /// allowance or already spent.
    pub fn spend(&mut self, machine: u64, epoch: u64, slot: u64, heartbeat_credited: bool) -> bool {
        if slot >= Self::allowance(heartbeat_credited) {
            return false;
        }
        self.spent.insert((machine, epoch, slot))
    }
}
