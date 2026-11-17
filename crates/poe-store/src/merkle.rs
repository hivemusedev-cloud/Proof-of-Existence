//! The Merkle companion root — light-duty protocol addition #2
//! (POE_LIGHT_DUTY_DESIGN.md §6).
//!
//! The store's state root is a chained flat hash: it binds the
//! state as a whole but yields no per-note path, while the Manual
//! assumes a light node keeps "the witness paths of their
//! commitments" — a Merkle path from a note to the epoch's
//! committed root. This module is the companion: at each close the
//! node also computes a Merkle root over three sorted sections of
//! the ledger —
//!
//! * **births**: the live note set, one leaf per live note, keyed
//!   by the note's commitment;
//! * **deaths**: the spent nullifiers, one leaf per nullifier,
//!   keyed by the nullifier itself;
//! * **machines**: the machine registry, one leaf per machine.
//!
//! The companion root is `H("merkle-companion", births_root,
//! deaths_root, machines_root)` and is named in the epoch's
//! finality certificate beside `state_root` (the state root's own
//! formula is unchanged). A full node answers a note query with
//! the note and its proofs; the light device checks them against
//! the companion root in its verified certificate:
//!
//! * the note is **in** the births section (an inclusion path);
//! * its nullifier is **absent** from the deaths section — the
//!   sorted-leaf construction proves absence by exhibiting the
//!   two neighbouring leaves the nullifier would sit between.
//!
//! A note is live iff both hold — the design note's rule, checked
//! from evidence. A death is shown the other way: the nullifier's
//! inclusion path in the deaths section.
//!
//! Construction notes: leaves within a section are sorted by key
//! (ties by leaf bytes; exact duplicate leaves are folded to one),
//! internal nodes are `H("merkle-node", left, right)`, an odd node
//! at a level pairs with itself, a single-leaf section's root is
//! the leaf, and an empty section's root is `H("merkle-empty")`.
//! Proofs carry the section's leaf count so a verifier rebuilds
//! the exact level shapes.

use poe_crypto::hash::{h, Part, H512};
use poe_kernel::ledger::{alive_at, Ledger, Note};

/// The root of an empty section.
pub fn empty_root() -> H512 {
    h("merkle-empty", &[])
}

fn node_hash(left: &H512, right: &H512) -> H512 {
    h("merkle-node", &[Part::Bytes(left), Part::Bytes(right)])
}

/// A note's leaf in the births section: a hash of the whole note,
/// so the path binds every field, not only the commitment.
pub fn note_leaf(n: &Note) -> H512 {
    h(
        "merkle-note",
        &[
            Part::Nat(n.cm),
            Part::Nat(n.nf),
            Part::Nat(n.asset),
            Part::Nat(n.value),
            Part::Nat(n.born),
        ],
    )
}

/// A nullifier's leaf in the deaths section.
pub fn death_leaf(nf: u64) -> H512 {
    h("merkle-death", &[Part::Nat(nf)])
}

/// A machine's leaf in the registry section.
pub fn machine_leaf(m: u64) -> H512 {
    h("merkle-machine", &[Part::Nat(m)])
}

/// A Merkle inclusion path: the leaf's index, the section's leaf
/// count, and the sibling hashes from the leaf level upward
/// (only levels where the leaf's node has a distinct partner
/// contribute a sibling; an odd level's last node pairs with
/// itself and contributes none).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InclusionProof {
    pub index: u64,
    pub leaf_count: u64,
    pub siblings: Vec<H512>,
}

/// An absence proof over a sorted section: the leaves the key
/// would sit between, each with its inclusion path. `pred` is the
/// greatest present key below the absent one, `succ` the least
/// present key above it; either is `None` at the section's edge,
/// and both are `None` only for an empty section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbsenceProof {
    pub leaf_count: u64,
    pub pred: Option<(u64, InclusionProof)>,
    pub succ: Option<(u64, InclusionProof)>,
}

/// A sorted Merkle tree over `(key, leaf)` entries.
pub struct SortedTree {
    keys: Vec<u64>,
    levels: Vec<Vec<H512>>,
}

impl SortedTree {
    /// Build from `(key, leaf)` entries in any order. Entries are
    /// sorted by `(key, leaf)` and exact duplicates folded.
    pub fn build(mut entries: Vec<(u64, H512)>) -> SortedTree {
        entries.sort();
        entries.dedup();
        let keys: Vec<u64> = entries.iter().map(|(k, _)| *k).collect();
        let mut level: Vec<H512> = entries.into_iter().map(|(_, l)| l).collect();
        let mut levels = vec![level.clone()];
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for i in (0..level.len()).step_by(2) {
                let right = if i + 1 < level.len() { level[i + 1] } else { level[i] };
                next.push(node_hash(&level[i], &right));
            }
            level = next;
            levels.push(level.clone());
        }
        SortedTree { keys, levels }
    }

    pub fn root(&self) -> H512 {
        match self.levels[0].len() {
            0 => empty_root(),
            _ => *self.levels.last().expect("levels").last().expect("root"),
        }
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The position of `key`'s first entry, if present.
    pub fn position(&self, key: u64) -> Option<usize> {
        self.keys.iter().position(|k| *k == key)
    }

    /// The position of the exact `(key, leaf)` entry, if present.
    /// (Two live notes may share a commitment key with different
    /// leaves; a proof must name its own note's entry.)
    pub fn position_of(&self, key: u64, leaf: &H512) -> Option<usize> {
        (0..self.keys.len()).find(|&i| {
            self.keys[i] == key && self.levels[0][i] == *leaf
        })
    }

    /// An inclusion proof for the entry at `index`.
    pub fn inclusion(&self, index: usize) -> Option<InclusionProof> {
        if index >= self.keys.len() {
            return None;
        }
        let mut siblings = Vec::new();
        let mut idx = index;
        for level in &self.levels[..self.levels.len() - 1] {
            if idx % 2 == 1 {
                siblings.push(level[idx - 1]);
            } else if idx + 1 < level.len() {
                siblings.push(level[idx + 1]);
            }
            idx /= 2;
        }
        Some(InclusionProof {
            index: index as u64,
            leaf_count: self.keys.len() as u64,
            siblings,
        })
    }

    /// An absence proof for `key`, or `None` when the key is
    /// present (absence is then false, and inclusion is the proof
    /// to give).
    pub fn absence(&self, key: u64) -> Option<AbsenceProof> {
        if self.position(key).is_some() {
            return None;
        }
        let at = self.keys.partition_point(|k| *k < key);
        let pred = if at > 0 {
            Some((self.keys[at - 1], self.inclusion(at - 1)?))
        } else {
            None
        };
        let succ = if at < self.keys.len() {
            Some((self.keys[at], self.inclusion(at)?))
        } else {
            None
        };
        Some(AbsenceProof { leaf_count: self.keys.len() as u64, pred, succ })
    }
}

/// Verify an inclusion path against a section root.
pub fn verify_inclusion(root: &H512, leaf: &H512, proof: &InclusionProof) -> bool {
    if proof.leaf_count == 0 || proof.index >= proof.leaf_count {
        return false;
    }
    if proof.leaf_count == 1 {
        return proof.siblings.is_empty() && leaf == root;
    }
    let mut cur = *leaf;
    let mut idx = proof.index;
    let mut count = proof.leaf_count;
    let mut sibs = proof.siblings.iter();
    while count > 1 {
        if idx % 2 == 1 {
            let Some(s) = sibs.next() else { return false };
            cur = node_hash(s, &cur);
        } else if idx + 1 < count {
            let Some(s) = sibs.next() else { return false };
            cur = node_hash(&cur, s);
        } else {
            cur = node_hash(&cur, &cur);
        }
        idx /= 2;
        count = count.div_ceil(2);
    }
    sibs.next().is_none() && cur == *root
}

/// Verify an absence proof against a section root. `leaf_of`
/// recomputes a present key's leaf (the section's leaf function),
/// binding each neighbour's key to the leaf its path proves.
pub fn verify_absence(
    root: &H512,
    key: u64,
    proof: &AbsenceProof,
    leaf_of: impl Fn(u64) -> H512,
) -> bool {
    if proof.leaf_count == 0 {
        return proof.pred.is_none() && proof.succ.is_none() && *root == empty_root();
    }
    let check = |entry: &(u64, InclusionProof)| -> bool {
        entry.1.leaf_count == proof.leaf_count
            && verify_inclusion(root, &leaf_of(entry.0), &entry.1)
    };
    match (&proof.pred, &proof.succ) {
        (Some(p), Some(s)) => {
            p.0 < key
                && key < s.0
                && s.1.index == p.1.index + 1
                && check(p)
                && check(s)
        }
        (None, Some(s)) => s.1.index == 0 && key < s.0 && check(s),
        (Some(p), None) => {
            p.1.index == proof.leaf_count - 1 && p.0 < key && check(p)
        }
        (None, None) => false,
    }
}

/// The three sections of a ledger's companion tree, with their
/// composed root.
pub struct CompanionSections {
    pub births: SortedTree,
    pub deaths: SortedTree,
    pub machines: SortedTree,
    pub births_root: H512,
    pub deaths_root: H512,
    pub machines_root: H512,
    pub root: H512,
}

/// Compose a companion root from its section roots.
pub fn companion_of(births_root: &H512, deaths_root: &H512, machines_root: &H512) -> H512 {
    h(
        "merkle-companion",
        &[
            Part::Bytes(births_root),
            Part::Bytes(deaths_root),
            Part::Bytes(machines_root),
        ],
    )
}

/// Build a ledger's companion sections: the live notes (born, not
/// spent, inside their window at the ledger's own clock), every
/// spent nullifier, and the machine registry.
pub fn companion_sections(ledger: &Ledger) -> CompanionSections {
    let births = SortedTree::build(
        ledger
            .births
            .iter()
            .filter(|n| alive_at(ledger.now, n) && !ledger.deaths.contains(&n.nf))
            .map(|n| (n.cm, note_leaf(n)))
            .collect(),
    );
    let deaths = SortedTree::build(ledger.deaths.iter().map(|nf| (*nf, death_leaf(*nf))).collect());
    let machines =
        SortedTree::build(ledger.machines.iter().map(|m| (*m, machine_leaf(*m))).collect());
    let births_root = births.root();
    let deaths_root = deaths.root();
    let machines_root = machines.root();
    let root = companion_of(&births_root, &deaths_root, &machines_root);
    CompanionSections { births, deaths, machines, births_root, deaths_root, machines_root, root }
}

/// The ledger's companion root, as named in its epoch's
/// certificate.
pub fn companion_root(ledger: &Ledger) -> H512 {
    companion_sections(ledger).root
}

/// A note's liveness proof: the note itself, its inclusion path in
/// the births section, and its nullifier's absence proof in the
/// deaths section, under the section roots they were taken from.
#[derive(Clone, Debug, PartialEq)]
pub struct NoteProof {
    pub note: Note,
    pub births_root: H512,
    pub deaths_root: H512,
    pub machines_root: H512,
    pub births: InclusionProof,
    pub deaths: AbsenceProof,
}

/// Prove the liveness of the live note with commitment `cm`, if
/// the ledger holds one.
pub fn prove_note(ledger: &Ledger, cm: u64) -> Option<NoteProof> {
    let note = *ledger
        .births
        .iter()
        .find(|n| n.cm == cm && alive_at(ledger.now, n) && !ledger.deaths.contains(&n.nf))?;
    let s = companion_sections(ledger);
    let idx = s.births.position_of(cm, &note_leaf(&note))?;
    Some(NoteProof {
        note,
        births_root: s.births_root,
        deaths_root: s.deaths_root,
        machines_root: s.machines_root,
        births: s.births.inclusion(idx)?,
        deaths: s.deaths.absence(note.nf)?,
    })
}

/// Verify a note proof against a companion root (the one named in
/// a verified certificate): the section roots must compose to it,
/// the note must be in the births section, and its nullifier must
/// be absent from the deaths section.
pub fn verify_note_proof(companion: &H512, proof: &NoteProof) -> bool {
    companion_of(&proof.births_root, &proof.deaths_root, &proof.machines_root) == *companion
        && verify_inclusion(&proof.births_root, &note_leaf(&proof.note), &proof.births)
        && verify_absence(&proof.deaths_root, proof.note.nf, &proof.deaths, death_leaf)
}

/// A death proof: a nullifier's inclusion path in the deaths
/// section, under the section roots it was taken from.
#[derive(Clone, Debug, PartialEq)]
pub struct DeathProof {
    pub nf: u64,
    pub births_root: H512,
    pub deaths_root: H512,
    pub machines_root: H512,
    pub deaths: InclusionProof,
}

/// Prove that nullifier `nf` stands in the ledger's deaths.
pub fn prove_death(ledger: &Ledger, nf: u64) -> Option<DeathProof> {
    let s = companion_sections(ledger);
    let idx = s.deaths.position(nf)?;
    Some(DeathProof {
        nf,
        births_root: s.births_root,
        deaths_root: s.deaths_root,
        machines_root: s.machines_root,
        deaths: s.deaths.inclusion(idx)?,
    })
}

/// Verify a death proof against a companion root.
pub fn verify_death_proof(companion: &H512, proof: &DeathProof) -> bool {
    companion_of(&proof.births_root, &proof.deaths_root, &proof.machines_root) == *companion
        && verify_inclusion(&proof.deaths_root, &death_leaf(proof.nf), &proof.deaths)
}
