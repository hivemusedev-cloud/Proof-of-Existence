//! poe-zk — the proof layer (BUILD_FLOW Step 5).
//!
//! A FRI-STARK over **Goldilocks**, via Plonky3 (`p3-uni-stark`,
//! `HidingFriPcs` — the hiding variant, so commitments are randomized and
//! the proofs are zero-knowledge about the witness items), carrying the
//! six bindings the kernel leaves to proofs:
//!
//! 1. a **join** bound to its root admission,
//! 2. a **transfer** bound to its slot and birth epoch,
//! 3. an **input vesting lock** open,
//! 4. each **offline show** on its coin's line at the input's challenge,
//! 5. **message tag / slot** ownership,
//! 6. **contract-version execution** correctness.
//!
//! All six share one shape — *a private list of items folds, item by item,
//! into an accumulator whose final value is public, while a counter
//! column walks a public start to a public end* — so one AIR carries all
//! six, parameterized per kind:
//!
//! * `acc` starts (row 0) at `fold(seed, item_0)` with `fold(a, x) =
//!   a·31 + x`, and each later real row folds its own item in; padding
//!   rows (selector `real = 0`, monotone) freeze both columns. The last
//!   row's `acc` must equal the public `root`: the prover knows a list
//!   that folds to the root, and the list itself never leaves the proof.
//! * `check` starts at the public `check_start` and steps by the kind's
//!   delta on every real row, ending at the public `check_end` — the
//!   counter relation (quota consumption, vesting fiftieths, execution
//!   steps). Field arithmetic cannot state "≥ 0"; what stops an
//!   over-consumption wrap is arithmetic itself: wrapping the Goldilocks
//!   modulus needs ~2^64 rows, and a trace is at most 2^32.
//!
//! Maturity, stated plainly (the Step 5 finish line also demands a
//! security review and target-phone benchmarks — both external to this
//! crate and still owed): the fold above is an *algebraic* accumulator.
//! Binding the public root to the node's actual `H` (or to a
//! Poseidon2-over-Goldilocks accumulator, the in-field hash this stack
//! would use) is the hardening step that marries this layer to
//! poe-kernel's data; the relation machinery — prove, verify, tamper
//! rejection — is what is built and tested here.

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_fri::{FriParameters, HidingFriPcs};
use p3_goldilocks::Goldilocks;
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::{Proof, StarkConfig, prove, verify};
use rand::SeedableRng;
use rand::rngs::SmallRng;

pub type Val = Goldilocks;
type Challenge = BinomialExtensionField<Val, 2>;
type ByteHash = Keccak256Hash;
type U64Hash = PaddingFreeSponge<p3_keccak::KeccakF, 25, 17, 4>;
type FieldHash = SerializingHasher<U64Hash>;
type Compress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
type ValMmcs = MerkleTreeHidingMmcs<
    [Val; p3_keccak::VECTOR_LEN],
    [u64; p3_keccak::VECTOR_LEN],
    FieldHash,
    Compress,
    SmallRng,
    4,
    4,
>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Dft = Radix2DitParallel<Val>;
type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, SmallRng>;
type Challenger = SerializingChallenger64<Val, HashChallenger<u8, ByteHash, 32>>;
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;
pub type BindingProof = Proof<Config>;

const FOLD: u64 = 31;
const COL_ACC: usize = 0;
const COL_ITEM: usize = 1;
const COL_CHECK: usize = 2;
const COL_REAL: usize = 3;
const WIDTH: usize = 4;

/// The six kernel bindings. Each kind fixes the counter's step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingKind {
    /// Join beside its root admission: the counter consumes quota, one
    /// per admitted item.
    JoinAdmission,
    /// Transfer on its slot and at its birth epoch: the counter is the
    /// slot itself, constant across the fold.
    TransferSlotEpoch,
    /// A vesting lock opens: the counter counts the lock's fiftieths
    /// down to zero.
    VestingLockOpen,
    /// An offline show on its coin's line at the input's challenge: the
    /// counter carries the challenge, constant.
    OfflineShowLine,
    /// A message's tag and slot are its sender's: the counter carries
    /// the slot, constant.
    MessageTagSlot,
    /// A contract version executes: the counter counts executed steps
    /// up from zero.
    ContractVersionExec,
}

impl BindingKind {
    /// The counter step per real row, as a field element (u64 form).
    fn delta_mod(self) -> u64 {
        match self {
            BindingKind::JoinAdmission | BindingKind::VestingLockOpen => {
                // -1 in the Goldilocks field.
                0xFFFF_FFFF_0000_0000 // p - 1, p = 2^64 - 2^32 + 1
            }
            BindingKind::ContractVersionExec => 1,
            _ => 0,
        }
    }
}

/// A binding statement: the private `items`, the accumulator `seed`, and
/// the counter's public start. The prover derives the public `root` and
/// `check_end`; the verifier is handed all four as public inputs.
pub struct Binding {
    pub kind: BindingKind,
    pub items: Vec<u64>,
    pub seed: u64,
    pub check_start: u64,
}

/// Public inputs layout: `[seed, root, check_start, check_end]`.
pub type PublicInputs = [u64; 4];

pub struct BindingAir {
    delta_mod: u64,
}

impl<F> BaseAir<F> for BindingAir {
    fn width(&self) -> usize {
        WIDTH
    }
}

impl<AB: AirBuilderWithPublicValues> Air<AB> for BindingAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let pis = builder.public_values();
        let seed: AB::Expr = pis[0].into();
        let root: AB::Expr = pis[1].into();
        let check_start: AB::Expr = pis[2].into();
        let check_end: AB::Expr = pis[3].into();
        let local = main.row_slice(0).expect("non-empty trace");
        let next = main.row_slice(1).expect("trace of at least 2 rows");
        let fold_m1 = AB::F::from_u64(FOLD - 1);
        let delta = AB::F::from_u64(self.delta_mod);

        // The selector is boolean, in every row.
        builder.assert_eq(local[COL_REAL] * local[COL_REAL], local[COL_REAL]);

        let mut first = builder.when_first_row();
        first.assert_eq(local[COL_REAL], AB::Expr::ONE);
        // Row 0 is the state after consuming item 0.
        first.assert_eq(
            local[COL_ACC],
            seed * AB::F::from_u64(FOLD) + local[COL_ITEM],
        );
        first.assert_eq(local[COL_CHECK], check_start + delta);

        let mut last = builder.when_last_row();
        last.assert_eq(local[COL_ACC], root);
        last.assert_eq(local[COL_CHECK], check_end);

        let mut trans = builder.when_transition();
        // Once padding, always padding.
        trans.assert_eq(next[COL_REAL] * local[COL_REAL], next[COL_REAL]);
        // The next row folds its item in iff it is real.
        trans.assert_eq(
            next[COL_ACC],
            local[COL_ACC] + next[COL_REAL] * (local[COL_ACC] * fold_m1 + next[COL_ITEM]),
        );
        trans.assert_eq(next[COL_CHECK], local[COL_CHECK] + next[COL_REAL] * delta);
    }
}

fn build_config() -> Config {
    let byte_hash = ByteHash {};
    let u64_hash = U64Hash::new(p3_keccak::KeccakF {});
    let field_hash = FieldHash::new(u64_hash);
    let compress = Compress::new(u64_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress, SmallRng::seed_from_u64(1));
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        num_queries: 100,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(
        Dft::default(),
        val_mmcs,
        fri_params,
        4,
        SmallRng::seed_from_u64(1),
    );
    let challenger = Challenger::from_hasher(vec![], byte_hash);
    Config::new(pcs, challenger)
}

fn fold_acc(seed: u64, items: &[u64]) -> u64 {
    let p: u128 = 0xFFFF_FFFF_0000_0001; // Goldilocks modulus
    let mut acc = seed as u128;
    for &x in items {
        acc = (acc * FOLD as u128 + x as u128) % p;
    }
    acc as u64
}

/// Prove a binding. Returns the proof and its public inputs; the caller
/// (the kernel side) checks `pis[1]` (the root) and `pis[3]` (the counter
/// end) against its own records — that comparison is the binding.
pub fn prove_binding(b: &Binding) -> Result<(BindingProof, PublicInputs), String> {
    if b.items.is_empty() {
        return Err("a binding needs at least one item".into());
    }
    let kind = b.kind;
    let root = fold_acc(b.seed, &b.items);
    let delta = kind.delta_mod();
    let p: u128 = 0xFFFF_FFFF_0000_0001;
    let check_end = if delta == 0 {
        b.check_start
    } else if delta == 1 {
        (b.check_start as u128 + b.items.len() as u128) as u64
    } else {
        // delta = p - 1: subtract the item count.
        ((b.check_start as u128 + p - (b.items.len() as u128 % p)) % p) as u64
    };

    let rows = (b.items.len().max(2)).next_power_of_two().max(8);
    let mut values = vec![Val::ZERO; rows * WIDTH];
    let mut acc = b.seed;
    let mut check = b.check_start;
    let delta_u = kind.delta_mod();
    for i in 0..rows {
        let real = i < b.items.len();
        if real {
            acc = fold_acc(acc, &[b.items[i]]);
            check = if delta_u == 0 {
                check
            } else if delta_u == 1 {
                check + 1
            } else {
                // field subtraction of 1, in u64 space via the modulus
                if check == 0 { 0xFFFF_FFFF_0000_0000 } else { check - 1 }
            };
        }
        let row = &mut values[i * WIDTH..(i + 1) * WIDTH];
        row[COL_ACC] = Val::from_u64(acc);
        row[COL_ITEM] = Val::from_u64(if real { b.items[i] } else { 0 });
        row[COL_CHECK] = Val::from_u64(check);
        row[COL_REAL] = if real { Val::ONE } else { Val::ZERO };
    }
    let trace = RowMajorMatrix::new(values, WIDTH);
    let pis_u = [b.seed, root, b.check_start, check_end];
    let pis: Vec<Val> = pis_u.iter().map(|&v| Val::from_u64(v)).collect();
    let config = build_config();
    let air = BindingAir { delta_mod: kind.delta_mod() };
    let proof = prove(&config, &air, trace, &pis);
    Ok((proof, pis_u))
}

/// Verify a binding proof against its kind and public inputs.
pub fn verify_binding(
    kind: BindingKind,
    proof: &BindingProof,
    pis: &PublicInputs,
) -> Result<(), String> {
    let config = build_config();
    let air = BindingAir { delta_mod: kind.delta_mod() };
    let pis_v: Vec<Val> = pis.iter().map(|&v| Val::from_u64(v)).collect();
    verify(&config, &air, proof, &pis_v).map_err(|e| format!("{e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(kind: BindingKind) -> Binding {
        Binding {
            kind,
            items: vec![101, 202, 303, 404, 505],
            seed: 7,
            check_start: match kind {
                BindingKind::JoinAdmission => 5,     // quota of 5, all consumed
                BindingKind::VestingLockOpen => 5,   // 5 fiftieths, all opened
                BindingKind::ContractVersionExec => 0, // steps count up
                _ => 42,                             // a constant carrier
            },
        }
    }

    #[test]
    fn all_six_bindings_prove_and_verify() {
        for kind in [
            BindingKind::JoinAdmission,
            BindingKind::TransferSlotEpoch,
            BindingKind::VestingLockOpen,
            BindingKind::OfflineShowLine,
            BindingKind::MessageTagSlot,
            BindingKind::ContractVersionExec,
        ] {
            let (proof, pis) = prove_binding(&sample(kind)).expect("prove");
            verify_binding(kind, &proof, &pis).unwrap_or_else(|e| {
                panic!("{kind:?} must verify: {e:?}");
            });
        }
    }

    #[test]
    fn wrong_public_inputs_are_rejected() {
        let (proof, pis) = prove_binding(&sample(BindingKind::TransferSlotEpoch)).unwrap();
        // A different accumulator root.
        let mut bad = pis;
        bad[1] += 1;
        assert!(verify_binding(BindingKind::TransferSlotEpoch, &proof, &bad).is_err());
        // A different counter end.
        let mut bad2 = pis;
        bad2[3] += 1;
        assert!(verify_binding(BindingKind::TransferSlotEpoch, &proof, &bad2).is_err());
        // A different seed.
        let mut bad3 = pis;
        bad3[0] += 1;
        assert!(verify_binding(BindingKind::TransferSlotEpoch, &proof, &bad3).is_err());
        // The wrong kind (different counter step) rejects the same proof.
        assert!(verify_binding(BindingKind::JoinAdmission, &proof, &pis).is_err());
    }

    #[test]
    fn vesting_counter_must_reach_zero() {
        // 5 items against a lock of 5 fiftieths: ends at 0, verifies.
        let (proof, pis) = prove_binding(&sample(BindingKind::VestingLockOpen)).unwrap();
        assert_eq!(pis[3], 0);
        verify_binding(BindingKind::VestingLockOpen, &proof, &pis).unwrap();
        // Claiming the lock opened after only part of the fold (root of a
        // prefix, end 2) is a different statement; the full proof does not
        // verify against it.
        let mut bad = pis;
        bad[3] = 2;
        assert!(verify_binding(BindingKind::VestingLockOpen, &proof, &bad).is_err());
    }
}
