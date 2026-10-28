use borsh::BorshDeserialize;
use jmt::mock::MockTreeStore;
use jmt::{JellyfishMerkleTree, KeyHash, SimpleHasher};

use super::*;

/// The hasher 0002 §7.1 names: `jmt` with BLAKE3 in derive-key mode under `TOG/v1/jmt`.
struct TogHasher(blake3::Hasher);

impl SimpleHasher for TogHasher {
    fn new() -> Self {
        TogHasher(blake3::Hasher::new_derive_key("TOG/v1/jmt"))
    }
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    fn finalize(self) -> [u8; 32] {
        *self.0.finalize().as_bytes()
    }
}

/// `jmt`'s Borsh proof layout, to reduce its sibling nodes to hashes as a server does.
#[derive(BorshDeserialize)]
struct JmtProof {
    leaf: Option<ProofLeaf>,
    siblings: Vec<JmtNode>,
}

#[derive(BorshDeserialize)]
enum JmtNode {
    Null,
    Internal { left: Hash32, right: Hash32 },
    Leaf(ProofLeaf),
}

fn convert(proof: &jmt::proof::SparseMerkleProof<TogHasher>) -> StateProof {
    let p = JmtProof::try_from_slice(&borsh::to_vec(proof).unwrap()).unwrap();
    let siblings = p
        .siblings
        .iter()
        .map(|n| match n {
            JmtNode::Null => EMPTY_SUBTREE,
            JmtNode::Internal { left, right } => internal_hash(left, right),
            JmtNode::Leaf(l) => leaf_hash(l),
        })
        .collect();
    StateProof { leaf: p.leaf, siblings }
}

/// A tree of `n` job-status entries, built by the `jmt` crate.
fn tree(n: u8) -> (MockTreeStore, Hash32, Vec<(Hash32, Vec<u8>)>) {
    let db = MockTreeStore::default();
    let entries: Vec<(Hash32, Vec<u8>)> = (0..n)
        .map(|i| {
            let status = JobStatus::Committed { worker: [i; 20], at: u64::from(i) };
            (key_hash(&items::job_status(&[i; 32])), borsh::to_vec(&status).unwrap())
        })
        .collect();
    let t = JellyfishMerkleTree::<_, TogHasher>::new(&db);
    let (root, batch) = t.put_value_set(entries.iter().map(|(k, v)| (KeyHash(*k), Some(v.clone()))), 0).unwrap();
    db.write_tree_update_batch(batch).unwrap();
    (db, root.0, entries)
}

#[test]
fn inclusion_matches_jmt() {
    let (db, root, entries) = tree(40);
    let t = JellyfishMerkleTree::<_, TogHasher>::new(&db);
    for (k, v) in &entries {
        let (value, proof) = t.get_with_proof(KeyHash(*k), 0).unwrap();
        assert_eq!(value.as_ref(), Some(v));
        let p = convert(&proof);
        assert_eq!(p.verify(&root, k, Some(v)), Ok(()));
        // The value decodes as the declared type.
        assert!(matches!(JobStatus::try_from_slice(v).unwrap(), JobStatus::Committed { .. }));
        // A different value or key fails.
        assert_eq!(p.verify(&root, k, Some(b"other")), Err(StateProofError::Mismatch));
        assert_eq!(p.verify(&root, k, None), Err(StateProofError::Mismatch));
        let mut bad_root = root;
        bad_root[0] ^= 1;
        assert_eq!(p.verify(&bad_root, k, Some(v)), Err(StateProofError::Root));
    }
}

#[test]
fn exclusion_matches_jmt() {
    let (db, root, _) = tree(40);
    let t = JellyfishMerkleTree::<_, TogHasher>::new(&db);
    for i in 100..140u8 {
        let k = key_hash(&items::job_status(&[i; 32]));
        let (value, proof) = t.get_with_proof(KeyHash(k), 0).unwrap();
        assert_eq!(value, None);
        // jmt itself accepts it, and so does the spec's verifier on the reduced proof.
        proof.verify_nonexistence(jmt::RootHash(root), KeyHash(k)).unwrap();
        let p = convert(&proof);
        assert_eq!(p.verify(&root, &k, None), Ok(()));
        assert_eq!(p.verify(&root, &k, Some(b"x")), Err(StateProofError::Mismatch));
    }
}

#[test]
fn tampered_siblings_fail() {
    let (db, root, entries) = tree(8);
    let t = JellyfishMerkleTree::<_, TogHasher>::new(&db);
    let (k, v) = &entries[3];
    let mut p = convert(&t.get_with_proof(KeyHash(*k), 0).unwrap().1);
    assert!(!p.siblings.is_empty());
    p.siblings[0][0] ^= 1;
    assert_eq!(p.verify(&root, k, Some(v)), Err(StateProofError::Root));
    p.siblings = vec![[0; 32]; 257];
    assert_eq!(p.verify(&root, k, Some(v)), Err(StateProofError::TooDeep(257)));
}

#[test]
fn empty_tree() {
    let p = StateProof { leaf: None, siblings: vec![] };
    assert_eq!(p.verify(&EMPTY_SUBTREE, &[7; 32], None), Ok(()));
}

#[test]
fn storage_keys() {
    let k = items::worker_jobs(&[1; 20]);
    assert_eq!(&k[..32], blake3::hash(b"compute_market").as_bytes());
    assert_eq!(&k[32..64], blake3::hash(b"worker_jobs").as_bytes());
    assert_eq!(&k[64..], blake3::hash(&[1; 20]).as_bytes());
    // A StorageValue hashes the empty borsh of `()`.
    assert_eq!(&items::threshold_epochs()[64..], blake3::hash(b"").as_bytes());
    assert_ne!(items::job(&[1; 32]), items::job_status(&[1; 32]));
    // A multi-key map hashes the borsh of the key tuple.
    let mut tuple = vec![2; 32];
    tuple.push(1);
    assert_eq!(&items::job_deals(&[2; 32], DealRole::Checkpoints)[64..], blake3::hash(&tuple).as_bytes());
    let a = items::account(&[3; 20]);
    assert_eq!(
        (&a[..32], &a[32..64]),
        (&blake3::hash(b"balances").as_bytes()[..], &blake3::hash(b"accounts").as_bytes()[..])
    );
    let acct = Account { nonce: 1, free: 2, reserved: 3 };
    let bytes = borsh::to_vec(&acct).unwrap();
    assert_eq!(bytes.len(), 8 + 16 + 16);
    assert_eq!(Account::try_from_slice(&bytes).unwrap(), acct);
}

#[test]
fn job_status_borsh_indices() {
    assert_eq!(borsh::to_vec(&JobStatus::Unassigned).unwrap(), vec![0]);
    let t = JobStatus::Terminal { outcome: JobOutcome::Refunded, at: 1 };
    assert_eq!(borsh::to_vec(&t).unwrap()[..2], [7, 3]);
    let v = JobStatus::Verifying { worker: [0; 20], sampled_at: 0, segments: vec![(1, VerifyStage::Audit)] };
    assert_eq!(borsh::to_vec(&v).unwrap()[0], 4);
}

#[test]
fn verifier_state_layouts() {
    assert_eq!(borsh::to_vec(&JobEnd::Completed { last: 3 }).unwrap(), [0, 3, 0, 0, 0]);
    assert_eq!(borsh::to_vec(&JobEnd::Fault { segment: 2 }).unwrap(), [1, 2, 0, 0, 0]);
    let r = KeyRecord { key: [7; 32], at: 9, reveal_deadline: Some(39) };
    let b = borsh::to_vec(&r).unwrap();
    assert_eq!(
        (&b[..32], &b[32..40], b[40], &b[41..]),
        (&[7; 32][..], &9u64.to_le_bytes()[..], 1, &39u64.to_le_bytes()[..])
    );
    assert_ne!(items::checkpoint(&[1; 32], 0), items::released_key(&[1; 32], 0));
    assert_eq!(items::lease_rate(&[1; 32]), storage_key("compute_market", "lease_rate", &[1; 32]));
    assert_eq!(items::wu_weights(), storage_key("compute_market", "wu_weights", &[]));
    assert_eq!(items::era_price(3), storage_key("compute_market", "era_prices", &3u32.to_le_bytes()));
    assert_eq!(items::era_prices_count(), storage_key("compute_market", "era_prices_count", &[]));
    assert_eq!(items::enclave_key(&[2; 32]), storage_key("hardware_registry", "enclave_keys", &[2; 32]));
    assert_eq!(items::closing_channels(9), storage_key("storage", "closing_channels", &9u64.to_le_bytes()));
    assert_eq!(items::locator_reports(&[1; 32]), storage_key("compute_market", "locator_reports", &[1; 32]));
    assert_eq!(borsh::to_vec(&JobOutcome::SenderFault).unwrap(), [4]);
}

#[test]
fn channel_layout() {
    use crate::channel::{Channel, ChannelId};
    use crate::job::RetentionClass;
    use crate::por::StorageWorkerId;
    let c = Channel {
        payer: [1; 20],
        payee: [2; 20],
        deposit: 5,
        closing: Some((3, 40)),
        holder: StorageWorkerId([3; 20]),
        prices: [1 << 30, 3, 0],
        opened: 9,
    };
    let b = borsh::to_vec(&c).unwrap();
    assert_eq!(b.len(), 20 + 20 + 16 + 1 + 16 + 8 + 20 + 3 * 16 + 8);
    assert_eq!(&b[81..101], &[3; 20]);
    // ⌈price × bytes / 2^30⌉, by the deal's class.
    assert_eq!(c.price(RetentionClass::Hot, 5), 5);
    assert_eq!(c.price(RetentionClass::ChallengeWindow, 1), 1);
    assert_eq!(c.price(RetentionClass::LongTerm, 1 << 30), 0);
    let k = items::payer_channels(&[1; 20], &StorageWorkerId([3; 20]));
    assert_eq!(k, storage_key("storage", "payer_channels", &[[1u8; 20], [3; 20]].concat()));
    assert_eq!((&b[..20], &b[20..40], &b[40..56], b[56]), (&[1; 20][..], &[2; 20][..], &5u128.to_le_bytes()[..], 1));
    assert_eq!(items::channel(&ChannelId(7)), storage_key("storage", "channels", &7u64.to_le_bytes()));
    let w = StorageWorkerId([3; 20]);
    assert_eq!(items::storage_worker(&w), storage_key("storage_registry", "workers", &[3; 20]));
}

#[test]
fn booking_layout_and_gpu0() {
    let b = Booking { cores: 8, ram_bytes: 1, scratch_bytes: 2, gpus: GpuBooking::Whole(vec![2, 5]) };
    let bytes = borsh::to_vec(&b).unwrap();
    assert_eq!(&bytes[20..], [1, 2, 0, 0, 0, 2, 5]);
    assert_eq!(b.gpu0(), Some(2));
    let mig = Booking { gpus: GpuBooking::Mig { gpu: 3, eighths: 2 }, ..b.clone() };
    assert_eq!((borsh::to_vec(&mig).unwrap()[20..].to_vec(), mig.gpu0()), (vec![2, 3, 2], Some(3)));
    assert_eq!(Booking { gpus: GpuBooking::None, ..b }.gpu0(), None);
    assert_eq!(items::lease(&[1; 32]), storage_key("compute_market", "leases", &[1; 32]));
}

#[test]
fn draw_stalls_layout_and_key() {
    use crate::sortition::DrawKind;
    let v = DrawStalls {
        stalls: vec![([1; 20], crate::job::DealId(9))],
        extended: true,
        opened: vec![(crate::job::DealId(9), 4, 2)],
        failed: vec![crate::job::DealId(9)],
    };
    let b = borsh::to_vec(&v).unwrap();
    let opened = [&1u32.to_le_bytes()[..], &9u64.to_le_bytes(), &4u64.to_le_bytes(), &2u16.to_le_bytes()].concat();
    let failed = [&1u32.to_le_bytes()[..], &9u64.to_le_bytes()].concat();
    assert_eq!(b, [&1u32.to_le_bytes()[..], &[1; 20], &9u64.to_le_bytes(), &[1], &opened, &failed].concat());
    let k = items::stalls(&[2; 32], 3, DrawKind::Verify { draw: 1 });
    assert_eq!(
        k,
        storage_key(
            "compute_market",
            "stalls",
            &borsh::to_vec(&([2u8; 32], 3u32, DrawKind::Verify { draw: 1 })).unwrap()
        )
    );
    assert_ne!(k, items::draw(&[2; 32], 3, DrawKind::Verify { draw: 1 }));
}

#[test]
fn index_and_progress_items_are_distinct() {
    use crate::sortition::DrawKind;
    let j = [7u8; 32];
    let d = crate::job::DealId(3);
    let keys = [
        items::job_ids(),
        items::job_progress(&j),
        items::segment_progress(&j, 1),
        items::round_votes(&j, 1, DrawKind::Jury { round: 0 }),
        items::job_challenge(&j, 1),
        items::dispute_ids(),
        items::dispute_progress(&j, 1),
        items::dispute(&j, 1),
        items::storage_missed(),
        items::i_sched(),
        items::deal_ids(),
        items::storage_counters(),
        items::slot_lock(&d, 2),
        items::suspects(),
        items::channel_ids(),
        items::challenge_ids(),
        items::encrypted_heights(),
        items::release_queue(),
    ];
    let set: alloc::collections::BTreeSet<_> = keys.iter().collect();
    assert_eq!(set.len(), keys.len());
    let enc = borsh::to_vec(&(d, 2u16)).unwrap();
    assert_eq!(items::slot_lock(&d, 2), storage_key("storage", "slot_locks", &enc));
    assert_eq!(items::i_sched(), storage_key("storage_registry", "i_sched", &[]));
    assert_eq!(
        items::round_votes(&j, 1, DrawKind::Jury { round: 0 })[..64],
        storage_key("compute_market", "rounds", &[])[..64]
    );
}

#[test]
fn emission_items_are_distinct() {
    let keys = [
        items::total_supply(),
        items::treasury(),
        items::era_points(4),
        items::era_fees(),
        items::unavailable(&[1; 20]),
        items::validator_jailed(&[1; 20]),
        items::era_bonus(4, 0),
        items::era_bonus_count(4),
        items::era_set(4),
        items::elected(4),
    ];
    let set: alloc::collections::BTreeSet<_> = keys.iter().collect();
    assert_eq!(set.len(), keys.len());
}
