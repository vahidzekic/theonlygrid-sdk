use super::*;
use crate::eligibility::Region;
use crate::payload::{Encryption, PayloadKind};

fn payload(i: u8, size: u64) -> PayloadCommitment {
    PayloadCommitment {
        version: 1,
        root: [i; 32],
        size,
        piece_log2: 20,
        kind: PayloadKind::Checkpoint,
        oci_digest: None,
        encryption: Encryption::None,
    }
}

fn payloads(n: u8) -> Vec<PayloadCommitment> {
    (0..n).map(|i| payload(i, 100 + u64::from(i))).collect()
}

/// The root computed level by level over the whole padded tree.
fn naive_root(leaves: &[PayloadSetLeaf]) -> Hash32 {
    let z = empty_roots();
    let mut level: Vec<Hash32> = leaves.iter().map(PayloadSetLeaf::hash).collect();
    for zd in z.iter().take(SET_DEPTH) {
        if level.is_empty() {
            return z[SET_DEPTH];
        }
        level = level.chunks(2).map(|c| node(&c[0], c.get(1).unwrap_or(zd))).collect();
    }
    level[0]
}

#[test]
fn frontier_matches_the_full_tree() {
    let all = payloads(40);
    let mut f = SetFrontier::new();
    assert_eq!(f.set.root, naive_root(&[]));
    for n in 1..=all.len() {
        f.append(&all[n - 1..n]).unwrap();
        let leaves = PayloadSetLeaf::chain(0, &all[..n]).unwrap();
        assert_eq!(f.set.root, naive_root(&leaves), "count {n}");
        assert_eq!(f.set.count as usize, n);
        assert_eq!(f.set.total_size, leaves.iter().map(|l| l.size).sum::<u64>());
        assert_eq!(f.frontier.len(), bit_len(n as u32));
        // Canonical: entries at clear bits are the empty roots.
        let z = empty_roots();
        for (d, h) in f.frontier.iter().enumerate() {
            if (n as u32) >> d & 1 == 0 {
                assert_eq!(*h, z[d]);
            }
        }
    }
}

#[test]
fn batch_append_equals_single_appends() {
    let all = payloads(13);
    let mut one = SetFrontier::new();
    for p in &all {
        one.append(std::slice::from_ref(p)).unwrap();
    }
    let mut batch = SetFrontier::new();
    let first = batch.append(&all[..5]).unwrap();
    let rest = batch.append(&all[5..]).unwrap();
    assert_eq!(batch, one);
    assert_eq!(rest[0].offset, first.iter().map(|l| l.size).sum::<u64>());
}

#[test]
fn paths_open_every_leaf_and_nothing_else() {
    let all = payloads(11);
    let mut f = SetFrontier::new();
    let leaves = f.append(&all).unwrap();
    for (i, leaf) in leaves.iter().enumerate() {
        let p = path(&leaves, i as u32).unwrap();
        assert!(verify_path(&f.set, leaf, &p));
        assert!(!verify_path(&f.set, &PayloadSetLeaf { offset: leaf.offset + 1, ..*leaf }, &p));
        assert!(!verify_path(&f.set, leaf, &MerklePath { index: p.index ^ 1, ..p.clone() }));
    }
    assert!(path(&leaves, 11).is_none());
    // An index past the count is rejected even with a path through empty leaves.
    let empty = PayloadSetLeaf { root: [0; 32], offset: 0, size: 0 };
    let p = MerklePath { index: 11, siblings: path(&leaves, 10).unwrap().siblings };
    assert!(!verify_path(&f.set, &empty, &p));
    let short = MerklePath { index: 0, siblings: path(&leaves, 0).unwrap().siblings[..31].to_vec() };
    assert!(!verify_path(&f.set, &leaves[0], &short));
}

#[test]
fn append_errors_leave_the_set_unchanged() {
    let mut f = SetFrontier::new();
    f.append(&payloads(3)).unwrap();
    let before = f.clone();
    assert_eq!(f.append(&[payload(9, u64::MAX)]), Err(SetError::Full));
    assert_eq!(f, before);
    let mut bad = before.clone();
    bad.frontier.pop();
    assert_eq!(bad.append(&payloads(1)), Err(SetError::Frontier));
}

fn open(owner: DealOwner) -> OpenDealTx {
    OpenDealTx {
        owner,
        class: RetentionClass::ChallengeWindow,
        layout: Layout::Replicate { r: 3 },
        payloads: payloads(1),
        duration: None,
        max_cost: 1,
        segment: None,
        replay: None,
        regions: None,
    }
}

#[test]
fn open_deal_shape() {
    let job = DealOwner::Job { job_id: [1; 32], role: DealRole::Checkpoints };
    assert_eq!(open(job).check(), Ok(()));
    assert_eq!(OpenDealTx { payloads: vec![], ..open(job) }.check(), Err(DealTxError::PayloadCount));
    assert_eq!(
        OpenDealTx {
            payloads: payloads(0).into_iter().chain((0..=255).map(|i| payload(i, 1))).chain([payload(0, 1)]).collect(),
            ..open(job)
        }
        .check(),
        Err(DealTxError::PayloadCount)
    );
    assert_eq!(OpenDealTx { class: RetentionClass::LongTerm, ..open(job) }.check(), Err(DealTxError::Layout));
    let rs = Layout::ReedSolomon { k: 10, m: 4, shard_roots: [0; 32] };
    assert_eq!(OpenDealTx { class: RetentionClass::LongTerm, layout: rs, ..open(job) }.check(), Ok(()));
    assert_eq!(OpenDealTx { layout: rs, ..open(job) }.check(), Err(DealTxError::Layout));
    assert_eq!(OpenDealTx { duration: Some(10), ..open(job) }.check(), Err(DealTxError::Owner));
    assert_eq!(OpenDealTx { segment: Some(2), ..open(job) }.check(), Err(DealTxError::Segment));

    let dissent = DealOwner::Job { job_id: [1; 32], role: DealRole::Dissent };
    assert_eq!(open(dissent).check(), Err(DealTxError::Segment));
    assert_eq!(OpenDealTx { segment: Some(2), ..open(dissent) }.check(), Ok(()));

    let account = DealOwner::Account([2; 20]);
    let replay = Some(ReplayGuard { chain_id: 1, nonce: 0 });
    assert_eq!(open(account).check(), Err(DealTxError::Owner));
    assert_eq!(OpenDealTx { duration: Some(10), ..open(account) }.check(), Err(DealTxError::Owner));
    assert_eq!(OpenDealTx { duration: Some(10), replay, ..open(account) }.check(), Ok(()));
}

#[test]
fn deal_payloads_are_v1_commitments() {
    // §2.2: version 1, pieces of 1 to 4 MiB, in an open and in an append alike.
    let job = DealOwner::Job { job_id: [1; 32], role: DealRole::Checkpoints };
    let with = |f: fn(&mut PayloadCommitment)| {
        let mut p = payloads(2);
        f(&mut p[1]);
        p
    };
    let append =
        |payloads| AppendPayloadTx { deal: DealId(1), at_count: 1, payloads, max_cost: 1, segment: None, replay: None };
    for (p, ok) in [
        (with(|p| p.piece_log2 = 20), true),
        (with(|p| p.piece_log2 = 22), true),
        (with(|p| p.piece_log2 = 19), false),
        (with(|p| p.piece_log2 = 23), false),
        (with(|p| p.piece_log2 = 63), false),
        (with(|p| p.version = 2), false),
    ] {
        let want = if ok { Ok(()) } else { Err(DealTxError::Commitment) };
        assert_eq!(OpenDealTx { payloads: p.clone(), ..open(job) }.check(), want);
        assert_eq!(append(p).check(), want);
    }
}

#[test]
fn open_deal_leaves_start_at_zero() {
    let tx = OpenDealTx { payloads: payloads(3), ..open(DealOwner::Account([0; 20])) };
    let offsets: Vec<u64> = tx.leaves().unwrap().iter().map(|l| l.offset).collect();
    assert_eq!(offsets, [0, 100, 201]);
}

#[test]
fn borsh_layout() {
    assert_eq!(borsh::to_vec(&DealOwner::Account([7; 20])).unwrap()[0], 1);
    let job = borsh::to_vec(&DealOwner::Job { job_id: [7; 32], role: DealRole::Outputs }).unwrap();
    assert_eq!((job[0], job.len(), job[33]), (0, 34, 2));
    assert_eq!(borsh::to_vec(&Layout::Replicate { r: 3 }).unwrap(), [0, 3]);
    let leaf = PayloadSetLeaf { root: [1; 32], offset: 2, size: 3 };
    assert_eq!(borsh::to_vec(&leaf).unwrap().len(), 48);
}

#[test]
fn every_payload_is_charged_for_at_least_one_mib() {
    let mib = MIN_BILLED_PAYLOAD;
    assert_eq!(charged_bytes([]), Some(0));
    assert_eq!(charged_bytes([0, 1, mib - 1]), Some(3 * mib));
    assert_eq!(charged_bytes([mib, mib + 1, 5 * mib]), Some(7 * mib + 1));
    assert_eq!(charged_bytes([u64::MAX, 1]), None);
}

#[test]
fn a_whole_deal_is_billed_at_least_one_mib_a_leaf() {
    let mib = MIN_BILLED_PAYLOAD;
    let set = |count, total_size| PayloadSetRoot { root: [0; 32], count, total_size };
    assert_eq!(charged_set_bytes(&set(0, 0)), 0);
    assert_eq!(charged_set_bytes(&set(3, 10)), 3 * mib);
    assert_eq!(charged_set_bytes(&set(2, 5 * mib)), 5 * mib);
    assert_eq!(charged_set_bytes(&set(u32::MAX, u64::MAX)), u64::MAX);
}

#[test]
fn deal_charge_rounds_each_term_up() {
    let prices = StoragePrices { per_gib_hour: 1_000, place_per_gib: 3 };
    // One GiB, three replicas, one hour: 3 GiB·h at 1000 plus 3 GiB placed at 3.
    let stored = Layout::Replicate { r: 3 }.stored(1 << 30, 0);
    assert_eq!(deal_charge(stored, 1800, &prices), Some(3_000 + 9));
    // One byte: each term rounds up to 1 separately.
    assert_eq!(deal_charge(1, 1, &prices), Some(2));
    assert_eq!(deal_charge(0, 1800, &prices), Some(0));
    assert_eq!(deal_charge(u128::MAX, 2, &prices), None);
}

#[test]
fn reed_solomon_stores_padded_shards() {
    let rs = Layout::ReedSolomon { k: 10, m: 4, shard_roots: [0; 32] };
    // 1 byte pads to one 4 KiB row per shard.
    assert_eq!(rs.stored(1, 1), 14 * 4096);
    // The whole deal, not the new bytes, sets the shard size.
    assert_eq!(rs.stored(1, 10 * 4096 + 1), 14 * 2 * 4096);
}

#[test]
fn renewal_and_dispute_shapes() {
    let replay = ReplayGuard { chain_id: 1, nonce: 0 };
    let renew = RenewDealTx { deal: DealId(1), extra_blocks: 1, max_cost: 0, replay };
    assert_eq!(renew.check(), Ok(()));
    assert_eq!(RenewDealTx { extra_blocks: 0, ..renew }.check(), Err(DealTxError::ExtraBlocks));

    let dispute = |offsets: Vec<u64>| RetrievalDisputeTx { deal: DealId(1), slot: 0, offsets, max_bond: 0, replay };
    assert_eq!(dispute(vec![0, 4096]).check(), Ok(()));
    assert_eq!(dispute((0..16).collect()).check(), Ok(()));
    for bad in [vec![], (0..17).collect(), vec![5, 5], vec![9, 4]] {
        assert_eq!(dispute(bad).check(), Err(DealTxError::Offsets));
    }
}

#[test]
fn storage_deal_borsh_follows_spec_field_order() {
    let mut set = SetFrontier::new();
    set.append(&payloads(3)).unwrap();
    let deal = StorageDeal {
        id: DealId(7),
        owner: DealOwner::Account([1; 20]),
        payloads: set.set,
        frontier: set.frontier.clone(),
        class: RetentionClass::LongTerm,
        layout: Layout::Replicate { r: 3 },
        slots: vec![],
        price_per_gib_hour: 1,
        place_per_gib: 9,
        collateral_per_slot: 2,
        budget: 3,
        retrieval_allowance: 4,
        repair_reserve: 5,
        start: 6,
        end: DealEnd::At(8),
        state: DealState::Repairing { slots: vec![0b101] },
        external: vec![ExternalLocator::Arweave { tx_id: [9; 32] }],
        materialized: vec![],
        regions: None,
    };
    let bytes = borsh::to_vec(&deal).unwrap();
    assert_eq!(borsh::from_slice::<StorageDeal>(&bytes).unwrap(), deal);
    // `payloads ‖ frontier` encode exactly as the SetFrontier they came from.
    let head = 8 + borsh::to_vec(&deal.owner).unwrap().len();
    let set = borsh::to_vec(&set).unwrap();
    assert_eq!(&bytes[head..head + set.len()], &set[..]);
    assert_eq!(borsh::to_vec(&DealState::Lost).unwrap(), [6]);
    assert_eq!(borsh::to_vec(&SlotStatus::Released).unwrap(), [3]);
}

#[test]
fn encoding_borsh_and_shard_lookup() {
    let set = ShardSet {
        roots: [3; 32],
        size: 4096,
        slots: vec![2, 0, 1],
        encoder: 0,
        slashed: false,
        bad: vec![],
        missed: 0,
    };
    let enc = Encoding {
        encoder: Some(PendingEncoder { slot: 3, deadline: None }),
        current: Some(set.clone()),
        next: None,
        misses: 1,
    };
    let bytes = borsh::to_vec(&enc).unwrap();
    assert_eq!(&bytes[..4], [1, 3, 0, 0]);
    assert_eq!(borsh::from_slice::<Encoding>(&bytes).unwrap(), enc);
    assert_eq!(enc.shards_of(1), Some(&set));
    assert_eq!(enc.shards_of(3), None);
    assert_ne!(crate::state::items::encoding(&DealId(1)), crate::state::items::deal(&DealId(1)));
}

#[test]
fn egress_floors_by_network() {
    // 0004 §3.1 "Egress floors (exact)".
    let params = |cw, lt| StorageParams {
        kappa_gb: 1,
        b_chunk: 1,
        challenge_window_min_egress_bps: cw,
        long_term_min_egress_bps: lt,
    };
    let g = 1_000_000_000;
    for (net, cw, lt) in [(1, 10 * g, g), (2, g, g / 10)] {
        assert_eq!(StorageParams::egress_floors(net), (cw, lt));
        assert_eq!(StorageParams::default_egress(net), (cw, lt));
        assert!(params(cw, lt).meets_egress_floors(net));
        assert!(!params(cw - 1, lt).meets_egress_floors(net), "{net}");
        assert!(!params(cw, lt - 1).meets_egress_floors(net), "{net}");
    }
    for net in [0, 3, 0x7e57] {
        assert_eq!(StorageParams::default_egress(net), (g / 10, g / 100));
        assert!(params(1, 1).meets_egress_floors(net));
        assert!(!params(0, 1).meets_egress_floors(net));
        assert!(!params(1, 0).meets_egress_floors(net));
    }
    // The new field is the fourth in Borsh, after the ChallengeWindow floor.
    let bytes = borsh::to_vec(&params(7, 9)).unwrap();
    assert_eq!(&bytes[bytes.len() - 16..], [7u64.to_le_bytes(), 9u64.to_le_bytes()].concat());
}

#[test]
fn open_deal_regions_are_for_account_and_inputs_deals_only_ascending_and_at_most_sixteen() {
    let regions = |n: u8| Some((0..n).map(|i| Region([b'A' + i / 26, b'A' + i % 26])).collect::<Vec<_>>());
    let account = DealOwner::Account([2; 20]);
    let replay = Some(ReplayGuard { chain_id: 1, nonce: 0 });
    let acct = |r| OpenDealTx { duration: Some(10), replay, regions: r, ..open(account) };
    assert_eq!(acct(regions(1)).check(), Ok(()));
    assert_eq!(acct(regions(MAX_DEAL_REGIONS as u8)).check(), Ok(()));
    assert_eq!(acct(regions(MAX_DEAL_REGIONS as u8 + 1)).check(), Err(DealTxError::Regions));
    assert_eq!(acct(Some(vec![])).check(), Err(DealTxError::Regions));
    assert_eq!(acct(Some(vec![Region(*b"FR"), Region(*b"DE")])).check(), Err(DealTxError::Regions));
    assert_eq!(acct(Some(vec![Region(*b"DE"), Region(*b"DE")])).check(), Err(DealTxError::Regions));

    let inputs = DealOwner::Job { job_id: [1; 32], role: DealRole::Inputs };
    assert_eq!(OpenDealTx { regions: regions(2), ..open(inputs) }.check(), Ok(()));
    for role in [DealRole::Checkpoints, DealRole::Outputs, DealRole::Dissent] {
        let job = DealOwner::Job { job_id: [1; 32], role };
        let segment = (role == DealRole::Dissent).then_some(2);
        let tx = OpenDealTx { regions: regions(2), segment, ..open(job) };
        assert_eq!(tx.check(), Err(DealTxError::Regions), "{role:?}");
    }
}

#[test]
fn regions_are_the_last_borsh_field_of_open_deal() {
    let tx = open(DealOwner::Account([2; 20]));
    let with = OpenDealTx { regions: Some(vec![Region(*b"DE")]), ..tx.clone() };
    let (a, b) = (borsh::to_vec(&tx).unwrap(), borsh::to_vec(&with).unwrap());
    assert_eq!((a.last(), &b[..a.len() - 1]), (Some(&0), &a[..a.len() - 1]));
    assert_eq!(&b[a.len() - 1..], &[1, 1, 0, 0, 0, b'D', b'E']);
}

#[test]
fn a_set_tree_gives_every_path_one_built_alone_would() {
    // One leaf by one: every hash a path needs comes from the tree as the root does.
    for n in [1, 2, 3, 7, 8, 9, 33] {
        let mut f = SetFrontier::new();
        let leaves = f.append(&payloads(n)).unwrap();
        let tree = SetTree::new(&leaves);
        assert_eq!(tree.count(), usize::from(n));
        for (i, leaf) in leaves.iter().enumerate() {
            let p = tree.path(i as u32).unwrap();
            assert!(verify_path(&f.set, leaf, &p), "n {n} leaf {i}");
            assert_eq!(Some(p), path(&leaves, i as u32));
        }
        assert!(tree.path(n as u32).is_none());
    }
    assert!(SetTree::new(&[]).path(0).is_none());
}

#[test]
fn t_place_reads_b_place_of_the_network() {
    const GIB: u64 = 1 << 30;
    // Mainnet: 10^8 B/s, 2·10^8 bytes a block.
    assert_eq!((t_place(0, 1), t_place(GIB, 1), t_place(200_000_000, 1)), (60, 66, 61));
    // Every other network: 5·10^6 B/s, 10^7 bytes a block.
    for network in [0, 2, 0x7e57] {
        assert_eq!((t_place(0, network), t_place(GIB, network), t_place(10_000_000, network)), (60, 168, 61));
    }
    // `L_escrow` places a checkpoint on the 3 slots of its `ChallengeWindow` deal.
    assert_eq!(crate::hub_key::l_escrow(100, GIB, 2), 100 + t_place(3 * GIB, 2));
}

#[test]
fn t_place_counts_every_slot_a_placement_draws() {
    const GIB: u64 = 1 << 30;
    // 1 GiB to `r = 3` holders on a testnet: S = 3 GiB, 60 + 323 blocks.
    assert_eq!(t_place_slots(GIB, 3, 2), 383);
    assert_eq!(t_place_slots(GIB, 1, 2), t_place(GIB, 2));
    assert_eq!(t_place_slots(u64::MAX, 2, 2), t_place(u64::MAX, 2));
    assert_eq!(Layout::Replicate { r: 5 }.placement_slots(), 5);
    // An RS deal's first placement is `Replicate { r: 2 }`.
    assert_eq!(Layout::ReedSolomon { k: 10, m: 4, shard_roots: [0; 32] }.placement_slots(), 2);
}
