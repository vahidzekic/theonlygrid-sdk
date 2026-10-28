use super::*;
use crate::payload::PayloadKind;
use crate::testing::{payload, sample_spec};

fn message(nonce: u64, payload: CgmpPayload) -> CgmpMessage {
    CgmpMessage {
        version: CGMP_VERSION,
        source: ChainId(7),
        dest: ChainId::HUB,
        channel_nonce: nonce,
        timeout_height: 1_000,
        fee: 5,
        origin: CgmpOrigin::Module { chain: ChainId(7), module: ModuleId(*b"render\0\0\0\0\0\0\0\0\0\0") },
        payload,
    }
}

#[test]
fn borsh_layout_follows_the_spec() {
    let m = message(3, CgmpPayload::Ack { of_nonce: 2, result: Err(CgmpError::SupplyLedgerUnderflow) });
    let b = borsh::to_vec(&m).unwrap();
    // version, source, dest, nonce, timeout, fee, origin = Module (2, chain, module).
    assert_eq!(b[0], 1);
    assert_eq!(&b[1..5], &7u32.to_le_bytes());
    assert_eq!(&b[5..9], &0u32.to_le_bytes());
    assert_eq!(&b[9..17], &3u64.to_le_bytes());
    assert_eq!(&b[17..25], &1_000u64.to_le_bytes());
    assert_eq!(&b[25..41], &5u128.to_le_bytes());
    assert_eq!(b[41], 2);
    // payload = Ack (4), of_nonce, Err (borsh 0) with CgmpError index 5.
    assert_eq!(&b[41 + 1 + 4 + 16..], &[4, 2, 0, 0, 0, 0, 0, 0, 0, 0, 5]);
    assert_eq!(borsh::from_slice::<CgmpMessage>(&b).unwrap(), m);

    let w = Weight { ref_time: 1, proof_size: 2 };
    assert_eq!(borsh::to_vec(&w).unwrap(), [1u64.to_le_bytes(), 2u64.to_le_bytes()].concat());
}

#[test]
fn hashes_and_bounds() {
    let m = message(0, CgmpPayload::TransferTog { to: [1; 20], amount: 9 });
    assert_eq!(m.hash(), tagged_hash(Domain::CgmpMsg, &[&borsh::to_vec(&m).unwrap()]));
    assert_eq!(next_head(&HEAD_0, &m.hash()), tagged_hash(Domain::CgmpQueue, &[&HEAD_0, &m.hash()]));
    assert!(m.is_well_formed());
    assert!(!CgmpMessage { version: 2, ..m.clone() }.is_well_formed());

    let call = |len| {
        message(1, CgmpPayload::Call { module: ModuleId([0; 16]), call: vec![0; len], weight_limit: Weight::default() })
    };
    assert!(call(MAX_CALL_LEN).is_well_formed());
    assert!(!call(MAX_CALL_LEN + 1).is_well_formed());

    let result = |n: usize| {
        let outputs = (0..n).map(|i| (format!("o{i:03}"), payload(PayloadKind::Output, 1, 1, None))).collect();
        let r = ComputeResult {
            job_id: [1; 32],
            outcome: JobOutcome::Settled,
            receipt_root: [2; 32],
            outputs,
            work_units: 3,
            charged: 4,
        };
        message(2, CgmpPayload::ComputeResult(r))
    };
    assert!(result(MAX_OUTPUTS).is_well_formed());
    assert!(!result(MAX_OUTPUTS + 1).is_well_formed());

    let req = message(
        3,
        CgmpPayload::ComputeRequest { spec: Box::new(sample_spec()), escrow: EscrowRef([3; 32]), callback: None },
    );
    let b = borsh::to_vec(&req).unwrap();
    assert_eq!(borsh::from_slice::<CgmpMessage>(&b).unwrap(), req);
}

#[test]
fn outbox_root_is_a_sorted_binary_tree() {
    let ch = |d: u32| OutboxChannel { dest: ChainId(d), head: [d as u8; 32], last_nonce: d as u64 };
    let leaf = |d: u32| {
        let bytes = borsh::to_vec(&(ChainId(d), [d as u8; 32], d as u64)).unwrap();
        tagged_hash(Domain::CgmpLeaf, &[&bytes])
    };
    assert_eq!(ch(4).leaf(), leaf(4));
    assert_eq!(outbox_root(&[]), EMPTY_OUTBOX);
    assert_eq!(outbox_root(&[ch(2)]), leaf(2));
    // Unsorted input; three leaves: the last moves up unchanged.
    assert_eq!(outbox_root(&[ch(3), ch(1), ch(2)]), outbox_node(&outbox_node(&leaf(1), &leaf(2)), &leaf(3)));
    assert_eq!(outbox_node(&leaf(1), &leaf(2)), tagged_hash(Domain::CgmpNode, &[&leaf(1), &leaf(2)]));
}

#[test]
fn weights_add_and_compare_per_component() {
    let (a, b) = (Weight::from_parts(5, 1), Weight::from_parts(2, 7));
    assert_eq!(a.saturating_add(b), Weight::from_parts(7, 8));
    assert_eq!(a.saturating_sub(b), Weight::from_parts(3, 0));
    assert_eq!(Weight::MAX.saturating_add(a), Weight::MAX);
    assert_eq!(Weight::MAX.checked_add(a), None);
    assert_eq!(a.checked_add(b), Some(Weight::from_parts(7, 8)));
    assert_eq!(b.saturating_mul(3), Weight::from_parts(6, 21));
    assert_eq!(a.min_each(b), Weight::from_parts(2, 1));
    // Neither fits in the other, though `Ord` puts `b` first.
    assert!(!a.all_lte(b) && !b.all_lte(a) && b < a);
    assert!(Weight::ZERO.all_lte(a) && a.all_lte(a));
}

#[test]
fn an_inbox_proof_folds_to_the_channel_head_and_lag_counts_pending() {
    let hashes: Vec<Hash32> = (0..4u8).map(|i| [i + 1; 32]).collect();
    let mut head = HEAD_0;
    for h in &hashes {
        head = next_head(&head, h);
    }
    let ch = CgmpChannel { head, last_nonce: Some(3), ..CgmpChannel::default() };
    assert_eq!(ch.pending(), 4);

    // Message 1, after 0 was processed: the proof is the hashes of 2 and 3.
    let queue = next_head(&HEAD_0, &hashes[0]);
    let after = ch.check_inbox(1, &queue, 1, &hashes[1], &hashes[2..]).unwrap();
    assert_eq!(after, next_head(&queue, &hashes[1]));
    // Wrong nonce, a short proof, or a wrong queue head fail.
    assert!(ch.check_inbox(2, &queue, 1, &hashes[1], &hashes[2..]).is_none());
    assert!(ch.check_inbox(1, &queue, 1, &hashes[1], &hashes[2..3]).is_none());
    assert!(ch.check_inbox(1, &HEAD_0, 1, &hashes[1], &hashes[2..]).is_none());
    // The last message needs an empty proof; no messages, no proof at all.
    let queue3 = hashes[..3].iter().fold(HEAD_0, |h, m| next_head(&h, m));
    assert_eq!(ch.check_inbox(3, &queue3, 3, &hashes[3], &[]), Some(head));
    assert!(CgmpChannel::default().check_inbox(0, &HEAD_0, 0, &hashes[0], &[]).is_none());

    let far = CgmpChannel { last_nonce: Some(300), ..ch };
    assert!(!far.within_lag(0) && far.within_lag(45) && far.within_lag(301));
    assert_eq!(CgmpChannel::default().pending(), 0);
}

#[test]
fn a_delivery_batch_folds_from_the_hub_queue_to_the_channel_head() {
    let msgs: Vec<CgmpMessage> =
        (0..5).map(|n| message(n, CgmpPayload::TransferTog { to: [1; 20], amount: u128::from(n) + 1 })).collect();
    let hashes: Vec<Hash32> = msgs.iter().map(CgmpMessage::hash).collect();
    let head = hashes.iter().fold(HEAD_0, |h, m| next_head(&h, m));
    let after0 = next_head(&HEAD_0, &hashes[0]);
    let ch = CgmpChannel { head, last_nonce: Some(4), next_nonce: 1, ..CgmpChannel::default() };

    // Messages 1 and 2, proof 3 and 4.
    let heads = check_delivery(&ch, &after0, ChainId(7), &msgs[1..3], &hashes[3..]).unwrap();
    assert_eq!(heads, vec![next_head(&after0, &hashes[1]), next_head(&next_head(&after0, &hashes[1]), &hashes[2])]);
    // All the rest, no proof.
    assert_eq!(check_delivery(&ch, &after0, ChainId(7), &msgs[1..], &[]).unwrap().last(), Some(&head));
    // A gap, a wrong source, a short proof, no messages, a wrong queue head.
    assert!(check_delivery(&ch, &after0, ChainId(7), &msgs[2..], &[]).is_none());
    assert!(check_delivery(&ch, &after0, ChainId(8), &msgs[1..], &[]).is_none());
    assert!(check_delivery(&ch, &after0, ChainId(7), &msgs[1..3], &hashes[3..4]).is_none());
    assert!(check_delivery(&ch, &after0, ChainId(7), &[], &hashes[1..]).is_none());
    assert!(check_delivery(&ch, &HEAD_0, ChainId(7), &msgs[1..], &[]).is_none());
}

#[test]
fn hub_fees_and_the_appchains_call() {
    let m = message(0, CgmpPayload::TransferTog { to: [1; 20], amount: 9 });
    let len = borsh::to_vec(&m).unwrap().len() as Amount;
    assert_eq!(min_hub_fee(&m), 1_000_000_000_000_000 + len * 1_000_000_000_000);
    assert_eq!(&APPCHAINS_MODULE.0[..10], b"appchains\0");
    let rules = crate::eligibility::WorkerSetRules {
        min_isolation: crate::job::IsolationTier::T0Gvisor,
        hw_filter: crate::eligibility::HwFilter {
            min_gpus: 0,
            cc: None,
            min_vram_bytes: 0,
            gpu_models: None,
            require_cc_capable: false,
            min_cpu_isa: None,
            min_ram_bytes: 0,
        },
        required_toolchains: vec![],
        min_bond: 1,
        min_reputation: 0,
        regions: None,
        accepts_external_jobs: false,
        allowlist: None,
        allowed_policies: None,
    };
    let call = borsh::to_vec(&AppchainsCall::SetWorkerSetRules(rules.clone())).unwrap();
    assert_eq!(call, [vec![0u8], borsh::to_vec(&rules).unwrap()].concat());
}

#[test]
fn worker_slashed_tags_follow_the_spec() {
    let offences = [
        WorkerOffence::ExecutorFault,
        WorkerOffence::LeaseExpired,
        WorkerOffence::VerifierAgainst,
        WorkerOffence::JurorAgainst,
        WorkerOffence::LostRound,
        WorkerOffence::EscrowFault,
    ];
    for (tag, o) in offences.iter().enumerate() {
        assert_eq!(borsh::to_vec(o).unwrap(), vec![tag as u8]);
    }
    let notice = WorkerSlashed { worker: [1; 20], offence: WorkerOffence::EscrowFault, job: [2; 32] };
    let bytes = borsh::to_vec(&CgmpPayload::WorkerSlashed(notice.clone())).unwrap();
    assert_eq!(bytes[0], 5);
    assert_eq!(&bytes[1..21], &[1; 20]);
    assert_eq!(bytes[21], 5);
    assert_eq!(&bytes[22..], &[2; 32]);
    assert_eq!(borsh::from_slice::<CgmpPayload>(&bytes).unwrap(), CgmpPayload::WorkerSlashed(notice));
}
