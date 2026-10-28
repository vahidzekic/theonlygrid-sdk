use super::*;

pub(crate) fn backed() -> BackedCandidate {
    let descriptor = CandidateDescriptor {
        chain_id: ChainId(7),
        relay_parent: (10, [1; 32]),
        collator: [2; 20],
        parent_head_hash: [3; 32],
        pov_hash: pov_hash(b"pov"),
        erasure_root: [4; 32],
        code_hash: [5; 32],
    };
    let commitments = ValidationResult {
        head: vec![6; 3],
        outbox_root: [7; 32],
        inbox_processed: 2,
        new_code: None,
        outbox: vec![(ChainId(9), [8; 32], 4)],
        inbox: vec![(ChainId(0), 2)],
    };
    BackedCandidate {
        receipt: CandidateReceipt { descriptor, commitments },
        votes: vec![(ValidatorIndex(1), [9; 64]), (ValidatorIndex(4), [9; 64])],
    }
}

#[test]
fn hashes_follow_the_tags() {
    let r = backed().receipt;
    let bytes = borsh::to_vec(&r).unwrap();
    assert_eq!(r.hash(), tagged_hash(Domain::Candidate, &[&bytes]));
    assert_eq!(borsh::from_slice::<CandidateReceipt>(&bytes).unwrap(), r);
    let m = backing_message(3 << 32, &r.hash());
    assert_eq!(m, tagged_hash(Domain::Backing, &[&(3u64 << 32).to_le_bytes(), &r.hash()]));
    assert_ne!(m, backing_message(4 << 32, &r.hash()));
    assert_eq!(head_hash(b"h"), tagged_hash(Domain::AppchainHeader, &[b"h"]));
}

#[test]
fn a_backing_group_is_the_five_smallest_draws() {
    let beacon = [3; 32];
    let g = backing_group(&beacon, ChainId(7), 20);
    assert_eq!(g.len(), BACKING_GROUP_SIZE);
    assert!(g.windows(2).all(|w| w[0] < w[1]));
    let draw = |i: u16| tagged_hash(Domain::BackingGroup, &[&beacon, &7u32.to_le_bytes(), &u32::from(i).to_le_bytes()]);
    let worst_in = g.iter().map(|v| draw(v.0)).max().unwrap();
    assert!((0..20).filter(|i| !g.contains(&ValidatorIndex(*i))).all(|i| draw(i) > worst_in));
    // Another chain or session draws another group; fewer validators than the group size gives all.
    assert_ne!(backing_group(&beacon, ChainId(8), 20), g);
    assert_ne!(backing_group(&[4; 32], ChainId(7), 20), g);
    assert_eq!(backing_group(&beacon, ChainId(7), 3), vec![ValidatorIndex(0), ValidatorIndex(1), ValidatorIndex(2)]);
    assert_eq!(backing_session(25, 10), 2);
}

fn indexes(v: &[ValidatorIndex]) -> Vec<u16> {
    v.iter().map(|i| i.0).collect()
}

#[test]
fn the_permutation_orders_the_draws_without_a_chain() {
    let beacon = [3; 32];
    let pi = backing_permutation(&beacon, 20);
    let draw = |i: u16| tagged_hash(Domain::BackingGroup, &[&beacon, &u32::from(i).to_le_bytes()]);
    assert!(pi.windows(2).all(|w| draw(w[0].0) < draw(w[1].0)));
    let mut sorted = indexes(&pi);
    sorted.sort_unstable();
    assert_eq!(sorted, (0..20).collect::<Vec<_>>());
    assert_ne!(backing_permutation(&[4; 32], 20), pi);
}

#[test]
fn groups_are_disjoint_and_each_chain_rotates_to_the_next_every_30_blocks() {
    let (beacon, n, session) = ([5; 32], 23u16, 1_800);
    let pi = backing_permutation(&beacon, n);
    let groups = usize::from(n) / BACKING_GROUP_SIZE;
    // At one relay height, ranks 0..G cover the first 5·G validators of π once each.
    let at = |rank: u64, r: u64| backing_assignment(&beacon, rank, r, session, n);
    let mut seen: Vec<u16> = (0..groups as u64).flat_map(|rank| indexes(&at(rank, 3_600).group)).collect();
    seen.sort_unstable();
    let mut first: Vec<u16> = indexes(&pi[..groups * BACKING_GROUP_SIZE]);
    first.sort_unstable();
    assert_eq!(seen, first);
    for rank in 0..9 {
        let a = at(rank, 3_600 + 7);
        assert_eq!(a.group.len(), BACKING_GROUP_SIZE);
        assert!(a.group.windows(2).all(|w| w[0] < w[1]));
        // The reserves follow the group in π, cyclically, and are not in it.
        assert_eq!(a.reserves.len(), BACKING_RESERVES);
        assert!(a.reserves.iter().all(|v| !a.group.contains(v)));
        let j = (0..groups).find(|j| {
            let mut g = indexes(&pi[j * 5..j * 5 + 5]);
            g.sort_unstable();
            g == indexes(&a.group)
        });
        let j = j.expect("a group is a block of π");
        assert_eq!(indexes(&a.reserves), indexes(&[pi[(j * 5 + 5) % 23], pi[(j * 5 + 6) % 23]]));
        // 30 blocks later in the session the chain has the next rank's group; a block earlier, the same.
        assert_eq!(at(rank, 3_600 + 37).group, at(rank + 1, 3_600 + 7).group);
        assert_eq!(at(rank, 3_600 + 29).group, a.group);
    }
    // Chains of consecutive ranks share the groups evenly: 9 chains on 4 groups, 2 or 3 each.
    let mut load = vec![0; groups];
    for rank in 0..9 {
        let g = at(rank, 3_600).group;
        let j = (0..groups as u64).find(|k| at(*k, 3_600).group == g).unwrap();
        load[j as usize] += 1;
    }
    assert!(load.iter().all(|l| (2..=3).contains(l)), "{load:?}");
    // A validator is a reserve for at most two groups.
    let mut reserve_of = vec![0; usize::from(n)];
    for rank in 0..groups as u64 {
        for v in at(rank, 3_600).reserves {
            reserve_of[usize::from(v.0)] += 1;
        }
    }
    assert!(reserve_of.iter().all(|c| *c <= 2));
}

#[test]
fn small_sets_have_one_group_and_fewer_reserves() {
    let beacon = [6; 32];
    for n in [1u16, 4, 5] {
        let a = backing_assignment(&beacon, 3, 40, 1_800, n);
        assert_eq!(indexes(&a.group), (0..n).collect::<Vec<_>>());
        assert!(a.reserves.is_empty());
    }
    let pi = backing_permutation(&beacon, 6);
    let a = backing_assignment(&beacon, 3, 40, 1_800, 6);
    assert_eq!(a.reserves, vec![pi[5]]);
    let a = backing_assignment(&beacon, 3, 40, 1_800, 7);
    assert_eq!(a.reserves.len(), 2);
}

#[test]
fn backing_assignment_vector() {
    // Pinned for other implementations (tog-sim, the collator): β = [7; 32], n = 12, rank 1,
    // relay height 3 661 in sessions of 1 800 blocks (step 2).
    let a = backing_assignment(&[7; 32], 1, 3_661, 1_800, 12);
    assert_eq!(indexes(&backing_permutation(&[7; 32], 12)), PERMUTATION_VECTOR);
    assert_eq!((indexes(&a.group), indexes(&a.reserves)), (GROUP_VECTOR.to_vec(), RESERVES_VECTOR.to_vec()));
}

#[test]
fn a_chain_ranks_by_the_session_list_then_the_unlisted_chains() {
    let (a, b, c, d) = (ChainId(2), ChainId(5), ChainId(9), ChainId(11));
    let listed = [b, d];
    let all = [a, b, c, d];
    assert_eq!(chain_rank(b, &listed, &all), Some(0));
    assert_eq!(chain_rank(d, &listed, &all), Some(1));
    assert_eq!(chain_rank(a, &listed, &all), Some(2));
    assert_eq!(chain_rank(c, &listed, &all), Some(3));
    assert_eq!(chain_rank(ChainId(40), &listed, &all), None);
    assert_eq!(chain_rank(c, &[], &all), Some(2));
}

#[test]
fn heads_start_at_genesis() {
    let h = AppChainHeads::genesis(vec![1, 2], 9);
    assert_eq!((h.pending.as_slice(), h.final_head.as_slice(), h.final_at), (&[1, 2][..], &[1, 2][..], 9));
}

fn genesis_head() -> HeadData {
    let h = Header {
        parent: [0; 32],
        number: 0,
        state_root: [5; 32],
        extrinsics_root: [0; 32],
        relay_parent: (0, [0; 32]),
        outbox_root: [0; 32],
        inbox_processed: 0,
        digest: vec![],
    };
    borsh::to_vec(&h).unwrap()
}

pub(crate) fn upload() -> UploadCodeTx {
    UploadCodeTx {
        chain_id: 1 << 32,
        signer: [1; 20],
        nonce: 0,
        code_hash: [2; 32],
        total_len: 10,
        offset: 4,
        bytes: vec![0; 6],
    }
}

pub(crate) fn register() -> RegisterAppChainTx {
    use crate::eligibility::HwFilter;
    use crate::job::IsolationTier;
    let rules = WorkerSetRules {
        min_isolation: IsolationTier::T0Gvisor,
        hw_filter: HwFilter {
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
    RegisterAppChainTx {
        chain_id: 1 << 32,
        signer: [1; 20],
        nonce: 1,
        code_hash: [2; 32],
        genesis_head: genesis_head(),
        worker_set_rules: rules,
        verification_modules: vec![VerificationModuleId([1; 16]), VerificationModuleId([2; 16])],
    }
}

pub(crate) fn vote() -> PreCheckVote {
    PreCheckVote { code_hash: [2; 32], era: 3, validator: ValidatorIndex(1), accept: true, sig: [7; 64] }
}

#[test]
fn an_upload_chunk_fits_its_code() {
    assert_eq!(upload().check_stateless(), Ok(()));
    assert_eq!(UploadCodeTx { bytes: vec![], ..upload() }.check_stateless(), Err(AppChainTxError::Chunk(0)));
    let big = vec![0; MAX_CODE_CHUNK + 1];
    assert_eq!(
        UploadCodeTx { bytes: big, total_len: MAX_CODE_LEN, ..upload() }.check_stateless(),
        Err(AppChainTxError::Chunk(MAX_CODE_CHUNK + 1))
    );
    assert_eq!(UploadCodeTx { offset: 5, ..upload() }.check_stateless(), Err(AppChainTxError::Length));
    let over = UploadCodeTx { total_len: MAX_CODE_LEN + 1, offset: 0, ..upload() };
    assert_eq!(over.check_stateless(), Err(AppChainTxError::Length));
}

#[test]
fn a_registration_needs_a_genesis_head_and_ascending_modules() {
    assert_eq!(register().check_stateless(), Ok(()));
    let mut not_genesis: Header = borsh::from_slice(&genesis_head()).unwrap();
    not_genesis.number = 1;
    let r = RegisterAppChainTx { genesis_head: borsh::to_vec(&not_genesis).unwrap(), ..register() };
    assert_eq!(r.check_stateless(), Err(AppChainTxError::GenesisHead));
    let mut trailing = genesis_head();
    trailing.push(0);
    assert_eq!(
        RegisterAppChainTx { genesis_head: trailing, ..register() }.check_stateless(),
        Err(AppChainTxError::GenesisHead)
    );
    let mut r = register();
    r.verification_modules.reverse();
    assert_eq!(r.check_stateless(), Err(AppChainTxError::Modules));
    let mut r = register();
    r.verification_modules = (0..17u8).map(|i| VerificationModuleId([i; 16])).collect();
    assert_eq!(r.check_stateless(), Err(AppChainTxError::Modules));
}

#[test]
fn a_pre_check_vote_signs_code_era_and_choice_under_the_hub_chain() {
    let v = vote();
    let m = v.message(1 << 32);
    let expected = tagged_hash(Domain::PreCheck, &[&(1u64 << 32).to_le_bytes(), &[2; 32], &3u64.to_le_bytes(), &[1]]);
    assert_eq!(m, expected);
    assert_ne!(PreCheckVote { accept: false, ..v.clone() }.message(1 << 32), m);
    assert_ne!(PreCheckVote { era: 4, ..v.clone() }.message(1 << 32), m);
    assert_ne!(PreCheckVote { sig: [0; 64], ..v.clone() }.message(2 << 32), m);
    assert_eq!(PreCheckVote { sig: [0; 64], ..v }.message(1 << 32), m);
}

#[test]
fn code_status_indices_match_spec() {
    let pre = CodeStatus::PreCheck { era: 1, until: 2, accept: vec![], reject: vec![] };
    for (i, s) in
        [CodeStatus::Uploading { until: 3 }, pre, CodeStatus::Accepted, CodeStatus::Rejected].iter().enumerate()
    {
        assert_eq!(borsh::to_vec(s).unwrap()[0], i as u8);
    }
}

#[test]
fn collate_frames_round_trip() {
    let c = Collation { receipt: backed().receipt, pov: vec![1, 2, 3] };
    assert_eq!(Collation::decode_frame(&c.encode_frame()), Some(c.clone()));
    let s = BackingStatement { receipt: c.receipt, validator: ValidatorIndex(4), sig: [5; 64] };
    for r in [CollateResponse::Seconded(Box::new(s)), CollateResponse::Error(CollateError::AlreadySeconded)] {
        assert_eq!(CollateResponse::decode_frame(&r.encode_frame()), Some(r));
    }
    assert_eq!(CollateResponse::decode_frame(&[COLLATE_ERROR, 5]), None);
    assert_eq!(Collation::decode_frame(&[COLLATE_SECONDED]), None);
}

#[test]
fn pov_frames_round_trip() {
    let q = PovRequest { candidate: [7; 32] };
    let f = q.encode_frame();
    assert_eq!(f.len(), POV_REQUEST_LEN);
    assert_eq!(PovRequest::decode_frame(&f), Some(q));
    assert_eq!(PovRequest::decode_frame(&f[..32]), None);
    for r in [PovResponse::Pov(vec![1, 2, 3]), PovResponse::NotAvailable] {
        assert_eq!(PovResponse::decode_frame(&r.encode_frame()), Some(r));
    }
    assert_eq!(PovResponse::decode_frame(&[POV_NOT_AVAILABLE, 1]), None);
    let big = PovResponse::Pov(vec![0; crate::erasure::MAX_POV_COMPRESSED + 1]).encode_frame();
    assert_eq!(PovResponse::decode_frame(&big), None);
}

pub(crate) fn bitfield() -> Bitfield {
    Bitfield { parent: [1; 32], era: 2, validator: ValidatorIndex(3), bits: vec![0b101], sig: [4; 64] }
}

pub(crate) fn approval() -> ApprovalVote {
    ApprovalVote { candidate: [1; 32], validator: ValidatorIndex(2), tranche: 0, sig: [3; 96] }
}

pub(crate) fn dispute() -> CandidateDispute {
    let vote = |v, valid| DisputeVote { validator: ValidatorIndex(v), valid, sig: [5; 64] };
    CandidateDispute { chain: ChainId(7), candidate: [1; 32], votes: vec![vote(0, false), vote(2, true)] }
}

#[test]
fn bitfields_and_dispute_votes_sign_under_the_hub_chain() {
    let b = bitfield();
    let fields = borsh::to_vec(&(&b.parent, b.era, b.validator, &b.bits)).unwrap();
    assert_eq!(b.message(1 << 32), tagged_hash(Domain::Bitfield, &[&(1u64 << 32).to_le_bytes(), &fields]));
    assert_eq!(Bitfield { sig: [0; 64], ..b.clone() }.message(1 << 32), b.message(1 << 32));
    assert_ne!(Bitfield { bits: vec![1], ..b.clone() }.message(1 << 32), b.message(1 << 32));

    let d = dispute();
    let v = &d.votes[0];
    let expected = tagged_hash(Domain::DisputeVote, &[&(1u64 << 32).to_le_bytes(), &[1; 32], &[0]]);
    assert_eq!(v.message(1 << 32, &d.candidate), expected);
    assert!(d.is_well_formed());
    let mut bad = d.clone();
    bad.votes.reverse();
    assert!(!bad.is_well_formed());
    assert!(!CandidateDispute { votes: vec![], ..d }.is_well_formed());
}

#[test]
fn approval_selection_follows_the_tranche_bound() {
    let a = approval();
    let out = a.out();
    assert_eq!(out, u64::from_le_bytes(tagged_hash(Domain::ApprovalOut, &[&[3; 96]])[..8].try_into().unwrap()));
    // With n ≤ k every validator is in tranche 0; tranche ≥ 1 halves the bound.
    assert!(a.selected(4) && a.selected(30));
    let bound0 = (30u128 << 64) / 1000;
    assert_eq!(a.selected(1000), u128::from(out) < bound0);
    let late = ApprovalVote { tranche: 1, ..a.clone() };
    assert_eq!(late.selected(1000), u128::from(out) < bound0 / 2);
    let m = approval_assignment(1 << 32, &[9; 32], &a.candidate, 2);
    let expected =
        tagged_hash(Domain::ApprovalVrf, &[&(1u64 << 32).to_le_bytes(), &[9; 32], &[1; 32], &2u32.to_le_bytes()]);
    assert_eq!(m, expected);
    assert_eq!((approvals_required(4), approvals_required(150)), (3, 20));
}

#[test]
fn bitsets_count_and_grow() {
    let mut b = Vec::new();
    set_bit(&mut b, 9);
    set_bit(&mut b, 0);
    assert_eq!(b, vec![1, 2]);
    assert!(bit(&b, 9) && bit(&b, 0) && !bit(&b, 1) && !bit(&b, 64));
    assert_eq!(count_bits(&b), 2);
}

#[test]
fn an_exit_reads_free_and_reserved_first() {
    let mut v = borsh::to_vec(&(7u128, 9u128)).unwrap();
    v.extend_from_slice(&[1, 2, 3]);
    assert_eq!(exit_balance(&v), Some((7, 9)));
    assert_eq!(exit_balance(&v[..20]), None);
}

#[test]
fn candidate_fates_are_indexed_0_to_2() {
    let fates = [CandidateFate::Final, CandidateFate::Invalid, CandidateFate::Dropped];
    for (i, f) in fates.iter().enumerate() {
        assert_eq!(borsh::to_vec(f).unwrap(), [i as u8]);
    }
}

#[test]
fn recover_frames_are_37_bytes_and_round_trip() {
    let req = RecoverRequest { chain: ChainId(7), candidate: [3; 32] };
    let frame = req.encode_frame();
    assert_eq!(frame.len(), RECOVER_REQUEST_LEN);
    assert_eq!(&frame[..5], [RECOVER_REQUEST, 7, 0, 0, 0]);
    assert_eq!(RecoverRequest::decode_frame(&frame), Some(req));
    assert_eq!(RecoverRequest::decode_frame(&frame[..36]), None);
    let ok = RecoverResponse::Recovered(vec![1, 2, 3]);
    assert_eq!(RecoverResponse::decode_frame(&ok.encode_frame()), Some(ok));
    for (e, code) in [(RecoverError::BadRequest, 0), (RecoverError::NotAvailable, 1), (RecoverError::Busy, 2)] {
        assert_eq!(RecoverResponse::Error(e).encode_frame(), [RECOVER_ERROR, code]);
        assert_eq!(RecoverResponse::decode_frame(&[RECOVER_ERROR, code]), Some(RecoverResponse::Error(e)));
    }
    assert_eq!(RecoverResponse::decode_frame(&[RECOVER_ERROR, 3]), None);
}

#[test]
fn chunks_of_a_candidate_with_messages_to_an_appchain_stay_for_t_cgmp_keep() {
    use crate::erasure::{chunk_window, CGMP_KEEP_BLOCKS, CHUNK_RETENTION_BLOCKS};
    assert_eq!(chunk_window(&[]), CHUNK_RETENTION_BLOCKS);
    assert_eq!(chunk_window(&[(ChainId(0), [1; 32], 1)]), CHUNK_RETENTION_BLOCKS);
    assert_eq!(chunk_window(&[(ChainId(0), [1; 32], 1), (ChainId(5), [1; 32], 1)]), CGMP_KEEP_BLOCKS);
}

// Computed independently from the 0002 §4.4 text with Python's blake3 (derive_key): offset 1,
// step 2, so j = (1 + 1 + 2) mod 2 = 0.
const PERMUTATION_VECTOR: [u16; 12] = [3, 6, 7, 9, 0, 2, 10, 1, 11, 5, 4, 8];
const GROUP_VECTOR: [u16; 5] = [0, 3, 6, 7, 9];
const RESERVES_VECTOR: [u16; 2] = [2, 10];
