//! The timed walk that proves a storage worker's media tier (TOG-SPEC-0012 §1–§2): its records,
//! the walk function, the messages on `/tog/grid/1/probe` and the report.
//!
//! The walk's space for `(target, tier)` is the concatenation of the byte spaces ([`Span`]) of the
//! target's `Active` slots on that tier, ascending by `(DealId, slot)`. Each of the
//! [`WALK_STEPS`] steps reads the 4 KiB leaf holding a byte the previous leaf chose, so the reads
//! can't run in parallel, be precomputed or be prefetched.

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::{tagged_hash, Domain, Hash32};

use crate::por::{ChunkOpening, Span, StorageWorkerId};
use crate::verifier::{VrfOutput, VrfProof};
use crate::worker::WorkerId;

/// Steps of one walk.
pub const WALK_STEPS: u32 = 512;
/// `T_walk` by tier on mainnet, `network_id` 1, µs net of RTT (TOG-SPEC-0012 §2.3): a tier passes
/// when the median walk is at most this.
pub const T_WALK_US: [u64; 2] = [400_000, 12_000_000];
/// `T_walk[Hdd]` on every other network: 30 s (testnet value, 2026-10-28), since a USB HDD of the
/// closed testnet walks in 10–12 s, at mainnet's bound.
pub const TESTNET_T_WALK_HDD_US: u64 = 30_000_000;

/// `T_walk` of `tier` on `network_id`.
pub const fn t_walk_us(network_id: u32, tier: MediaTier) -> u64 {
    match (network_id, tier) {
        (1, _) | (_, MediaTier::Nvme) => T_WALK_US[tier as usize],
        (_, MediaTier::Hdd) => TESTNET_T_WALK_HDD_US,
    }
}
/// How long a prober waits for the digest and the transcript.
pub const WALK_TIMEOUT_SECS: u64 = 600;
/// `net_us` of a walk that failed: a wrong digest, an opening that doesn't verify, or no answer.
pub const WALK_FAILED: u64 = u64::MAX;

/// A storage medium, by how fast it reads at random. Borsh index = position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize)]
pub enum MediaTier {
    /// Hot: `Hot` and `ChallengeWindow` slots. RAM passes too.
    Nvme,
    /// Cold: `LongTerm` slots.
    Hdd,
}

/// The ECVRF input of a walk prober: `"TOG/v1/walk" ‖ prober ‖ target ‖ u8 tier ‖ u64_le(session)`,
/// 60 bytes. The prober's id makes the input its own (PA-5), as in `probe_input`.
pub fn walk_input(prober: &WorkerId, target: &StorageWorkerId, tier: MediaTier, session: u64) -> Vec<u8> {
    [Domain::Walk.tag().as_bytes(), prober, &target.0, &[tier as u8], &session.to_le_bytes()].concat()
}

/// `seed = H("TOG/v1/walk-seed" ‖ β ‖ nonce)`, `β` the VRF output of the walk's proof.
pub fn walk_seed(out: &VrfOutput, nonce: &[u8; 32]) -> [u8; 32] {
    tagged_hash(Domain::WalkSeed, &[&out.y, &out.salt_v, nonce])
}

/// One walk over a space of `len` bytes from `seed`: `leaf(j, x)` gives the bytes of the 4 KiB leaf
/// holding byte `x` at step `j`. `None` if `len` is 0 or a leaf is missing.
pub fn walk<B: AsRef<[u8]>>(
    seed: &[u8; 32],
    len: u64,
    mut leaf: impl FnMut(u32, u64) -> Option<B>,
) -> Option<[u8; 32]> {
    if len == 0 {
        return None;
    }
    let mut acc = blake3::derive_key(Domain::Walk.tag(), seed);
    for j in 0..WALK_STEPS {
        let x = u64::from_le_bytes(acc[..8].try_into().expect("8 bytes")) % len;
        let bytes = leaf(j, x)?;
        let mut h = blake3::Hasher::new();
        h.update(&acc);
        h.update(&j.to_le_bytes());
        h.update(bytes.as_ref());
        acc = *h.finalize().as_bytes();
    }
    Some(acc)
}

/// A slot's span in a walk's space, with the RS shard the slot holds (ignored for other slots).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WalkSpan {
    /// The slot's bytes; `base` is its place in the walk's space.
    pub span: Span,
    /// `HolderSlot.shard`.
    pub shard: u16,
}

/// Total bytes of `spans`; `None` on overflow.
pub fn space_len(spans: &[WalkSpan]) -> Option<u64> {
    spans.iter().try_fold(0u64, |a, s| a.checked_add(s.span.len))
}

/// The span holding byte `x` of the walk's space and the set offset of that byte.
pub fn locate(spans: &[WalkSpan], mut x: u64) -> Option<(&WalkSpan, u64)> {
    for s in spans {
        if x < s.span.len {
            return Some((s, s.span.at(x, s.shard)?));
        }
        x -= s.span.len;
    }
    None
}

/// The digest a transcript proves: each opening must be the leaf holding the step's byte, proven
/// against its span's set root (TOG-SPEC-0012 §2.2 rule 3). `None` if any opening fails, or there
/// are not exactly [`WALK_STEPS`] of them.
pub fn verify_transcript(seed: &[u8; 32], spans: &[WalkSpan], openings: &[ChunkOpening]) -> Option<[u8; 32]> {
    if openings.len() != WALK_STEPS as usize {
        return None;
    }
    let len = space_len(spans)?;
    walk(seed, len, |j, x| {
        let (s, set_off) = locate(spans, x)?;
        let o = &openings[j as usize];
        (o.deal == s.span.deal && o.slot == s.span.slot && o.proves(&s.span.set, set_off)).then_some(&o.chunk[..])
    })
}

/// `0x04`, prober to target: start a walk.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WalkStart {
    /// The walked storage worker.
    pub target: StorageWorkerId,
    /// Its tier.
    pub tier: MediaTier,
    /// Session.
    pub session: u64,
    /// The prober.
    pub prober: WorkerId,
    /// Proof over [`walk_input`]`(prober, target, tier, session)`.
    pub proof: VrfProof,
    /// Fresh per walk; with the proof's output it gives the seed.
    pub nonce: [u8; 32],
}

/// `0x84`, target to prober: the walk's accumulator, which stops the prober's timer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WalkDigest {
    /// `acc`.
    pub acc: [u8; 32],
}

/// `0x85`, target to prober: the leaves read, in step order.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WalkTranscript {
    /// One per step.
    pub openings: Vec<ChunkOpening>,
}

/// One accepted walk of a tier (TOG-SPEC-0012 §1.1).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TierWalk {
    /// The prober.
    pub prober: WorkerId,
    /// Session.
    pub session: u64,
    /// Walk time net of RTT, µs; [`WALK_FAILED`] for a failed transcript.
    pub net_us: u64,
}

/// Walks kept per tier, from distinct probers.
pub const WALKS_KEPT: usize = 5;
/// Fresh walks a tier needs before a verdict (TOG-SPEC-0012 §1.4).
pub const WALKS_FOR_VERDICT: usize = 3;
/// `WALK_FRESH_SESSIONS`: a walk counts in the verdict of a session up to this many sessions
/// after its own (TOG-SPEC-0012 §1.4).
pub const WALK_FRESH_SESSIONS: u64 = 24;
/// `PROBATION_BYTES`: bytes a record may hold on `Unverified` tiers (TOG-SPEC-0012 §1.3).
pub const PROBATION_BYTES: u64 = 64 << 30;
/// `PROBATION_ERAS`: eras a new record's `Pass` tiers stay under the probation limits
/// (TOG-SPEC-0012 §1.3 "New records").
pub const PROBATION_ERAS: u64 = 7;
/// Whole eras of `Fail` after which a tier's slots exit to repair (TOG-SPEC-0012 §1.4).
pub const FAIL_EXIT_ERAS: u8 = 3;

/// A tier's verdict (TOG-SPEC-0012 §1.1). Borsh index = position.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum TierVerdict {
    /// Fewer than three walks so far.
    #[default]
    Unverified,
    /// The median walk is within `T_walk` since height `since`.
    Pass {
        /// First height of the passing run.
        since: u64,
    },
    /// The median walk is over `T_walk` since height `since`, for `eras` whole eras.
    Fail {
        /// First height of the failing run.
        since: u64,
        /// Eras the failure has lasted.
        eras: u8,
    },
}

/// `storage_registry.media[StorageWorkerId]` (TOG-SPEC-0012 §1.1), Borsh in field order. Arrays
/// are indexed by [`MediaTier`].
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MediaRecord {
    /// Capacity by tier; the sum is the record's `capacity_bytes`.
    pub capacity: [u64; 2],
    /// Committed bytes by tier, kept by the Hub; the sum is `committed_bytes`.
    pub committed: [u64; 2],
    /// Verdict by tier.
    pub verdict: [TierVerdict; 2],
    /// The last [`WALKS_KEPT`] accepted walks by tier, from distinct probers, oldest first.
    pub walks: [Vec<TierWalk>; 2],
    /// Bytes of active slots placed while their tier was `Unverified`.
    pub probation_bytes: u64,
}

impl MediaRecord {
    /// The record of a storage worker that never declared its media: all of it `Nvme`,
    /// unverified, no walks.
    pub fn undeclared(capacity_bytes: u64, committed_bytes: u64) -> Self {
        Self { capacity: [capacity_bytes, 0], committed: [committed_bytes, 0], ..Self::default() }
    }

    /// Appends an accepted walk of `tier`: drops an older one of the same prober, then the oldest
    /// beyond [`WALKS_KEPT`].
    pub fn push_walk(&mut self, tier: MediaTier, walk: TierWalk) {
        let walks = &mut self.walks[tier as usize];
        walks.retain(|w| w.prober != walk.prober);
        walks.push(walk);
        if walks.len() > WALKS_KEPT {
            walks.drain(..walks.len() - WALKS_KEPT);
        }
    }

    /// The verdict of `tier` at the end of session `session`, judged at height `height`
    /// (TOG-SPEC-0012 §1.4). Only fresh walks count, those of session
    /// `session − WALK_FRESH_SESSIONS` or later. With at least [`WALKS_FOR_VERDICT`] of them:
    /// `Pass` if their median `net_us` (the lower middle of an even count) is at most `T_walk` of
    /// `network_id` ([`t_walk_us`]), else `Fail`. With fewer, `Pass` returns to `Unverified`, `Fail` stays and keeps counting
    /// its eras, and `Unverified` stays. A run keeps its `since`; a failure counts its whole eras
    /// of `era_length` blocks.
    pub fn judge(&self, network_id: u32, tier: MediaTier, session: u64, height: u64, era_length: u64) -> TierVerdict {
        let oldest = session.saturating_sub(WALK_FRESH_SESSIONS);
        let walks: Vec<&TierWalk> = self.walks[tier as usize].iter().filter(|w| w.session >= oldest).collect();
        let old = self.verdict[tier as usize];
        let fail = |since: u64| TierVerdict::Fail {
            since,
            eras: u8::try_from((height - since) / era_length.max(1)).unwrap_or(u8::MAX),
        };
        if walks.len() < WALKS_FOR_VERDICT {
            return match old {
                TierVerdict::Pass { .. } | TierVerdict::Unverified => TierVerdict::Unverified,
                TierVerdict::Fail { since, .. } => fail(since),
            };
        }
        let mut net: Vec<u64> = walks.iter().map(|w| w.net_us).collect();
        net.sort_unstable();
        if net[(net.len() - 1) / 2] <= t_walk_us(network_id, tier) {
            match old {
                TierVerdict::Pass { since } => TierVerdict::Pass { since },
                _ => TierVerdict::Pass { since: height },
            }
        } else {
            match old {
                TierVerdict::Fail { since, .. } => fail(since),
                _ => fail(height),
            }
        }
    }
}

/// `TxBody` 57, user lane, signed by the record's owner (TOG-SPEC-0012 §1.1): sets the per-tier
/// split of the record's capacity, whose sum becomes `capacity_bytes`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DeclareStorageMediaTx {
    /// The record.
    pub worker: StorageWorkerId,
    /// Capacity by [`MediaTier`], each at least the tier's committed bytes.
    pub capacity: [u64; 2],
    /// Replay domain and the owner's nonce.
    pub replay: crate::storage::ReplayGuard,
}

/// `TxBody` 56, compute-market lane, signed by the prober's worker key (TOG-SPEC-0012 §2.2).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TierProbeReportTx {
    /// The walked storage worker.
    pub target: StorageWorkerId,
    /// Its tier.
    pub tier: MediaTier,
    /// Session; the report is valid in this session or the next.
    pub session: u64,
    /// Proof over [`walk_input`]`(prober, target, tier, session)`, the prober being the report's
    /// signer.
    pub proof: VrfProof,
    /// Walk time net of RTT, µs; [`WALK_FAILED`] if it failed.
    pub net_us: u64,
    /// BLAKE3 of the transcript bytes.
    pub transcript_root: Hash32,
}

/// `net_us` (TOG-SPEC-0012 §2.2 rule 3): `elapsed − rtt` if the digest matches the transcript
/// and every opening verifies, else [`WALK_FAILED`].
pub fn net_us(elapsed_us: u64, rtt_us: u64, digest: &[u8; 32], proven: Option<[u8; 32]>) -> u64 {
    match proven {
        Some(acc) if acc == *digest => elapsed_us.saturating_sub(rtt_us),
        _ => WALK_FAILED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::DealId;
    use crate::payload::{PayloadCommitment, PayloadKind};
    use crate::por::Bao4kProof;
    use crate::storage::{path, MerklePath, PayloadSetLeaf, SetFrontier};

    /// A one-payload set of `size` bytes and its span at `base`.
    fn payload(size: usize, fill: u8, deal: u64, base: u64) -> (Vec<u8>, WalkSpan, PayloadSetLeaf, MerklePath) {
        let bytes: Vec<u8> = (0..size).map(|i| (i as u8).wrapping_mul(31) ^ fill).collect();
        let commitment = PayloadCommitment {
            root: *blake3::hash(&bytes).as_bytes(),
            ..crate::testing::payload(PayloadKind::Input, 0, size as u64, None)
        };
        let mut frontier = SetFrontier::new();
        let leaves = frontier.append(&[commitment]).unwrap();
        let path = path(&leaves, 0).unwrap();
        let span = Span { deal: DealId(deal), slot: 0, set: frontier.set, base, len: size as u64, leaves: vec![] };
        (bytes, WalkSpan { span, shard: 0 }, leaves[0], path)
    }

    #[test]
    fn a_tier_is_judged_on_the_median_of_three_or_more_walks() {
        let walk = |p: u8, net_us| TierWalk { prober: [p; 20], session: 0, net_us };
        let mut m = MediaRecord::undeclared(10, 4);
        assert_eq!((m.capacity, m.committed), ([10, 0], [4, 0]));
        m.push_walk(MediaTier::Nvme, walk(1, 100));
        m.push_walk(MediaTier::Nvme, walk(2, WALK_FAILED));
        assert_eq!(m.judge(1, MediaTier::Nvme, 0, 50, 100), TierVerdict::Unverified, "two walks");
        m.push_walk(MediaTier::Nvme, walk(3, 500_000));
        // 100, 500 000, MAX: the median fails.
        m.verdict[0] = m.judge(1, MediaTier::Nvme, 0, 50, 100);
        assert_eq!(m.verdict[0], TierVerdict::Fail { since: 50, eras: 0 });
        assert_eq!(m.judge(1, MediaTier::Nvme, 0, 260, 100), TierVerdict::Fail { since: 50, eras: 2 });
        // The same prober again replaces its walk: 100, 300 000, 500 000 passes.
        m.push_walk(MediaTier::Nvme, walk(2, 300_000));
        assert_eq!(m.walks[0].iter().map(|w| w.prober[0]).collect::<Vec<_>>(), [1, 3, 2]);
        m.verdict[0] = m.judge(1, MediaTier::Nvme, 0, 270, 100);
        assert_eq!(m.verdict[0], TierVerdict::Pass { since: 270 });
        assert_eq!(m.judge(1, MediaTier::Nvme, 0, 900, 100), TierVerdict::Pass { since: 270 });
        // An even count reads the lower middle; at most five are kept.
        for p in 4..=6 {
            m.push_walk(MediaTier::Nvme, walk(p, 1));
        }
        assert_eq!(m.walks[0].len(), WALKS_KEPT);
        assert_eq!(m.judge(1, MediaTier::Hdd, 0, 900, 100), TierVerdict::Unverified, "tiers are apart");
    }

    #[test]
    fn an_hdd_walk_of_20_s_fails_on_mainnet_and_passes_elsewhere() {
        assert_eq!([t_walk_us(1, MediaTier::Nvme), t_walk_us(1, MediaTier::Hdd)], T_WALK_US);
        for network_id in [2, 0x7e58] {
            assert_eq!(t_walk_us(network_id, MediaTier::Nvme), T_WALK_US[0]);
            assert_eq!(t_walk_us(network_id, MediaTier::Hdd), TESTNET_T_WALK_HDD_US);
        }
        let mut m = MediaRecord::undeclared(0, 0);
        for p in 1..=3 {
            m.push_walk(MediaTier::Hdd, TierWalk { prober: [p; 20], session: 0, net_us: 20_000_000 });
        }
        assert_eq!(m.judge(1, MediaTier::Hdd, 0, 50, 100), TierVerdict::Fail { since: 50, eras: 0 });
        assert_eq!(m.judge(0x7e58, MediaTier::Hdd, 0, 50, 100), TierVerdict::Pass { since: 50 });
        m.push_walk(MediaTier::Hdd, TierWalk { prober: [4; 20], session: 0, net_us: 31_000_000 });
        m.push_walk(MediaTier::Hdd, TierWalk { prober: [5; 20], session: 0, net_us: 31_000_000 });
        m.push_walk(MediaTier::Hdd, TierWalk { prober: [6; 20], session: 0, net_us: 31_000_000 });
        assert!(matches!(m.judge(2, MediaTier::Hdd, 0, 50, 100), TierVerdict::Fail { .. }));
    }

    #[test]
    fn only_walks_of_the_last_fresh_sessions_count_and_a_pass_without_them_returns_to_unverified() {
        let walk = |p: u8, session, net_us| TierWalk { prober: [p; 20], session, net_us };
        let mut m = MediaRecord::undeclared(10, 0);
        for p in 1..=3 {
            m.push_walk(MediaTier::Nvme, walk(p, 10, 100));
        }
        m.verdict[0] = m.judge(1, MediaTier::Nvme, 10, 50, 100);
        assert_eq!(m.verdict[0], TierVerdict::Pass { since: 50 });
        // Still fresh at the last session that counts session 10.
        let last = 10 + WALK_FRESH_SESSIONS;
        assert_eq!(m.judge(1, MediaTier::Nvme, last, 900, 100), TierVerdict::Pass { since: 50 });
        // A session later the walks are stale: the cached-once pass does not last.
        assert_eq!(m.judge(1, MediaTier::Nvme, last + 1, 900, 100), TierVerdict::Unverified);
        // Two fresh walks out of four are not enough; a third fresh one judges on those three only.
        m.push_walk(MediaTier::Nvme, walk(4, last + 1, WALK_FAILED));
        m.push_walk(MediaTier::Nvme, walk(5, last + 1, WALK_FAILED));
        assert_eq!(m.judge(1, MediaTier::Nvme, last + 1, 900, 100), TierVerdict::Unverified);
        m.push_walk(MediaTier::Nvme, walk(1, last + 1, 100));
        m.verdict[0] = m.judge(1, MediaTier::Nvme, last + 1, 900, 100);
        assert_eq!(m.verdict[0], TierVerdict::Fail { since: 900, eras: 0 });
        // A failure without fresh walks stays and keeps counting its eras.
        let stale = last + 2 + WALK_FRESH_SESSIONS;
        assert_eq!(m.judge(1, MediaTier::Nvme, stale, 1150, 100), TierVerdict::Fail { since: 900, eras: 2 });
    }

    #[test]
    fn a_walk_over_two_slots_verifies_and_a_wrong_leaf_does_not() {
        let (a, sa, la, pa) = payload(40_000, 1, 1, 0);
        let (b, sb, lb, pb) = payload(9_000, 2, 2, 40_000);
        let spans = [sa, sb];
        let seed = [7; 32];
        let len = space_len(&spans).unwrap();
        // The target: reads leaves and records openings.
        let mut openings = vec![];
        let acc = walk(&seed, len, |_, x| {
            let (s, off) = locate(&spans, x).unwrap();
            let (bytes, leaf, path) = if s.span.deal == DealId(1) { (&a, la, &pa) } else { (&b, lb, &pb) };
            let i = off / 4096;
            let chunk = &bytes[(i * 4096) as usize..bytes.len().min(((i + 1) * 4096) as usize)];
            openings.push(ChunkOpening {
                deal: s.span.deal,
                slot: 0,
                set_leaf: leaf,
                set_path: path.clone(),
                chunk_index: i,
                chunk: chunk.to_vec(),
                chunk_proof: Bao4kProof::prove(bytes, i).unwrap(),
            });
            Some(chunk)
        })
        .unwrap();
        assert_eq!(verify_transcript(&seed, &spans, &openings), Some(acc));
        assert!(openings.iter().any(|o| o.deal == DealId(2)), "both slots are read");
        assert_eq!(net_us(500, 100, &acc, verify_transcript(&seed, &spans, &openings)), 400);
        // Another seed walks elsewhere.
        assert_ne!(verify_transcript(&[8; 32], &spans, &openings), Some(acc));
        let mut bad = openings.clone();
        bad[100].chunk[0] ^= 1;
        assert_eq!(verify_transcript(&seed, &spans, &bad), None);
        assert_eq!(net_us(500, 100, &acc, None), WALK_FAILED);
        let mut moved = openings.clone();
        moved.swap(3, 4);
        assert!(verify_transcript(&seed, &spans, &moved).is_none_or(|d| d != acc));
        assert_eq!(verify_transcript(&seed, &spans, &openings[1..]), None);
        assert_eq!(walk(&seed, 0, |_, _| Some(&[][..])), None);
    }

    #[test]
    fn the_input_and_seed_are_bound_to_every_field() {
        let (p, t) = ([4; 20], StorageWorkerId([3; 20]));
        let i = walk_input(&p, &t, MediaTier::Hdd, 9);
        assert_eq!(i.len(), 60);
        assert_eq!((&i[..11], &i[11..31], &i[31..51]), (&b"TOG/v1/walk"[..], &p[..], &t.0[..]));
        assert_eq!((i[51], &i[52..]), (1, &9u64.to_le_bytes()[..]));
        assert_ne!(i, walk_input(&p, &t, MediaTier::Nvme, 9));
        assert_ne!(i, walk_input(&[5; 20], &t, MediaTier::Hdd, 9), "another prober's input is not this one");
        let out = VrfOutput { y: [1; 32], salt_v: [2; 32] };
        assert_ne!(walk_seed(&out, &[0; 32]), walk_seed(&out, &[1; 32]));
        assert_eq!(borsh::to_vec(&MediaTier::Hdd).unwrap(), [1]);
    }
}
