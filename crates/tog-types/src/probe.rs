//! Bandwidth probes (TOG-SPEC-0004 §3.3 "Bandwidth probe (exact)") and payload provider records in
//! the Grid DHT (TOG-SPEC-0004 §7.1 "Finding non-holder peers (exact)").
//!
//! A VRF-selected compute worker downloads `P` pseudo-random bytes from a target, uploads as many back
//! on the same `/tog/grid/1/probe` stream, and reports both rates in `TxBody` variant 42. The Hub
//! keeps the last five reports from distinct probers and sets the target's `net` to their median.

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::hash::{tagged_hash, Domain};
use tog_primitives::{Address, Amount, Hash32, ONE_TOG};

use crate::verifier::{VrfOutput, VrfProof};
use crate::walk::{WalkDigest, WalkStart, WalkTranscript, WALK_STEPS};
use crate::worker::{NetProfile, WorkerId};

/// Protocol id of the probe stream (TOG-SPEC-0006 §2.4).
pub const PROBE_PROTOCOL: &str = "/tog/grid/1/probe";
/// `P`: bytes sent each way.
pub const PROBE_BYTES: u64 = 256 << 20;
/// Largest `ProbeBytes` body.
pub const PROBE_MAX_CHUNK: usize = 4 << 20;
/// A direction not finished within this many seconds gets rate 0.
pub const PROBE_TIMEOUT_SECS: u64 = 600;
/// Hub blocks per session of the reference genesis (TOG-SPEC-0002 §2.3); a network's own is
/// `Genesis.session_length`.
pub const SESSION_LENGTH: u64 = 1_800;
/// Reports kept per target, from distinct probers.
pub const PROBES_KEPT: usize = 5;
/// `probe_fee` on mainnet, `network_id` 1: 0.01 TOG (placeholder, TOG-SPEC-0004 §14).
pub const MAINNET_PROBE_FEE: Amount = ONE_TOG / 100;
/// `probe_fee` on every other network: 0.001 TOG (testnet value, 2026-10-25).
pub const TESTNET_PROBE_FEE: Amount = ONE_TOG / 1_000;

/// `probe_fee` of `network_id`: paid from the target's bond to the prober per accepted
/// `ProbeReport` and `TierProbeReport` (TOG-SPEC-0004 §14, TOG-SPEC-0012 §2).
pub const fn probe_fee(network_id: u32) -> Amount {
    match network_id {
        1 => MAINNET_PROBE_FEE,
        _ => TESTNET_PROBE_FEE,
    }
}

/// The session of Hub height `h`, with sessions of `session_length` blocks.
pub fn session_of(height: u64, session_length: u64) -> u64 {
    height / session_length.max(1)
}

/// ECVRF input `"TOG/v1/probe" ‖ p ‖ t ‖ u64_le(s)`, 60 bytes, with `p` the prober's id (TOG-SPEC-0004
/// §3.3); like the sortition input, the tag is a plain prefix.
pub fn probe_input(prober: &Address, target: &Address, session: u64) -> Vec<u8> {
    [Domain::Probe.tag().as_bytes(), prober, target, &session.to_le_bytes()].concat()
}

/// The VRF part of eligibility: `y · n < 2 · 2^256`, with `y` the big-endian first half of β and `n`
/// the number of `Active` workers. About two probers per target per session.
pub fn probe_selected(out: &VrfOutput, active_workers: u64) -> bool {
    // y as four little-endian u64 limbs, times n; the product is below 2^257 iff its top limb is 0 or 1.
    let mut carry = 0u128;
    for i in (0..4).rev() {
        let limb = u64::from_be_bytes(out.y[i * 8..i * 8 + 8].try_into().expect("8 bytes"));
        carry = (limb as u128 * active_workers as u128 + carry) >> 64;
    }
    carry < 2
}

/// Which way the bytes go: `d` in the byte-stream derivation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    /// 0: target to prober (`X_down`).
    Down = 0,
    /// 1: prober to target (`X_up`).
    Up = 1,
}

/// `X_down` or `X_up`: the BLAKE3 XOF of `derive_key("TOG/v1/probe-bytes", borsh((t, s, p, d)))`
/// (derive-key mode, so its first 32 bytes are that `derive_key`), of which the first
/// [`PROBE_BYTES`] bytes are sent. `d` is a `u8`. Fill buffers from it in order.
pub fn probe_stream(target: &Address, session: u64, prober: &WorkerId, d: Direction) -> blake3::OutputReader {
    let key_input = borsh::to_vec(&(target, session, prober, d as u8)).expect("in-memory borsh cannot fail");
    let mut h = blake3::Hasher::new_derive_key(Domain::ProbeBytes.tag());
    h.update(&key_input);
    h.finalize_xof()
}

/// `⌊8 · P · 1 000 / ms⌋`; a transfer measured as 0 ms counts as 1 ms.
pub fn rate_bps(ms: u64) -> u64 {
    let r = 8 * PROBE_BYTES as u128 * 1_000 / ms.max(1) as u128;
    r.min(u64::MAX as u128) as u64
}

/// `0x01`: the prober opens a probe.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ProbeStart {
    /// The probed worker or storage worker.
    pub target: Address,
    /// Hub session.
    pub session: u64,
    /// The prober's `WorkerId`.
    pub prober: WorkerId,
    /// Proof over [`probe_input`] under the prober's `vrf_key`.
    pub proof: VrfProof,
}

/// One message on `/tog/grid/1/probe`; each is framed as on `/tog/pieces/1` (a `u32` LE length, the
/// type byte, the Borsh body).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeMessage {
    /// `0x01`, prober to target.
    Start(ProbeStart),
    /// `0x02`, prober to target: the next bytes of `X_up`.
    Up(Vec<u8>),
    /// `0x81`, target to prober: the next bytes of `X_down`.
    Down(Vec<u8>),
    /// `0x82`: `X_down` is complete.
    End,
    /// `0x83`: `blake3` of the `P` bytes of `X_up` received.
    Ack(Hash32),
    /// `0x86`: not answered; ends the stream.
    Busy,
    /// `0x04`, prober to target: a timed walk of a storage tier (TOG-SPEC-0012 §2.2).
    WalkStart(WalkStart),
    /// `0x84`, target to prober: the walk's digest.
    WalkDigest(WalkDigest),
    /// `0x85`, target to prober: the walk's openings, at most [`WALK_TRANSCRIPT_MAX`] bytes.
    WalkTranscript(WalkTranscript),
    /// `0x05`, prober to target before `WalkStart`: one of up to [`WALK_PINGS`] round trips that
    /// measure `rtt_us` (TOG-SPEC-0012 §2.2 rule 2).
    WalkPing(WalkPing),
    /// `0x87`, target to prober at once: the answer to the `WalkPing` of the same `seq`.
    WalkPong(WalkPing),
}

/// `0x05`/`0x87` body: the ping's number, 0 to [`WALK_PINGS`] − 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WalkPing {
    /// The ping's number.
    pub seq: u8,
}

/// `WalkPing`s a prober sends before `WalkStart`, and the most a target answers on one stream.
pub const WALK_PINGS: u8 = 5;

/// Largest `WalkTranscript` message: 512 openings of a 4 KiB leaf with a depth-32 set path and a
/// BLAKE3 proof of up to 52 levels, about 3.6 MiB, with room.
pub const WALK_TRANSCRIPT_MAX: usize = 8 << 20;

fn typed(t: u8, body: &impl BorshSerialize) -> Vec<u8> {
    let mut v = vec![t];
    borsh::to_writer(&mut v, body).expect("in-memory borsh cannot fail");
    v
}

impl ProbeMessage {
    /// Type byte and Borsh body.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Start(s) => typed(0x01, s),
            Self::Up(b) => typed(0x02, b),
            Self::Down(b) => typed(0x81, b),
            Self::End => vec![0x82],
            Self::Ack(h) => typed(0x83, h),
            Self::Busy => vec![0x86],
            Self::WalkStart(w) => typed(0x04, w),
            Self::WalkDigest(d) => typed(0x84, d),
            Self::WalkTranscript(t) => typed(0x85, t),
            Self::WalkPing(p) => typed(0x05, p),
            Self::WalkPong(p) => typed(0x87, p),
        }
    }

    /// Decodes exactly one message; byte chunks above [`PROBE_MAX_CHUNK`] are rejected.
    pub fn decode(msg: &[u8]) -> Option<Self> {
        let (&t, b) = msg.split_first()?;
        let chunk = |b: &[u8]| borsh::from_slice::<Vec<u8>>(b).ok().filter(|c| c.len() <= PROBE_MAX_CHUNK);
        match t {
            0x01 => borsh::from_slice(b).ok().map(Self::Start),
            0x02 => chunk(b).map(Self::Up),
            0x81 => chunk(b).map(Self::Down),
            0x82 if b.is_empty() => Some(Self::End),
            0x83 => borsh::from_slice(b).ok().map(Self::Ack),
            0x86 if b.is_empty() => Some(Self::Busy),
            0x04 => borsh::from_slice(b).ok().map(Self::WalkStart),
            0x84 => borsh::from_slice(b).ok().map(Self::WalkDigest),
            0x85 => borsh::from_slice::<WalkTranscript>(b)
                .ok()
                .filter(|t| t.openings.len() <= WALK_STEPS as usize)
                .map(Self::WalkTranscript),
            0x05 => borsh::from_slice::<WalkPing>(b).ok().filter(|p| p.seq < WALK_PINGS).map(Self::WalkPing),
            0x87 => borsh::from_slice::<WalkPing>(b).ok().filter(|p| p.seq < WALK_PINGS).map(Self::WalkPong),
            _ => None,
        }
    }
}

/// `TxBody` variant 42, compute-market lane, signed by the prober's worker key.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ProbeReportTx {
    /// A `WorkerId` or `StorageWorkerId`.
    pub target: Address,
    /// Session of the probe; the report is valid in this session or the next.
    pub session: u64,
    /// Proof over [`probe_input`]`(target, session)`.
    pub proof: VrfProof,
    /// Prober to target, bits per second.
    pub ingress_bps: u64,
    /// Target to prober, bits per second.
    pub egress_bps: u64,
    /// Minimum of 5 pings on the probe connection before `ProbeStart`, in µs; 0 if not measured.
    pub rtt_us: u32,
    /// ASN of the target's connected remote IP from the prober's ASN table (TOG-SPEC-0006 §6.3).
    pub asn: u32,
    /// The "Region and ASN check" (TOG-SPEC-0004 §3.3): false iff `rtt_us` is shorter than light in
    /// fiber needs between the prober's region and the target's declared one.
    pub region_ok: bool,
}

/// One kept report in `hardware_registry.probes[target]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ProbeEntry {
    /// The prober's `WorkerId`.
    pub prober: WorkerId,
    /// Session.
    pub session: u64,
    /// Ingress, bits per second.
    pub ingress_bps: u64,
    /// Egress, bits per second.
    pub egress_bps: u64,
    /// The report's `rtt_us`.
    pub rtt_us: u32,
    /// The report's `asn`.
    pub asn: u32,
    /// The report's `region_ok`.
    pub region_ok: bool,
}

/// Appends an accepted report: drops an older entry from the same prober, then the oldest beyond
/// [`PROBES_KEPT`]. Entries stay oldest first.
pub fn push_probe(entries: &mut Vec<ProbeEntry>, entry: ProbeEntry) {
    entries.retain(|e| e.prober != entry.prober);
    entries.push(entry);
    if entries.len() > PROBES_KEPT {
        entries.drain(..entries.len() - PROBES_KEPT);
    }
}

/// The target's `net`: per-direction median of the kept entries, the lower middle of an even count.
/// `None` when there are none.
pub fn probed_net(entries: &[ProbeEntry]) -> Option<NetProfile> {
    let median = |f: fn(&ProbeEntry) -> u64| {
        let mut v: Vec<u64> = entries.iter().map(f).collect();
        v.sort_unstable();
        v[(v.len() - 1) / 2]
    };
    (!entries.is_empty())
        .then(|| NetProfile { ingress_bps: median(|e| e.ingress_bps), egress_bps: median(|e| e.egress_bps) })
}

/// Kept entries that must disagree to flag a record (TOG-SPEC-0004 §3.3 "Region and ASN check").
pub const REGION_FLAG_MIN: usize = 3;

/// `region_flagged` over the kept entries: at least [`REGION_FLAG_MIN`] have `region_ok = false`,
/// or, for a storage record (`declared_asn` set), at least as many observed another ASN. An entry
/// with `asn = 0` observed none (ASN 0 is reserved and never announced, RFC 7607).
pub fn region_flagged(entries: &[ProbeEntry], declared_asn: Option<u32>) -> bool {
    let region = entries.iter().filter(|e| !e.region_ok).count();
    let asn = declared_asn.map_or(0, |d| entries.iter().filter(|e| e.asn != 0 && e.asn != d).count());
    region >= REGION_FLAG_MIN || asn >= REGION_FLAG_MIN
}

/// Most providers a downloader asks for.
pub const MAX_PROVIDERS: usize = 20;
/// A provider re-announces this often while it serves the root, in seconds.
pub const PROVIDE_REPUBLISH: u64 = 3_600;
/// Server-mode nodes keep a provider record this long, in seconds.
pub const PROVIDE_TTL: u64 = 6 * 3_600;

/// Grid-DHT provider key of a payload root: `H("TOG/v1/provide" ‖ root)`.
pub fn provide_key(root: &Hash32) -> Hash32 {
    tagged_hash(Domain::Provide, &[root])
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    fn out(y: [u8; 32]) -> VrfOutput {
        VrfOutput { y, salt_v: [0; 32] }
    }

    #[test]
    fn probe_fee_is_a_tenth_off_mainnet() {
        assert_eq!(probe_fee(1), ONE_TOG / 100);
        for network_id in [0, 2, 0x7e57, u32::MAX] {
            assert_eq!(probe_fee(network_id), ONE_TOG / 1_000, "network {network_id}");
        }
    }

    #[test]
    fn selection_threshold_is_two_over_n() {
        // n = 4: y < 2^255, i.e. the top bit is clear.
        let mut y = [0xff; 32];
        y[0] = 0x7f;
        assert!(probe_selected(&out(y), 4));
        y[0] = 0x80;
        y[1..].fill(0);
        assert!(!probe_selected(&out(y), 4));
        // n ≤ 2 selects everyone.
        assert!(probe_selected(&out([0xff; 32]), 2));
        assert!(!probe_selected(&out([0xff; 32]), 3));
        assert!(probe_selected(&out([0; 32]), u64::MAX));
    }

    #[test]
    fn input_layout() {
        let a = probe_input(&[6; 20], &[7; 20], 9);
        assert_eq!(a.len(), 60);
        assert!(a.starts_with(b"TOG/v1/probe"));
        assert_eq!((&a[12..32], &a[32..52]), (&[6; 20][..], &[7; 20][..]));
        assert_eq!(&a[52..], &9u64.to_le_bytes());
    }

    #[test]
    fn streams_follow_the_derivation() {
        let (t, p) = ([1; 20], [2; 20]);
        let mut down = [0u8; 64];
        probe_stream(&t, 3, &p, Direction::Down).read_exact(&mut down).unwrap();
        let key = blake3::derive_key("TOG/v1/probe-bytes", &borsh::to_vec(&(t, 3u64, p, 0u8)).unwrap());
        assert_eq!(down[..32], key);
        let mut up = [0u8; 64];
        probe_stream(&t, 3, &p, Direction::Up).read_exact(&mut up).unwrap();
        assert_ne!(up, down);
    }

    #[test]
    fn messages_round_trip_and_bound_chunks() {
        let start = ProbeStart { target: [1; 20], session: 2, prober: [3; 20], proof: VrfProof([4; 80]) };
        for m in [
            ProbeMessage::Start(start),
            ProbeMessage::Up(vec![1, 2]),
            ProbeMessage::Down(vec![3]),
            ProbeMessage::End,
            ProbeMessage::Ack([5; 32]),
            ProbeMessage::Busy,
            ProbeMessage::WalkStart(crate::walk::WalkStart {
                target: crate::por::StorageWorkerId([1; 20]),
                tier: crate::walk::MediaTier::Hdd,
                session: 2,
                prober: [3; 20],
                proof: VrfProof([4; 80]),
                nonce: [5; 32],
            }),
            ProbeMessage::WalkDigest(WalkDigest { acc: [6; 32] }),
            ProbeMessage::WalkTranscript(WalkTranscript { openings: vec![] }),
            ProbeMessage::WalkPing(WalkPing { seq: 0 }),
            ProbeMessage::WalkPong(WalkPing { seq: WALK_PINGS - 1 }),
        ] {
            assert_eq!(ProbeMessage::decode(&m.encode()), Some(m));
        }
        assert_eq!(ProbeMessage::WalkDigest(WalkDigest { acc: [6; 32] }).encode()[0], 0x84);
        assert_eq!(ProbeMessage::WalkPing(WalkPing { seq: 3 }).encode(), [0x05, 3]);
        assert_eq!(ProbeMessage::WalkPong(WalkPing { seq: 3 }).encode(), [0x87, 3]);
        assert_eq!(ProbeMessage::decode(&[0x05, WALK_PINGS]), None, "seq 0 to 4");
        assert_eq!(ProbeMessage::decode(&ProbeMessage::Down(vec![0; PROBE_MAX_CHUNK + 1]).encode()), None);
        assert_eq!(ProbeMessage::decode(&[0x82, 0]), None);
    }

    #[test]
    fn rates() {
        assert_eq!(rate_bps(1_000), 8 * PROBE_BYTES);
        assert_eq!(rate_bps(0), rate_bps(1));
    }

    #[test]
    fn kept_reports_and_median() {
        let e = |p: u8, i: u64| ProbeEntry {
            prober: [p; 20],
            session: 0,
            ingress_bps: i,
            egress_bps: 10 * i,
            rtt_us: 0,
            asn: 0,
            region_ok: true,
        };
        let mut v = vec![];
        assert_eq!(probed_net(&v), None);
        for (p, i) in [(1, 5), (2, 1), (3, 9), (4, 7)] {
            push_probe(&mut v, e(p, i));
        }
        // 1, 5, 7, 9: lower middle.
        assert_eq!(probed_net(&v), Some(NetProfile { ingress_bps: 5, egress_bps: 50 }));
        // Same prober again replaces its entry and moves to the end.
        push_probe(&mut v, e(2, 100));
        assert_eq!(v.iter().map(|x| x.prober[0]).collect::<Vec<_>>(), [1, 3, 4, 2]);
        push_probe(&mut v, e(5, 0));
        push_probe(&mut v, e(6, 0));
        assert_eq!(v.iter().map(|x| x.prober[0]).collect::<Vec<_>>(), [3, 4, 2, 5, 6]);
        // 0, 0, 7, 9, 100.
        assert_eq!(probed_net(&v).unwrap().ingress_bps, 7);
    }

    #[test]
    fn three_of_five_disagreeing_entries_flag_a_record() {
        let e = |p: u8, asn: u32, region_ok: bool| ProbeEntry {
            prober: [p; 20],
            session: 0,
            ingress_bps: 1,
            egress_bps: 1,
            rtt_us: 900,
            asn,
            region_ok,
        };
        let mut v = vec![e(1, 7, false), e(2, 7, false), e(3, 7, true), e(4, 8, true), e(5, 0, true)];
        assert!(!region_flagged(&v, Some(7)), "two region and one ASN disagreement");
        v[2].region_ok = false;
        assert!(region_flagged(&v, None), "three region disagreements flag a compute worker too");
        v[2].region_ok = true;
        v[0].asn = 9;
        v[1].asn = 9;
        assert!(region_flagged(&v, Some(7)), "three other ASNs");
        assert!(!region_flagged(&v, None), "a compute worker declares no ASN");
        v[3].asn = 0;
        assert!(!region_flagged(&v, Some(7)), "ASN 0 observed none");
    }

    #[test]
    fn provide_key_is_tagged() {
        assert_eq!(provide_key(&[1; 32]), blake3::derive_key("TOG/v1/provide", &[1; 32]));
    }
}
