use super::*;
use crate::payload::{Encryption, PayloadCommitment, PayloadKind};
use crate::storage::{path, SetFrontier};

fn bytes(len: usize, salt: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31) ^ salt ^ (i >> 10) as u8).collect()
}

const SIZES: [usize; 11] =
    [1, 1024, 4096, 4097, 5000, 8192, 3 * 4096 + 7, 4 * 4096, 17 * 4096, 17 * 4096 + 1, (1 << 20) + 123];

#[test]
fn every_leaf_verifies_and_nothing_else() {
    for size in SIZES {
        let data = bytes(size, 1);
        let root = *blake3::hash(&data).as_bytes();
        let leaves = (size as u64).div_ceil(4096);
        for i in 0..leaves {
            let p = Bao4kProof::prove(&data, i).unwrap();
            let (lo, hi) = (i as usize * 4096, size.min((i as usize + 1) * 4096));
            let chunk = &data[lo..hi];
            assert!(p.verify(&root, size as u64, i, chunk), "size {size} leaf {i}");
            if size <= 4096 {
                assert!(p.siblings.is_empty());
            }

            let mut bad = chunk.to_vec();
            bad[0] ^= 1;
            assert!(!p.verify(&root, size as u64, i, &bad));
            if i + 1 == leaves {
                // The last leaf's length is fixed by the size (the set leaf binds the size itself).
                assert!(!p.verify(&root, size as u64 + 1, i, chunk), "size {size} leaf {i}");
            }
            if leaves > 1 {
                let other = (i + 1) % leaves;
                assert!(!p.verify(&root, size as u64, other, chunk));
                let mut short = p.clone();
                short.siblings.pop();
                assert!(!short.verify(&root, size as u64, i, chunk));
                let mut long = p.clone();
                long.siblings.push([0; 32]);
                assert!(!long.verify(&root, size as u64, i, chunk));
            }
        }
        assert!(Bao4kProof::prove(&data, leaves).is_none());
        assert!(!Bao4kProof::default().verify(&root, size as u64, leaves, &[]));
    }
}

#[test]
fn proof_depth() {
    // 16 full leaves: a balanced tree of depth 4.
    let data = bytes(16 * 4096, 2);
    assert_eq!(Bao4kProof::prove(&data, 5).unwrap().siblings.len(), 4);
    // 17 leaves: the 17th sits right under the root, the others one level deeper than 16.
    let data = bytes(17 * 4096, 2);
    assert_eq!(Bao4kProof::prove(&data, 16).unwrap().siblings.len(), 1);
    assert_eq!(Bao4kProof::prove(&data, 0).unwrap().siblings.len(), 5);
}

#[test]
fn draws() {
    let t = ChallengeTarget::Slot { deal: DealId(3), slot: 1 };
    let seed = [9; 32];
    assert_eq!(t.draw(&seed, 0), t.draw(&seed, 0));
    assert_ne!(t.draw(&seed, 0), t.draw(&seed, 1));
    assert_ne!(t.draw(&seed, 0), ChallengeTarget::Slot { deal: DealId(3), slot: 2 }.draw(&seed, 0));
    let h = tagged_hash(Domain::Por, &[&seed, &borsh::to_vec(&t).unwrap(), &0u32.to_le_bytes()]);
    assert_eq!(t.draw(&seed, 0).to_le_bytes(), h[..8]);

    assert!(t.set_offset(&seed, 0, 1000).unwrap() < 1000);
    assert_eq!(t.set_offset(&seed, 0, 0), None);
    assert_eq!(ChallengeTarget::Holder(StorageWorkerId([1; 20])).set_offset(&seed, 0, 1000), None);
    for j in 0..50 {
        let ack = ChallengeTarget::Ack { deal: DealId(3), slot: 1, from_offset: 900, to_offset: 1000 };
        assert!((900..1000).contains(&ack.set_offset(&seed, j, 1000).unwrap()));
        assert!((900..1000).contains(&ack.set_offset(&seed, j, 5000).unwrap()), "one leaf of a larger set");
        assert_eq!(ack.set_offset(&seed, j, 999), None, "past the set");
        let empty = ChallengeTarget::Ack { deal: DealId(3), slot: 1, from_offset: 900, to_offset: 900 };
        assert_eq!(empty.set_offset(&seed, j, 1000), None);
    }
}

#[test]
fn openings_prove_set_offsets() {
    let datas: Vec<Vec<u8>> =
        [5000usize, 4096, 1, 9 * 4096 + 3].iter().enumerate().map(|(i, &n)| bytes(n, i as u8)).collect();
    let payloads: Vec<PayloadCommitment> = datas
        .iter()
        .map(|d| PayloadCommitment {
            version: 1,
            root: *blake3::hash(d).as_bytes(),
            size: d.len() as u64,
            piece_log2: 20,
            kind: PayloadKind::Checkpoint,
            oci_digest: None,
            encryption: Encryption::None,
        })
        .collect();
    let mut set = SetFrontier::new();
    let leaves = set.append(&payloads).unwrap();
    let target = ChallengeTarget::Executor { deal: DealId(1), worker: [4; 20] };
    for j in 0..MAX_Q as u32 {
        let off = target.set_offset(&[7; 32], j, set.set.total_size).unwrap();
        let (i, chunk_index) = locate(&leaves, off).unwrap();
        let d = &datas[i];
        let lo = chunk_index as usize * 4096;
        let opening = ChunkOpening {
            deal: DealId(1),
            slot: 0,
            set_leaf: leaves[i],
            set_path: path(&leaves, i as u32).unwrap(),
            chunk_index,
            chunk: d[lo..d.len().min(lo + 4096)].to_vec(),
            chunk_proof: Bao4kProof::prove(d, chunk_index).unwrap(),
        };
        assert!(opening.proves(&set.set, off), "draw {j}");
        // The same opening does not prove a byte of another leaf or chunk.
        let elsewhere = if off >= 4096 { off - 4096 } else { off + 4096 };
        if locate(&leaves, elsewhere) != Some((i, chunk_index)) {
            assert!(!opening.proves(&set.set, elsewhere));
        }
    }
    assert_eq!(locate(&leaves, set.set.total_size), None);
    assert_eq!(locate(&leaves, 5000), Some((1, 0)));
    assert_eq!(locate(&leaves, 4999), Some((0, 1)));
}

#[test]
fn borsh_layout() {
    let first = |t: ChallengeTarget| borsh::to_vec(&t).unwrap()[0];
    assert_eq!(first(ChallengeTarget::Holder(StorageWorkerId([0; 20]))), 0);
    assert_eq!(first(ChallengeTarget::Slot { deal: DealId(0), slot: 0 }), 1);
    assert_eq!(first(ChallengeTarget::Executor { deal: DealId(0), worker: [0; 20] }), 2);
    assert_eq!(first(ChallengeTarget::Ack { deal: DealId(0), slot: 0, from_offset: 0, to_offset: 0 }), 3);
    assert_eq!(first(ChallengeTarget::Chunks { deal: DealId(0), slot: 0, offsets: vec![] }), 4);
    let tx = RespondChallengeTx { response: ChallengeResponse { challenge: ChallengeId(5), openings: vec![] } };
    assert_eq!(borsh::to_vec(&crate::TxBody::RespondChallenge(Box::new(tx))).unwrap()[0], 21);
}

#[test]
fn lazy_offset_walks_the_slot_leaves() {
    let leaf = |offset, size| PayloadSetLeaf { root: [0; 32], offset, size };
    // Leaves 1 and 3 of a set, held by one lazy slot.
    let held = [(1, leaf(100, 50)), (3, leaf(400, 10))];
    assert_eq!(lazy_offset(&held, 0), Some((1, 100)));
    assert_eq!(lazy_offset(&held, 49), Some((1, 149)));
    assert_eq!(lazy_offset(&held, 50), Some((3, 400)));
    assert_eq!(lazy_offset(&held, 59), Some((3, 409)));
    assert_eq!(lazy_offset(&held, 60), None);
}

#[test]
fn chunks_are_named_not_drawn() {
    let t = ChallengeTarget::Chunks { deal: DealId(3), slot: 1, offsets: vec![10, 9000] };
    assert_eq!(t.set_offset(&[1; 32], 0, 10_000), Some(10));
    assert_eq!(t.set_offset(&[2; 32], 1, 10_000), Some(9000));
    // Past the named offsets, or past the set.
    assert_eq!(t.set_offset(&[1; 32], 2, 10_000), None);
    assert_eq!(t.set_offset(&[1; 32], 1, 9000), None);
}

#[test]
fn locate_reads_the_spans_fixed_at_issue() {
    let leaf = |offset, size| PayloadSetLeaf { root: [0; 32], offset, size };
    let set = |total_size| PayloadSetRoot { root: [1; 32], count: 2, total_size };
    let span = |deal, base, len, leaves| Span { deal: DealId(deal), slot: 0, set: set(1000), base, len, leaves };
    let ch = |target, spans| RetrievabilityChallenge {
        id: ChallengeId(1),
        target,
        seed: [7; 32],
        q: 16,
        issued: 1,
        deadline: 2,
        challenger: None,
        spans,
    };

    // A holder's spans: a whole set, RS shard 3 (one 100-byte shard of a 1000-byte shard set)
    // and a lazy slot; `base` is each span's place in the challenge's byte space.
    let lazy = vec![(1, leaf(100, 50)), (3, leaf(400, 10))];
    let spans = vec![span(1, 0, 1000, vec![]), span(2, 1000, 100, vec![]), span(3, 1100, 60, lazy.clone())];
    let h = ch(ChallengeTarget::Holder(StorageWorkerId([9; 20])), spans);
    let shard = |s: &Span| if s.deal == DealId(2) { 3 } else { 0 };
    for j in 0..64 {
        let x = h.target.draw(&h.seed, j) % 1160;
        let (s, off) = h.locate(j, shard).unwrap();
        match s.deal.0 {
            1 => assert_eq!(off, x),
            2 => assert_eq!(off, 300 + x - 1000),
            _ => assert_eq!(Some(off), lazy_offset(&lazy, x - 1100).map(|(_, o)| o)),
        }
    }

    // A slot or executor target draws over its one span, never the set's current size.
    let s = ch(ChallengeTarget::Slot { deal: DealId(1), slot: 0 }, vec![span(1, 0, 600, vec![])]);
    for j in 0..16 {
        assert_eq!(s.locate(j, |_| 0).unwrap().1, s.target.draw(&s.seed, j) % 600);
    }
    let e = ch(ChallengeTarget::Executor { deal: DealId(3), worker: [1; 20] }, vec![span(3, 0, 60, lazy.clone())]);
    for j in 0..16 {
        let (_, off) = e.locate(j, |_| 0).unwrap();
        assert!(lazy.iter().any(|(_, l)| l.offset <= off && off < l.offset + l.size));
    }

    // Disputed chunks of a lazy slot are set offsets inside its leaves.
    let c =
        ch(ChallengeTarget::Chunks { deal: DealId(3), slot: 0, offsets: vec![120, 200] }, vec![span(3, 0, 60, lazy)]);
    assert_eq!(c.locate(0, |_| 0).map(|(_, o)| o), Some(120));
    assert_eq!(c.locate(1, |_| 0), None);

    // No spans, or an empty byte space: nothing to draw.
    assert_eq!(ch(ChallengeTarget::Slot { deal: DealId(1), slot: 0 }, vec![]).locate(0, |_| 0), None);
    assert_eq!(
        ch(ChallengeTarget::Holder(StorageWorkerId([9; 20])), vec![span(1, 0, 0, vec![])]).locate(0, |_| 0),
        None
    );
}
