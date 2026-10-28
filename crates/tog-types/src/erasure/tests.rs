use super::*;

fn pov(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + 3) as u8).collect()
}

#[test]
fn parameters_follow_the_set_size() {
    assert_eq!(params(1), (1, 0));
    assert_eq!(params(4), (2, 2));
    assert_eq!(params(150), (50, 100));
    assert_eq!(shard_size(1009, 2), 506);
    assert_eq!(shard_size(8, 3), 4);
}

#[test]
fn any_k_chunks_recover_the_pov_and_every_proof_checks() {
    for (n, len) in [(1, 10), (4, 1001), (7, 0), (10, 4097)] {
        let c = pov(len);
        let chunks = encode(&c, n).unwrap();
        assert_eq!(chunks.len(), n);
        let root = erasure_root(&chunks);
        let all = ErasureChunk::all(chunks);
        assert!(all.iter().all(|x| x.verify(&root, n as u32)), "n = {n}");
        // The last k chunks alone (parity where m > 0).
        let (k, _) = params(n);
        assert_eq!(recover(&all[n - k..], &root, n).unwrap(), c, "n = {n}");
        // Data shards are D itself.
        let d: Vec<u8> = all.iter().take(k).flat_map(|x| x.chunk.clone()).collect();
        assert_eq!(d[..8], (len as u64).to_le_bytes());
    }
}

#[test]
fn a_proof_fails_for_another_index_root_or_extra_entry() {
    let chunks = encode(&pov(300), 5).unwrap();
    let root = erasure_root(&chunks);
    let all = ErasureChunk::all(chunks);
    // Index 4 is unpaired at the leaves and the next level: one sibling only.
    assert_eq!(all[4].proof.len(), 1);
    assert!(!ErasureChunk { index: 3, ..all[4].clone() }.verify(&root, 5));
    assert!(!all[4].verify(&[1; 32], 5));
    assert!(!all[4].verify(&root, 4));
    let mut extra = all[0].clone();
    extra.proof.push([0; 32]);
    assert!(!extra.verify(&root, 5));
}

#[test]
fn chunks_that_are_not_a_codeword_fail_on_the_root() {
    let mut chunks = encode(&pov(200), 4).unwrap();
    chunks[3][0] ^= 1;
    // Proofs against the tampered set's own root check, but 0 and 1 re-encode to another one.
    let root = erasure_root(&chunks);
    let all = ErasureChunk::all(chunks);
    assert_eq!(recover(&all[..2], &root, 4), Err(ErasureError::Root));
    assert_eq!(recover(&all[..1], &root, 4), Err(ErasureError::Missing));
}

#[test]
fn frames_round_trip() {
    let req = ChunkRequest { candidate: [1; 32], index: 9 };
    let f = req.encode_frame();
    assert_eq!(f.len(), CHUNK_REQUEST_LEN);
    assert_eq!(ChunkRequest::decode_frame(&f), Some(req));
    assert_eq!(ChunkRequest::decode_frame(&f[..36]), None);
    let chunk = ErasureChunk { index: 2, chunk: vec![1, 2], proof: vec![[3; 32]] };
    for r in [ChunkResponse::Chunk(chunk), ChunkResponse::Error(ChunkError::Busy)] {
        assert_eq!(ChunkResponse::decode_frame(&r.encode_frame()), Some(r));
    }
    assert_eq!(ChunkResponse::decode_frame(&[CHUNK_ERROR_TYPE, 3]), None);
}
