use super::*;

fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect()
}

#[test]
fn field_arithmetic() {
    assert_eq!(mul(0x8000, 2), 0x002D, "x^16 = x^5 + x^3 + x^2 + 1");
    for a in [1u16, 2, 3, 0x1234, 0xffff, 0x8000] {
        assert_eq!(mul(a, 1), a);
        assert_eq!(mul(a, 0), 0);
        assert_eq!(mul(a, inv(a)), 1);
        for b in [5u16, 0x00ff, 0xabcd] {
            assert_eq!(mul(a, b), mul(b, a));
            assert_eq!(mul(a, b ^ 7), mul(a, b) ^ mul(a, 7));
        }
    }
    // Carry-less reference product reduced by the field polynomial.
    let slow = |a: u16, b: u16| {
        let mut r: u32 = 0;
        for i in 0..16 {
            if b >> i & 1 == 1 {
                r ^= u32::from(a) << i;
            }
        }
        for i in (16..32).rev() {
            if r >> i & 1 == 1 {
                r ^= POLY << (i - 16);
            }
        }
        r as u16
    };
    for (a, b) in [(0x1234u16, 0x5678u16), (0xffff, 0xffff), (0x8001, 0x4003)] {
        assert_eq!(mul(a, b), slow(a, b));
    }
}

#[test]
fn params() {
    assert_eq!(RsCode::new(0, 4).unwrap_err(), RsError::Params);
    assert_eq!(RsCode::new(10, 0).unwrap_err(), RsError::Params);
    assert_eq!(RsCode::new(60, 5).unwrap_err(), RsError::Params);
    assert!(RsCode::new(60, 4).is_ok());
}

#[test]
fn any_k_shards_determine_the_rest() {
    let code = RsCode::new(10, 4).unwrap();
    let shards = code.encode(&data(10 * 4096 * 2 + 777));
    assert_eq!(shards.len(), 14);
    let size = shard_size(10 * 4096 * 2 + 777, 10) as usize;
    assert_eq!((size, shards.iter().all(|s| s.len() == size)), (3 * 4096, true));

    // Interpolate each symbol from shards 4..14 (k of them, mostly parity) and evaluate at 0..4.
    let xs: Vec<u16> = (4..14).collect();
    for j in [0, size / 2 - 2, size - 2] {
        let ys: Vec<u16> = (4..14).map(|s| u16::from_le_bytes([shards[s][j], shards[s][j + 1]])).collect();
        for target in 0..4u16 {
            let c = lagrange(&xs, target);
            let v = c.iter().zip(&ys).fold(0u16, |acc, (&c, &y)| acc ^ mul(c, y));
            let s = target as usize;
            assert_eq!(v, u16::from_le_bytes([shards[s][j], shards[s][j + 1]]), "symbol {j} of shard {s}");
        }
    }
}

#[test]
fn recover_rebuilds_lost_data_shards() {
    let code = RsCode::new(10, 4).unwrap();
    let shards = code.encode(&data(10 * 4096 * 2 + 777));
    // Shards 0, 3, 5 and 9 lost: rows 4096..8192 come back from 1, 2, 4, 6, 7, 8 and parity 10..14.
    let known: Vec<(usize, &[u8])> =
        [1, 2, 4, 6, 7, 8, 10, 11, 12, 13].iter().map(|&s| (s, &shards[s][4096..8192])).collect();
    let got = code.recover(&known, &[0, 3, 5, 9]).unwrap();
    for (row, s) in got.iter().zip([0, 3, 5, 9]) {
        assert_eq!(row.as_slice(), &shards[s][4096..8192]);
    }
    assert_eq!(code.recover(&known[..9], &[0]), Err(RsError::Shape));
    let mut twice = known.clone();
    twice[0] = known[1];
    assert_eq!(code.recover(&twice, &[0]), Err(RsError::Shape));
    let odd: Vec<(usize, &[u8])> = known.iter().map(|&(s, b)| (s, &b[..3])).collect();
    assert_eq!(code.recover(&odd, &[0]), Err(RsError::Shape));
}

#[test]
fn systematic_and_padded() {
    let code = RsCode::new(3, 2).unwrap();
    let d = data(5000);
    let shards = code.encode(&d);
    assert_eq!(shard_size(5000, 3), 4096);
    assert_eq!(&shards[0][..], &d[..4096]);
    assert_eq!(&shards[1][..904], &d[4096..]);
    assert!(shards[1][904..].iter().all(|&b| b == 0) && shards[2].iter().all(|&b| b == 0));
}

#[test]
fn bad_encoding_is_detected() {
    let code = RsCode::new(4, 2).unwrap();
    let shards = code.encode(&data(4 * 4096 * 2));
    let row = |shards: &[Vec<u8>], j: usize| -> Vec<Vec<u8>> {
        shards.iter().map(|s| s[j * 4096..(j + 1) * 4096].to_vec()).collect()
    };
    for j in 0..2 {
        let r = row(&shards, j);
        let refs: Vec<&[u8]> = r.iter().map(Vec::as_slice).collect();
        assert_eq!(code.is_codeword(&refs), Ok(true));
    }
    let mut bad = shards.clone();
    bad[5][4096 + 100] ^= 1;
    let r = row(&bad, 1);
    let refs: Vec<&[u8]> = r.iter().map(Vec::as_slice).collect();
    assert_eq!(code.is_codeword(&refs), Ok(false));
    assert_eq!(code.is_codeword(&refs[..5]), Err(RsError::Shape));
}

#[test]
fn shard_roots_are_a_payload_set() {
    let code = RsCode::new(2, 1).unwrap();
    let shards = code.encode(&data(9000));
    let (leaves, root) = RsCode::shard_roots(&shards);
    let size = shard_size(9000, 2);
    for (s, leaf) in leaves.iter().enumerate() {
        assert_eq!(*leaf, PayloadSetLeaf { root: *blake3::hash(&shards[s]).as_bytes(), offset: s as u64 * size, size });
        let path = crate::storage::path(&leaves, s as u32).unwrap();
        let set = crate::storage::PayloadSetRoot { root, count: 3, total_size: 3 * size };
        assert!(crate::storage::verify_path(&set, leaf, &path));
    }
}

#[test]
fn encoder_slot_is_the_low_bit_of_the_le_word() {
    let beacon = [0x11; 32];
    let h = tagged_hash(Domain::Encoder, &[&beacon, &7u64.to_le_bytes()]);
    assert_eq!(encoder_slot(&beacon, DealId(7)), u16::from(h[0] & 1));
    let slots: Vec<u16> = (0..64).map(|d| encoder_slot(&beacon, DealId(d))).collect();
    assert!(slots.contains(&0) && slots.contains(&1));
}

#[test]
fn encoding_fraud_layout() {
    let opening = ChunkOpening {
        deal: DealId(1),
        slot: 2,
        set_leaf: PayloadSetLeaf { root: [0; 32], offset: 0, size: 0 },
        set_path: crate::storage::MerklePath { index: 0, siblings: vec![] },
        chunk_index: 0,
        chunk: vec![],
        chunk_proof: crate::por::Bao4kProof::default(),
    };
    let tx = EncodingFraudTx {
        submitter: [3; 20],
        deal: DealId(1),
        proof: EncodingFraud::Data { shard: opening, byte: 9, payload: None },
        replay: ReplayGuard { chain_id: 1, nonce: 0 },
    };
    let body = borsh::to_vec(&crate::TxBody::EncodingFraud(Box::new(tx))).unwrap();
    assert_eq!(body[0], 24);
    // submitter, deal, then the proof's variant index.
    assert_eq!(body[1 + 20 + 8], 1);
}

#[test]
fn table_free_field_ops_match_the_tables() {
    for a in (0..=u16::MAX).step_by(97).chain([1, 2, u16::MAX]) {
        for b in (0..=u16::MAX).step_by(251).chain([0, 1, u16::MAX]) {
            assert_eq!(mul_slow(a, b), mul(a, b), "{a} · {b}");
        }
        if a != 0 {
            assert_eq!(inv_slow(a), inv(a), "{a}⁻¹");
        }
    }
}

/// The symbol-at-a-time encoder this module had before the byte-split tables, kept as the
/// reference the fast one must match byte for byte.
fn parity_reference(k: usize, m: usize, data: &[&[u8]]) -> Vec<Vec<u8>> {
    let xs: Vec<u16> = (0..k as u16).collect();
    let coeffs: Vec<Vec<u16>> = (0..m).map(|p| lagrange(&xs, (k + p) as u16)).collect();
    let len = data[0].len();
    let mut out = vec![vec![0u8; len]; m];
    for t in (0..len).step_by(2) {
        let d: Vec<u16> = data.iter().map(|r| u16::from_le_bytes([r[t], r[t + 1]])).collect();
        for (row, c) in out.iter_mut().zip(&coeffs) {
            let v = c.iter().zip(&d).fold(0u16, |acc, (&c, &x)| acc ^ mul_slow(c, x));
            row[t..t + 2].copy_from_slice(&v.to_le_bytes());
        }
    }
    out
}

/// The reference for `recover`, as above.
fn recover_reference(known: &[(usize, &[u8])], targets: &[usize]) -> Vec<Vec<u8>> {
    let xs: Vec<u16> = known.iter().map(|&(i, _)| i as u16).collect();
    let len = known[0].1.len();
    let coeffs: Vec<Vec<u16>> = targets.iter().map(|&t| lagrange(&xs, t as u16)).collect();
    let mut out = vec![vec![0u8; len]; targets.len()];
    for t in (0..len).step_by(2) {
        let ys: Vec<u16> = known.iter().map(|(_, b)| u16::from_le_bytes([b[t], b[t + 1]])).collect();
        for (row, c) in out.iter_mut().zip(&coeffs) {
            let v = c.iter().zip(&ys).fold(0u16, |acc, (&c, &y)| acc ^ mul_slow(c, y));
            row[t..t + 2].copy_from_slice(&v.to_le_bytes());
        }
    }
    out
}

fn noise(len: usize, mut x: u64) -> Vec<u8> {
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

#[test]
fn fast_parity_and_recovery_are_byte_identical_to_the_reference() {
    for (k, m, len) in [(10usize, 4usize, 3 * CHUNK_4K), (1, 1, CHUNK_4K), (4, 2, 2), (7, 5, 9000), (32, 32, CHUNK_4K)]
    {
        let code = RsCode::new(k as u8, m as u8).unwrap();
        let shards: Vec<Vec<u8>> = (0..k).map(|i| noise(len, 0x9e37_79b9 + i as u64)).collect();
        let mut extremes = shards.clone();
        extremes[0].fill(0xff);
        for shards in [shards, extremes] {
            let data: Vec<&[u8]> = shards.iter().map(Vec::as_slice).collect();
            let want = parity_reference(k, m, &data);
            let mut got = vec![vec![0xa5u8; len]; m];
            code.parity_into(&data, &mut got.iter_mut().map(Vec::as_mut_slice).collect::<Vec<_>>()).unwrap();
            assert_eq!(got, want, "parity, RS({k}, {m}), {len} bytes");
            if len % CHUNK_4K == 0 {
                for j in 0..len / CHUNK_4K {
                    let rows: Vec<&[u8]> = data.iter().map(|d| &d[j * CHUNK_4K..(j + 1) * CHUNK_4K]).collect();
                    let rows_want: Vec<Vec<u8>> =
                        want.iter().map(|w| w[j * CHUNK_4K..(j + 1) * CHUNK_4K].to_vec()).collect();
                    assert_eq!(code.parity_rows(&rows).unwrap(), rows_want, "row {j}");
                }
            }
            let all: Vec<&[u8]> = data.iter().copied().chain(want.iter().map(Vec::as_slice)).collect();
            // Keep the last k shards, rebuild the first ones (data shards when m >= 1).
            let known: Vec<(usize, &[u8])> = (m..k + m).map(|i| (i, all[i])).collect();
            let targets: Vec<usize> = (0..m.min(k)).collect();
            assert_eq!(code.recover(&known, &targets).unwrap(), recover_reference(&known, &targets));
            for (t, got) in targets.iter().zip(code.recover(&known, &targets).unwrap()) {
                assert_eq!(got, all[*t], "shard {t} rebuilt, RS({k}, {m})");
            }
        }
    }
}

#[test]
fn fast_paths_check_shapes() {
    let code = RsCode::new(4, 2).unwrap();
    let d = [0u8; 8];
    let data: Vec<&[u8]> = vec![&d; 4];
    let (mut a, mut b) = ([0u8; 8], [0u8; 6]);
    assert_eq!(code.parity_into(&data, &mut [&mut a, &mut b]), Err(RsError::Shape));
    assert_eq!(code.parity_into(&data[..3], &mut [&mut a, &mut [0u8; 8]]), Err(RsError::Shape));
    let odd = [0u8; 7];
    assert_eq!(code.parity_into(&[&odd[..]; 4], &mut [&mut [0u8; 7], &mut [0u8; 7]]), Err(RsError::Shape));
    let known: Vec<(usize, &[u8])> = (0..4).map(|i| (i, &d[..])).collect();
    assert_eq!(code.recover_into(&known, &[4], &mut [&mut [0u8; 6]]), Err(RsError::Shape));
    assert_eq!(code.recover_into(&known, &[4, 5], &mut [&mut [0u8; 8]]), Err(RsError::Shape));
}

#[test]
fn one_parity_symbol_is_the_symbol_of_the_full_parity_rows() {
    for (k, m) in [(1u8, 1u8), (4, 2), (10, 4), (7, 5), (32, 32), (63, 1), (1, 63)] {
        let shards: Vec<Vec<u8>> = (0..k).map(|i| noise(CHUNK_4K, 0x51ed_2701 + u64::from(i) * 977)).collect();
        let mut extremes = shards.clone();
        extremes.iter_mut().for_each(|s| s.fill(0xff));
        for shards in [shards, extremes] {
            let data: Vec<&[u8]> = shards.iter().map(Vec::as_slice).collect();
            let rows = RsCode::new(k, m).unwrap().parity_rows(&data).unwrap();
            let reference = parity_reference(usize::from(k), usize::from(m), &data);
            assert_eq!(rows, reference);
            for (p, row) in rows.iter().enumerate() {
                for symbol in [0usize, 1, 2, 1023, 2046, 2047].into_iter().chain((0..2048).step_by(97)) {
                    let got = RsCode::parity_symbol(k, m, &data, p, symbol).unwrap();
                    assert_eq!(
                        got.to_le_bytes(),
                        row[2 * symbol..2 * symbol + 2],
                        "RS({k}, {m}) p {p} symbol {symbol}"
                    );
                }
            }
        }
    }
}

#[test]
fn one_parity_symbol_checks_its_inputs() {
    let row = [0u8; CHUNK_4K];
    let data: Vec<&[u8]> = vec![&row; 4];
    assert_eq!(RsCode::parity_symbol(0, 2, &[], 0, 0), Err(RsError::Params));
    assert_eq!(RsCode::parity_symbol(32, 33, &data, 0, 0), Err(RsError::Params));
    assert_eq!(RsCode::parity_symbol(4, 2, &data[..3], 0, 0), Err(RsError::Shape));
    assert_eq!(RsCode::parity_symbol(4, 2, &data, 2, 0), Err(RsError::Shape));
    assert_eq!(RsCode::parity_symbol(4, 2, &data, 0, 2048), Err(RsError::Shape));
    let short = [0u8; 4094];
    assert_eq!(RsCode::parity_symbol(4, 2, &[&row, &row, &row, &short], 0, 0), Err(RsError::Shape));
    assert_eq!(RsCode::parity_symbol(4, 2, &data, 1, 2047), Ok(0));
}
