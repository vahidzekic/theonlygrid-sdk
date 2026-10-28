use ed25519_dalek::{Signer, SigningKey};

use super::*;

/// The spec's weighted pick: walk the pool, subtracting weights.
fn pick(pool: &[(u8, u128)], mut x: u128) -> usize {
    pool.iter()
        .position(|&(_, w)| {
            if x < w {
                true
            } else {
                x -= w;
                false
            }
        })
        .unwrap()
}

#[test]
fn place_draw_vector() {
    let beacon = [0x11; 32];
    let h0 = tagged_hash(Domain::Place, &[&beacon, &7u64.to_le_bytes(), &0u32.to_le_bytes()]);
    assert_eq!(h0[..4], [0x51, 0x13, 0xfb, 0xb4]);
    assert_eq!(h0[28..], [0x5a, 0xfe, 0xdf, 0x72]);
    let h1 = tagged_hash(Domain::Place, &[&beacon, &7u64.to_le_bytes(), &1u32.to_le_bytes()]);
    assert_eq!(h1[..4], [0xe5, 0x54, 0x59, 0xec]);
    assert_eq!(h1[28..], [0xa4, 0xbb, 0xf9, 0xfe]);

    let mut pool = vec![(1u8, 500u128), (2, 300), (3, 200)];
    let x = place_draw(&beacon, DealId(7), 0, 1000);
    assert_eq!(x, 322);
    assert_eq!(pool.remove(pick(&pool, x)).0, 1);
    let x = place_draw(&beacon, DealId(7), 1, 500);
    assert_eq!(x, 350);
    assert_eq!(pool.remove(pick(&pool, x)).0, 3);
}

#[test]
fn place_draw_is_the_full_256_bit_remainder() {
    let beacon = [0x42; 32];
    for total in [1u128, 2, 255, 256, 1_000_003, u64::MAX as u128 + 7, u128::MAX - 58, u128::MAX] {
        let h = tagged_hash(Domain::Place, &[&beacon, &3u64.to_le_bytes(), &9u32.to_le_bytes()]);
        // Long division of the 256-bit value by `total`, done independently via two u128 halves.
        let hi = u128::from_be_bytes(h[..16].try_into().unwrap());
        let lo = u128::from_be_bytes(h[16..].try_into().unwrap());
        let r_hi = hi % total;
        // (r_hi · 2^128 + lo) mod total, by 128 doublings.
        let mut r = r_hi;
        for _ in 0..128 {
            r = addmod(r, r, total);
        }
        let expected = addmod(r, lo % total, total);
        assert_eq!(place_draw(&beacon, DealId(3), 9, total), expected, "total {total}");
        assert!(expected < total);
    }
}

#[test]
fn sched_vector() {
    let beacon = [0x11; 32];
    let w = StorageWorkerId([0x22; 20]);
    assert_eq!(sched_hash(&beacon, &w)[..8], [0x07, 0x24, 0x5f, 0x78, 0xbb, 0x38, 0xb3, 0xc0]);
    assert_eq!(u64::from_le_bytes(sched_hash(&beacon, &w)[..8].try_into().unwrap()), 13_885_504_453_942_912_007);
    assert_eq!(sched_threshold(1800), 10_248_191_152_060_862);
    assert!(!is_scheduled(&beacon, &w, 1800));
    // I_sched = 1: every block.
    assert!(is_scheduled(&beacon, &w, 1));
}

fn registration(key: &SigningKey) -> RegisterStorageWorkerTx {
    let mut ask = StorageAsk::default();
    ask.per_class[RetentionClass::ChallengeWindow as usize] =
        ClassAsk { price_per_gib_hour: 100, retrieval_price_per_gib: 5 };
    let mut tx = RegisterStorageWorkerTx {
        chain_id: 1 << 32,
        owner: [9; 20],
        owner_nonce: 4,
        storage_key: key.verifying_key().to_bytes(),
        storage_sig: [0; 64],
        operator_group: None,
        region: Region(*b"DE"),
        asn: 3320,
        classes: ClassSet(0b010),
        capacity_bytes: 4 << 40,
        ask,
        bond: 1_000,
    };
    tx.storage_sig = key.sign(&tx.bind_digest()).to_bytes();
    tx
}

#[test]
fn registration_rules() {
    let key = SigningKey::from_bytes(&[5; 32]);
    let tx = registration(&key);
    tx.check_stateless().unwrap();
    assert_eq!(tx.worker_id(), StorageWorkerId(ed25519_address(&tx.storage_key)));
    let r = tx.record(500);
    assert_eq!(
        (r.committed_bytes, r.locked_collateral, r.status, r.region_flagged),
        (0, 0, StorageWorkerStatus::Active, false)
    );

    let bad = |f: &dyn Fn(&mut RegisterStorageWorkerTx)| {
        let mut t = tx.clone();
        f(&mut t);
        t.check_stateless().unwrap_err()
    };
    assert_eq!(bad(&|t| t.region = Region(*b"de")), StorageRegistrationError::Region);
    assert_eq!(bad(&|t| t.asn = 0), StorageRegistrationError::Asn);
    assert_eq!(bad(&|t| t.classes = ClassSet(0)), StorageRegistrationError::Classes);
    assert_eq!(bad(&|t| t.classes = ClassSet(0b1010)), StorageRegistrationError::Classes);
    // LongTerm served but unpriced; Hot priced but not served.
    assert_eq!(bad(&|t| t.classes = ClassSet(0b110)), StorageRegistrationError::Ask);
    assert_eq!(bad(&|t| t.ask.per_class[0].retrieval_price_per_gib = 1), StorageRegistrationError::Ask);
    assert_eq!(bad(&|t| t.capacity_bytes = (1 << 30) - 1), StorageRegistrationError::Capacity);
    // The signature binds the nonce.
    assert_eq!(bad(&|t| t.owner_nonce = 5), StorageRegistrationError::Signature);
}

#[test]
fn borsh_layouts() {
    let key = SigningKey::from_bytes(&[5; 32]);
    let tx = registration(&key);
    let body = crate::TxBody::RegisterStorageWorker(Box::new(tx.clone()));
    assert_eq!(borsh::to_vec(&body).unwrap()[0], 23);
    // Status indices.
    assert_eq!(borsh::to_vec(&StorageWorkerStatus::Unbonding { until: 0 }).unwrap()[0], 3);
    // The record ends with status then region_flagged.
    let mut r = tx.record(0);
    r.region_flagged = true;
    let bytes = borsh::to_vec(&r).unwrap();
    assert_eq!(bytes[bytes.len() - 2..], [0, 1]);
    assert_eq!(bytes[..20], r.id.0);
}
