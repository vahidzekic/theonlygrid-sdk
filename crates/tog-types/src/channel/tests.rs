use super::*;
use crate::tx::Signature;

#[test]
fn voucher_is_signed_by_the_payer() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[4; 32]);
    let payer = tog_primitives::ed25519_address(&key.verifying_key().to_bytes());
    let v = Voucher { channel: ChannelId(2), cumulative: 1_000 };
    let signed = SignedVoucher::sign_ed25519(v, 7, &key);
    assert_eq!(signed.signer(7), Ok(payer));

    // The digest covers the channel, the amount and the network (storage audit R-10).
    let other = SignedVoucher { voucher: Voucher { cumulative: 2_000, ..v }, ..signed.clone() };
    assert_eq!(other.signer(7), Err(SignatureError::Invalid));
    assert_ne!(signed.signer(8), Ok(payer));
    let mut msg = b"".to_vec();
    borsh::BorshSerialize::serialize(&v, &mut msg).unwrap();
    assert_eq!(v.signing_hash(7), tagged_hash(Domain::Voucher, &[&7u64.to_le_bytes(), &msg]));
    assert_eq!(msg, [&2u64.to_le_bytes()[..], &1_000u128.to_le_bytes()[..]].concat());

    // An EIP-712 signature never signs a voucher.
    let eip = SignedVoucher { voucher: v, sig: Signature::Secp256k1Eip712([0; 65]) };
    assert_eq!(eip.signer(7), Err(SignatureError::Invalid));
}

fn addr(b: u8) -> Address {
    [b; 20]
}

#[test]
fn service_types_have_their_spec_borsh() {
    let holder = StorageWorkerId(addr(1));
    let retrieval = ServiceKind::Retrieval { holder };
    assert_eq!(borsh::to_vec(&retrieval).unwrap(), [&[0u8][..], &[1; 20]].concat());
    let bandwidth = ServiceKind::Bandwidth { router: RouterId(addr(2)), exit: ExitId(addr(3)) };
    assert_eq!(borsh::to_vec(&bandwidth).unwrap(), [&[1u8][..], &[2; 20], &[3; 20]].concat());
    assert_eq!(retrieval.fee_class(), FeeClass::Retrieval);
    assert_eq!(bandwidth.fee_class(), FeeClass::Bandwidth);

    for (i, c) in FeeClass::ALL.into_iter().enumerate() {
        assert_eq!(borsh::to_vec(&c).unwrap(), [i as u8]);
        assert_eq!(c as usize, i);
    }
    assert_eq!(borsh::to_vec(&ChannelPrices::PerGib(5)).unwrap()[0], 1);
    let payees = Payees { first: addr(4), second: Some((addr(5), 250_000)) };
    assert_eq!(borsh::to_vec(&payees).unwrap(), [&[4; 20][..], &[1], &[5; 20], &250_000u32.to_le_bytes()].concat());
}

#[test]
fn an_open_channel_executes_as_a_retrieval_service_channel() {
    let replay = crate::storage::ReplayGuard { chain_id: 9, nonce: 3 };
    let open = OpenChannelTx { holder: StorageWorkerId(addr(1)), deposit: 7, replay };
    assert_eq!(
        OpenServiceChannelTx::from(open),
        OpenServiceChannelTx {
            service: ServiceKind::Retrieval { holder: StorageWorkerId(addr(1)) },
            deposit: 7,
            voucher_key: None,
            max_price_per_gib: Amount::MAX,
            replay,
        }
    );
    assert_eq!(ChannelPrices::PerClass([3, 9, 4]).max_per_gib(), 9);
    assert_eq!(ChannelPrices::PerGib(6).max_per_gib(), 6);
}

#[test]
fn payees_take_a_share_strictly_between_none_and_all() {
    assert!(Payees::one(addr(1)).is_valid());
    for (ppm, ok) in [(0, false), (1, true), (999_999, true), (1_000_000, false)] {
        assert_eq!(Payees { first: addr(1), second: Some((addr(2), ppm)) }.is_valid(), ok, "{ppm}");
    }
    let p = Payees { first: addr(1), second: Some((addr(2), 1)) };
    assert!(p.contains(&addr(1)) && p.contains(&addr(2)) && !p.contains(&addr(3)));
}

#[test]
fn a_settlement_batch_is_1_to_64_ascending_channels() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[4; 32]);
    let v = |c| SignedVoucher::sign_ed25519(Voucher { channel: ChannelId(c), cumulative: 1 }, 7, &key);
    let batch = |ids: &[u64]| SettleChannelsTx { vouchers: ids.iter().map(|&c| v(c)).collect() };
    assert!(!batch(&[]).is_well_formed());
    assert!(batch(&[3]).is_well_formed());
    assert!(batch(&[1, 4, 9]).is_well_formed());
    assert!(!batch(&[4, 4]).is_well_formed());
    assert!(!batch(&[4, 1]).is_well_formed());
    let full: Vec<u64> = (0..MAX_SETTLE as u64).collect();
    assert!(batch(&full).is_well_formed());
    let over: Vec<u64> = (0..=MAX_SETTLE as u64).collect();
    assert!(!batch(&over).is_well_formed());
}

#[test]
fn the_testnet_table_is_the_decided_one_and_loads() {
    let pct =
        |s: &FeeSplit| (100 - (s.burn_ppm + s.treasury_ppm) / 10_000, s.burn_ppm / 10_000, s.treasury_ppm / 10_000);
    let rows: Vec<_> = TESTNET_FEE_SPLITS.iter().map(pct).collect();
    assert_eq!(rows, [(90, 7, 3), (90, 5, 5), (95, 3, 2), (90, 7, 3)]);
    assert!(TESTNET_FEE_SPLITS.iter().all(|s| s.bonus_cap_ppm == 0));
    assert_eq!(check_fee_splits(&TESTNET_FEE_SPLITS), Ok(()));
}

#[test]
fn a_table_out_of_bounds_does_not_load() {
    let with = |class: FeeClass, s: FeeSplit| {
        let mut t = TESTNET_FEE_SPLITS;
        t[class as usize] = s;
        check_fee_splits(&t)
    };
    let split = |burn_ppm, treasury_ppm, bonus_cap_ppm| FeeSplit { burn_ppm, treasury_ppm, bonus_cap_ppm };
    assert_eq!(with(FeeClass::StorageDeal, split(100_000, 100_000, 0)), Ok(()));
    assert_eq!(
        with(FeeClass::StorageDeal, split(100_000, 100_001, 0)),
        Err(FeeTableError::Take(FeeClass::StorageDeal))
    );
    assert_eq!(with(FeeClass::Retrieval, split(u32::MAX, u32::MAX, 0)), Err(FeeTableError::Take(FeeClass::Retrieval)));
    assert_eq!(with(FeeClass::Bandwidth, split(30_000, 0, 30_000)), Ok(()));
    assert_eq!(with(FeeClass::Bandwidth, split(30_000, 0, 30_001)), Err(FeeTableError::Bonus(FeeClass::Bandwidth)));
    assert_eq!(with(FeeClass::ComputeExec, split(50_000, 0, 0)), Ok(()));
    assert_eq!(with(FeeClass::ComputeExec, split(100_000, 50_000, 0)), Ok(()));
    assert_eq!(with(FeeClass::ComputeExec, split(49_999, 0, 0)), Err(FeeTableError::ComputeTake));
    assert_eq!(with(FeeClass::ComputeExec, split(100_000, 50_001, 0)), Err(FeeTableError::ComputeTake));
    // Storage and retrieval may take less than compute's floor.
    assert_eq!(with(FeeClass::Retrieval, split(0, 0, 0)), Ok(()));
}

#[test]
fn settle_splits_exactly_with_dust_to_the_first_payee() {
    let tog = 10u128.pow(18);
    let [compute, storage, retrieval, bandwidth] = TESTNET_FEE_SPLITS;
    let one = Payees::one(addr(1));

    // 0003 §7: ⌊7·F/100⌋ burned, ⌊3·F/100⌋ to the treasury, dust to the executor.
    let f = 1_000_001;
    assert_eq!(
        compute.settle(f, &one),
        Settlement { to_first: f - 70_000 - 30_000, to_second: 0, treasury: 30_000, burn: 70_000 }
    );
    assert_eq!(compute.settle(99, &one), Settlement { to_first: 91, to_second: 0, treasury: 2, burn: 6 });

    // §3.4 worked example rows.
    assert_eq!(
        compute.settle(2_160 * tog, &one),
        Settlement { to_first: 1_944 * tog, to_second: 0, treasury: 64_800 * tog / 1_000, burn: 151_200 * tog / 1_000 }
    );
    let s = storage.settle(7_200 * tog / 1_000, &one);
    assert_eq!((s.to_first, s.treasury, s.burn), (6_480 * tog / 1_000, 360 * tog / 1_000, 360 * tog / 1_000));
    let r = retrieval.settle(tog, &one);
    assert_eq!((r.to_first, r.treasury, r.burn), (950 * tog / 1_000, 20 * tog / 1_000, 30 * tog / 1_000));
    let split = Payees { first: addr(1), second: Some((addr(2), 500_000)) };
    let b = bandwidth.settle(tog / 2, &split);
    assert_eq!(
        b,
        Settlement {
            to_first: 225 * tog / 1_000,
            to_second: 225 * tog / 1_000,
            treasury: 15 * tog / 1_000,
            burn: 35 * tog / 1_000
        }
    );

    // The parts always sum to x, up to the largest amount.
    for x in [0, 1, 999_999, 1_000_000, 123_456_789_012_345, Amount::MAX] {
        for s in TESTNET_FEE_SPLITS {
            let p = s.settle(x, &Payees { first: addr(1), second: Some((addr(2), 333_333)) });
            assert_eq!(p.to_first + p.to_second + p.treasury + p.burn, x);
            assert_eq!(p.burn, (U256(x) * s.burn_ppm).0);
        }
    }
}

/// `⌊x · ppm / 10⁶⌋` by long multiplication, as an independent check of the ppm helper.
struct U256(Amount);
impl core::ops::Mul<u32> for U256 {
    type Output = U256;
    fn mul(self, ppm: u32) -> U256 {
        let (hi, lo) = (self.0 >> 64, self.0 & u128::from(u64::MAX));
        let (hi, lo) = (hi * u128::from(ppm), lo * u128::from(ppm));
        // (hi·2⁶⁴ + lo) / 10⁶, carrying hi's remainder into the low half.
        let (qh, rh) = (hi / 1_000_000, hi % 1_000_000);
        U256((qh << 64) + ((rh << 64) + lo) / 1_000_000)
    }
}

#[test]
fn a_retrieval_service_channel_reads_as_a_0004_channel_keyed_by_its_voucher_key() {
    let holder = StorageWorkerId(addr(1));
    let service = ServiceChannel {
        payer: addr(2),
        voucher_key: addr(3),
        service: ServiceKind::Retrieval { holder },
        payees: Payees::one(addr(4)),
        prices: ChannelPrices::PerClass([5, 6, 7]),
        deposit: 100,
        closing: Some((40, 9)),
        opened: 8,
    };
    let view = Channel {
        payer: addr(3),
        payee: addr(4),
        deposit: 100,
        closing: Some((40, 9)),
        holder,
        prices: [5, 6, 7],
        opened: 8,
    };
    assert_eq!(service.retrieval_view(), Some(view));
    let bandwidth = ServiceChannel {
        service: ServiceKind::Bandwidth { router: RouterId(addr(5)), exit: ExitId(addr(6)) },
        prices: ChannelPrices::PerGib(3),
        ..service
    };
    assert_eq!(bandwidth.retrieval_view(), None);
    // The legacy record wins; otherwise the service one; neither is none.
    let legacy = Channel { payer: addr(9), ..view };
    assert_eq!(retrieval_channel(Some(legacy), Some(service)), Some(legacy));
    assert_eq!(retrieval_channel(None, Some(service)), Some(view));
    assert_eq!(retrieval_channel(None, Some(bandwidth)), None);
    assert_eq!(retrieval_channel(None, None), None);
    let [a, b] = retrieval_channel_keys(&ChannelId(3));
    assert_eq!(
        (a, b),
        (crate::state::items::channel(&ChannelId(3)), crate::state::items::service_channel(&ChannelId(3)))
    );
    assert_ne!(a, b);
}
