use super::*;

#[test]
fn bp_rounding() {
    assert_eq!(bp_ceil(10_001, 5_000), 5_001);
    assert_eq!(bp_floor(10_001, 5_000), 5_000);
    assert_eq!(bp_ceil(Amount::MAX, BP), Amount::MAX);
    assert_eq!(bp_floor(Amount::MAX, BP), Amount::MAX);
}

#[test]
fn bp_ceil_is_exact_where_the_product_overflows() {
    // Expected values from arbitrary-precision arithmetic.
    let cases: [(Amount, u32, Amount); 4] = [
        (Amount::MAX, 9_999, 340_248_338_684_246_369_617_028_269_971_025_034_634),
        (Amount::MAX - 3, 1, 34_028_236_692_093_846_346_337_460_743_176_822),
        (
            340_282_366_920_938_463_463_374_607_431_768_210_007,
            3_333,
            113_416_112_894_748_789_872_342_756_657_008_344_396,
        ),
        (Amount::MAX / 10_000 + 1, BP, Amount::MAX / 10_000 + 1),
    ];
    for (amount, bp, want) in cases {
        assert_eq!(bp_ceil(amount, bp), want, "⌈{amount} × {bp} / 10 000⌉");
    }
}

#[test]
fn testnet_params_are_the_decided_values_and_valid() {
    let p = testnet_reservation_params(43_200);
    assert!(p.is_valid());
    // 1.8 TOG per hour of slice at the floor (§7).
    assert_eq!(p.min_price_per_block * Amount::from(p.min_duration_blocks), 18 * 10u128.pow(17));
    assert_eq!((p.bond_bp, p.miss_penalty_bp, p.fault_penalty_bp, p.treasury_bp), (1_000, 500, BP, 300));
    assert_eq!((p.cancel_notice_blocks, p.max_open_per_payer, p.retention_blocks), (1_800, 16, 43_200));
    // Misses alone cost at most 15% of the bond before the fault rule ends the reservation.
    assert_eq!(u32::from(MAX_RESERVATION_MISSES) * p.miss_penalty_bp, 1_500);
}
